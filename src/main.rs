#[macro_use]
extern crate log;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use smoltcp::iface::InterfaceBuilder;
use smoltcp::socket::{SocketSet, TcpSocket, TcpSocketBuffer, TcpState};
use smoltcp::wire::{IpAddress, IpCidr};
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::port_pool::PortPool;
use crate::virtual_device::VirtualIpDevice;
use crate::wg::WireGuardTunnel;

pub mod config;
pub mod ip_sink;
pub mod port_pool;
pub mod virtual_device;
pub mod wg;

pub const MAX_PACKET: usize = 65536;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_args().with_context(|| "Failed to read config")?;
    init_logger(&config)?;
    let port_pool = Arc::new(PortPool::new());

    let wg = WireGuardTunnel::new(&config)
        .await
        .with_context(|| "Failed to initialize WireGuard tunnel")?;
    let wg = Arc::new(wg);

    {
        // Start routine task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.routine_task().await });
    }

    {
        // Start consumption task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.consume_task().await });
    }

    {
        // Start IP sink task for incoming IP packets
        let wg = wg.clone();
        tokio::spawn(async move { ip_sink::run_ip_sink_interface(wg).await });
    }

    info!(
        "Tunnelling [{}]->[{}] (via [{}] as peer {})",
        &config.source_addr, &config.dest_addr, &config.endpoint_addr, &config.source_peer_ip
    );

    tcp_proxy_server(
        config.source_addr,
        config.source_peer_ip,
        config.dest_addr,
        port_pool.clone(),
        wg,
    )
    .await
}

/// Starts the server that listens on TCP connections.
async fn tcp_proxy_server(
    listen_addr: SocketAddr,
    source_peer_ip: IpAddr,
    dest_addr: SocketAddr,
    port_pool: Arc<PortPool>,
    wg: Arc<WireGuardTunnel>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| "Failed to listen on TCP proxy server")?;

    loop {
        let wg = wg.clone();
        let port_pool = port_pool.clone();
        let (socket, peer_addr) = listener
            .accept()
            .await
            .with_context(|| "Failed to accept connection on TCP proxy server")?;

        // Assign a 'virtual port': this is a unique port number used to route IP packets
        // received from the WireGuard tunnel. It is the port number that the virtual client will
        // listen on.
        let virtual_port = match port_pool.next() {
            Ok(port) => port,
            Err(e) => {
                error!(
                    "Failed to assign virtual port number for connection [{}]: {:?}",
                    peer_addr, e
                );
                continue;
            }
        };

        info!("[{}] Incoming connection from {}", virtual_port, peer_addr);

        tokio::spawn(async move {
            let port_pool = Arc::clone(&port_pool);
            let result = handle_tcp_proxy_connection(
                socket,
                virtual_port,
                source_peer_ip,
                dest_addr,
                wg.clone(),
            )
            .await;

            if let Err(e) = result {
                error!(
                    "[{}] Connection dropped un-gracefully: {:?}",
                    virtual_port, e
                );
            } else {
                info!("[{}] Connection closed by client", virtual_port);
            }

            // Release port when connection drops
            wg.release_virtual_interface(virtual_port);
            port_pool.release(virtual_port);
        });
    }
}

/// Handles a new TCP connection with its assigned virtual port.
async fn handle_tcp_proxy_connection(
    socket: TcpStream,
    virtual_port: u16,
    source_peer_ip: IpAddr,
    dest_addr: SocketAddr,
    wg: Arc<WireGuardTunnel>,
) -> anyhow::Result<()> {
    // Abort signal for stopping the Virtual Interface
    let abort = Arc::new(AtomicBool::new(false));

    // Signals that the Virtual Client is ready to send data
    let (virtual_client_ready_tx, virtual_client_ready_rx) = tokio::sync::oneshot::channel::<()>();

    // data_to_real_client_(tx/rx): This task reads the data from this mpsc channel to send back
    // to the real client.
    let (data_to_real_client_tx, mut data_to_real_client_rx) = tokio::sync::mpsc::channel(1_000);

    // data_to_real_server_(tx/rx): This task sends the data received from the real client to the
    // virtual interface (virtual server socket).
    let (data_to_virtual_server_tx, data_to_virtual_server_rx) = tokio::sync::mpsc::channel(1_000);

    // Spawn virtual interface
    {
        let abort = abort.clone();
        tokio::spawn(async move {
            virtual_tcp_interface(
                virtual_port,
                source_peer_ip,
                dest_addr,
                wg,
                abort,
                data_to_real_client_tx,
                data_to_virtual_server_rx,
                virtual_client_ready_tx,
            )
            .await
        });
    }

    // Wait for virtual client to be ready.
    virtual_client_ready_rx
        .await
        .expect("failed to wait for virtual client to be ready");
    trace!("[{}] Virtual client is ready to send data", virtual_port);

    loop {
        tokio::select! {
            readable_result = socket.readable() => {
                match readable_result {
                    Ok(_) => {
                        // Buffer for the individual TCP segment.
                        let mut buffer = Vec::with_capacity(MAX_PACKET);
                        match socket.try_read_buf(&mut buffer) {
                            Ok(size) if size > 0 => {
                                let data = &buffer[..size];
                                debug!(
                                    "[{}] Read {} bytes of TCP data from real client",
                                    virtual_port, size
                                );
                                if let Err(e) = data_to_virtual_server_tx.send(data.to_vec()).await {
                                    error!(
                                        "[{}] Failed to dispatch data to virtual interface: {:?}",
                                        virtual_port, e
                                    );
                                }
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                continue;
                            }
                            Err(e) => {
                                error!(
                                    "[{}] Failed to read from client TCP socket: {:?}",
                                    virtual_port, e
                                );
                                break;
                            }
                            _ => {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("[{}] Failed to check if readable: {:?}", virtual_port, e);
                        break;
                    }
                }
            }
            data_recv_result = data_to_real_client_rx.recv() => {
                match data_recv_result {
                    Some(data) => match socket.try_write(&data) {
                        Ok(size) => {
                            debug!(
                                "[{}] Wrote {} bytes of TCP data to real client",
                                virtual_port, size
                            );
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if abort.load(Ordering::Relaxed) {
                                break;
                            } else {
                                continue;
                            }
                        }
                        Err(e) => {
                            error!(
                                "[{}] Failed to write to client TCP socket: {:?}",
                                virtual_port, e
                            );
                        }
                    },
                    None => {
                        if abort.load(Ordering::Relaxed) {
                            break;
                        } else {
                            continue;
                        }
                    },
                }
            }
        }
    }

    trace!("[{}] TCP socket handler task terminated", virtual_port);
    abort.store(true, Ordering::Relaxed);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn virtual_tcp_interface(
    virtual_port: u16,
    source_peer_ip: IpAddr,
    dest_addr: SocketAddr,
    wg: Arc<WireGuardTunnel>,
    abort: Arc<AtomicBool>,
    data_to_real_client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut data_to_virtual_server_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    virtual_client_ready_tx: tokio::sync::oneshot::Sender<()>,
) -> anyhow::Result<()> {
    let mut virtual_client_ready_tx = Some(virtual_client_ready_tx);

    // Create a device and interface to simulate IP packets
    // In essence:
    // * TCP packets received from the 'real' client are 'sent' to the 'virtual server' via the 'virtual client'
    // * Those TCP packets generate IP packets, which are captured from the interface and sent to the WireGuardTunnel
    // * IP packets received by the WireGuardTunnel (from the endpoint) are fed into this 'virtual interface'
    // * The interface processes those IP packets and routes them to the 'virtual client' (the rest is discarded)
    // * The TCP data read by the 'virtual client' is sent to the 'real' TCP client

    // Consumer for IP packets to send through the virtual interface
    // Initialize the interface
    let device = VirtualIpDevice::new(virtual_port, wg)
        .with_context(|| "Failed to initialize VirtualIpDevice")?;
    let mut virtual_interface = InterfaceBuilder::new(device)
        .ip_addrs([
            // Interface handles IP packets for the sender and recipient
            IpCidr::new(IpAddress::from(source_peer_ip), 32),
            IpCidr::new(IpAddress::from(dest_addr.ip()), 32),
        ])
        .finalize();

    // Server socket: this is a placeholder for the interface to route new connections to.
    // TODO: Determine if we even need buffers here.
    let server_socket: anyhow::Result<TcpSocket> = {
        static mut TCP_SERVER_RX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
        static mut TCP_SERVER_TX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
        let tcp_rx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_RX_DATA[..] });
        let tcp_tx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_TX_DATA[..] });
        let mut socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

        socket
            .listen((IpAddress::from(dest_addr.ip()), dest_addr.port()))
            .with_context(|| "Virtual server socket failed to listen")?;

        Ok(socket)
    };

    let client_socket: anyhow::Result<TcpSocket> = {
        static mut TCP_SERVER_RX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
        static mut TCP_SERVER_TX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
        let tcp_rx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_RX_DATA[..] });
        let tcp_tx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_TX_DATA[..] });
        let mut socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

        socket
            .connect(
                (IpAddress::from(dest_addr.ip()), dest_addr.port()),
                (IpAddress::from(source_peer_ip), virtual_port),
            )
            .with_context(|| "Virtual server socket failed to listen")?;

        Ok(socket)
    };

    // Socket set: there are always 2 sockets: 1 virtual client and 1 virtual server.
    let mut socket_set_entries: [_; 2] = Default::default();
    let mut socket_set = SocketSet::new(&mut socket_set_entries[..]);
    let _server_handle = socket_set.add(server_socket?);
    let client_handle = socket_set.add(client_socket?);

    // Any data that wasn't sent because it was over the sending buffer limit
    let mut tx_extra = Vec::new();

    loop {
        let loop_start = smoltcp::time::Instant::now();

        // Shutdown occurs when the real client closes the connection,
        // or if the client was in a CLOSE-WAIT state (after a server FIN) and had no data to send anmore.
        // One last poll-loop iteration is executed so that the RST segment can be dispatched.
        let shutdown = abort.load(Ordering::Relaxed);

        if shutdown {
            // Shutdown: sends a RST packet.
            trace!("[{}] Shutting down virtual interface", virtual_port);
            let mut client_socket = socket_set.get::<TcpSocket>(client_handle);
            client_socket.abort();
        }

        match virtual_interface.poll(&mut socket_set, loop_start) {
            Ok(processed) if processed => {
                trace!(
                    "[{}] Virtual interface polled some packets to be processed",
                    virtual_port
                );
            }
            Err(e) => {
                error!("[{}] Virtual interface poll error: {:?}", virtual_port, e);
            }
            _ => {}
        }

        {
            let mut client_socket = socket_set.get::<TcpSocket>(client_handle);

            if client_socket.can_recv() {
                match client_socket.recv(|buffer| (buffer.len(), buffer.to_vec())) {
                    Ok(data) => {
                        trace!(
                            "[{}] Virtual client received {} bytes of data",
                            virtual_port,
                            data.len()
                        );
                        // Send it to the real client
                        if let Err(e) = data_to_real_client_tx.send(data).await {
                            error!("[{}] Failed to dispatch data from virtual client to real client: {:?}", virtual_port, e);
                        }
                    }
                    Err(e) => {
                        error!(
                            "[{}] Failed to read from virtual client socket: {:?}",
                            virtual_port, e
                        );
                    }
                }
            }
            if client_socket.can_send() {
                if let Some(virtual_client_ready_tx) = virtual_client_ready_tx.take() {
                    virtual_client_ready_tx
                        .send(())
                        .expect("Failed to notify real client that virtual client is ready");
                }

                let mut to_transfer = None;

                if tx_extra.is_empty() {
                    // The payload segment from the previous loop is complete,
                    // we can now read the next payload in the queue.
                    if let Ok(data) = data_to_virtual_server_rx.try_recv() {
                        to_transfer = Some(data);
                    } else if client_socket.state() == TcpState::CloseWait {
                        // No data to be sent in this loop. If the client state is CLOSE-WAIT (because of a server FIN),
                        // the interface is shutdown.
                        trace!("[{}] Shutting down virtual interface because client sent no more data, and server sent FIN (CLOSE-WAIT)", virtual_port);
                        abort.store(true, Ordering::Relaxed);
                        continue;
                    }
                }

                let to_transfer_slice = to_transfer.as_ref().unwrap_or(&tx_extra).as_slice();
                if !to_transfer_slice.is_empty() {
                    let total = to_transfer_slice.len();
                    match client_socket.send_slice(to_transfer_slice) {
                        Ok(sent) => {
                            trace!(
                                "[{}] Sent {}/{} bytes via virtual client socket",
                                virtual_port,
                                sent,
                                total,
                            );
                            tx_extra = Vec::from(&to_transfer_slice[sent..total]);
                        }
                        Err(e) => {
                            error!(
                                "[{}] Failed to send slice via virtual client socket: {:?}",
                                virtual_port, e
                            );
                        }
                    }
                }
            }
        }

        if shutdown {
            break;
        }

        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    trace!("[{}] Virtual interface task terminated", virtual_port);
    abort.store(true, Ordering::Relaxed);
    Ok(())
}

fn init_logger(config: &Config) -> anyhow::Result<()> {
    let mut builder = pretty_env_logger::formatted_builder();
    builder.parse_filters(&config.log);
    builder
        .try_init()
        .with_context(|| "Failed to initialize logger")
}
