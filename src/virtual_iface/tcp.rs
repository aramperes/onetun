use crate::config::{PortForwardConfig, PortProtocol};
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::{VirtualInterfacePoll, VirtualPort};
use crate::wg::WireGuardTunnel;
use anyhow::Context;
use async_trait::async_trait;
use smoltcp::iface::InterfaceBuilder;
use smoltcp::socket::{TcpSocket, TcpSocketBuffer, TcpState};
use smoltcp::wire::{IpAddress, IpCidr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_PACKET: usize = 65536;

/// A virtual interface for proxying Layer 7 data to Layer 3 packets, and vice-versa.
pub struct TcpVirtualInterface {
    /// The virtual port assigned to the virtual client, used to
    /// route Layer 4 segments/datagrams to and from the WireGuard tunnel.
    virtual_port: u16,
    /// The overall port-forward configuration: used for the destination address (on which
    /// the virtual server listens) and the protocol in use.
    port_forward: PortForwardConfig,
    /// The WireGuard tunnel to send IP packets to.
    wg: Arc<WireGuardTunnel>,
    /// Abort signal to shutdown the virtual interface and its parent task.
    abort: Arc<AtomicBool>,
    /// Channel sender for pushing Layer 7 data back to the real client.
    data_to_real_client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Channel receiver for processing Layer 7 data through the virtual interface.
    data_to_virtual_server_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    /// One-shot sender to notify the parent task that the virtual client is ready to send Layer 7 data.
    virtual_client_ready_tx: tokio::sync::oneshot::Sender<()>,
}

impl TcpVirtualInterface {
    /// Initialize the parameters for a new virtual interface.
    /// Use the `poll_loop()` future to start the virtual interface poll loop.
    pub fn new(
        virtual_port: u16,
        port_forward: PortForwardConfig,
        wg: Arc<WireGuardTunnel>,
        abort: Arc<AtomicBool>,
        data_to_real_client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        data_to_virtual_server_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        virtual_client_ready_tx: tokio::sync::oneshot::Sender<()>,
    ) -> Self {
        Self {
            virtual_port,
            port_forward,
            wg,
            abort,
            data_to_real_client_tx,
            data_to_virtual_server_rx,
            virtual_client_ready_tx,
        }
    }
}

#[async_trait]
impl VirtualInterfacePoll for TcpVirtualInterface {
    async fn poll_loop(self) -> anyhow::Result<()> {
        let mut virtual_client_ready_tx = Some(self.virtual_client_ready_tx);
        let mut data_to_virtual_server_rx = self.data_to_virtual_server_rx;
        let source_peer_ip = self.wg.source_peer_ip;

        // Create a device and interface to simulate IP packets
        // In essence:
        // * TCP packets received from the 'real' client are 'sent' to the 'virtual server' via the 'virtual client'
        // * Those TCP packets generate IP packets, which are captured from the interface and sent to the WireGuardTunnel
        // * IP packets received by the WireGuardTunnel (from the endpoint) are fed into this 'virtual interface'
        // * The interface processes those IP packets and routes them to the 'virtual client' (the rest is discarded)
        // * The TCP data read by the 'virtual client' is sent to the 'real' TCP client

        // Consumer for IP packets to send through the virtual interface
        // Initialize the interface
        let device =
            VirtualIpDevice::new_direct(VirtualPort(self.virtual_port, PortProtocol::Tcp), self.wg)
                .with_context(|| "Failed to initialize TCP VirtualIpDevice")?;

        // there are always 2 sockets: 1 virtual client and 1 virtual server.
        let mut sockets: [_; 2] = Default::default();
        let mut virtual_interface = InterfaceBuilder::new(device, &mut sockets[..])
            .ip_addrs([
                // Interface handles IP packets for the sender and recipient
                IpCidr::new(IpAddress::from(source_peer_ip), 32),
                IpCidr::new(IpAddress::from(self.port_forward.destination.ip()), 32),
            ])
            .finalize();

        // Server socket: this is a placeholder for the interface to route new connections to.
        let server_socket: anyhow::Result<TcpSocket> = {
            static mut TCP_SERVER_RX_DATA: [u8; 0] = [];
            static mut TCP_SERVER_TX_DATA: [u8; 0] = [];
            let tcp_rx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_RX_DATA[..] });
            let tcp_tx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_TX_DATA[..] });
            let mut socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

            socket
                .listen((
                    IpAddress::from(self.port_forward.destination.ip()),
                    self.port_forward.destination.port(),
                ))
                .with_context(|| "Virtual server socket failed to listen")?;

            Ok(socket)
        };

        let client_socket: anyhow::Result<TcpSocket> = {
            let rx_data = vec![0u8; MAX_PACKET];
            let tx_data = vec![0u8; MAX_PACKET];
            let tcp_rx_buffer = TcpSocketBuffer::new(rx_data);
            let tcp_tx_buffer = TcpSocketBuffer::new(tx_data);
            let socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
            Ok(socket)
        };

        let _server_handle = virtual_interface.add_socket(server_socket?);
        let client_handle = virtual_interface.add_socket(client_socket?);

        // Any data that wasn't sent because it was over the sending buffer limit
        let mut tx_extra = Vec::new();

        // Counts the connection attempts by the virtual client
        let mut connection_attempts = 0;
        // Whether the client has successfully connected before. Prevents the case of connecting again.
        let mut has_connected = false;

        loop {
            let loop_start = smoltcp::time::Instant::now();

            // Shutdown occurs when the real client closes the connection,
            // or if the client was in a CLOSE-WAIT state (after a server FIN) and had no data to send anymore.
            // One last poll-loop iteration is executed so that the RST segment can be dispatched.
            let shutdown = self.abort.load(Ordering::Relaxed);

            if shutdown {
                // Shutdown: sends a RST packet.
                trace!("[{}] Shutting down virtual interface", self.virtual_port);
                let client_socket = virtual_interface.get_socket::<TcpSocket>(client_handle);
                client_socket.abort();
            }

            match virtual_interface.poll(loop_start) {
                Ok(processed) if processed => {
                    trace!(
                        "[{}] Virtual interface polled some packets to be processed",
                        self.virtual_port
                    );
                }
                Err(e) => {
                    error!(
                        "[{}] Virtual interface poll error: {:?}",
                        self.virtual_port, e
                    );
                }
                _ => {}
            }

            {
                let (client_socket, context) =
                    virtual_interface.get_socket_and_context::<TcpSocket>(client_handle);

                if !shutdown && client_socket.state() == TcpState::Closed && !has_connected {
                    // Not shutting down, but the client socket is closed, and the client never successfully connected.
                    if connection_attempts < 10 {
                        // Try to connect
                        client_socket
                            .connect(
                                context,
                                (
                                    IpAddress::from(self.port_forward.destination.ip()),
                                    self.port_forward.destination.port(),
                                ),
                                (IpAddress::from(source_peer_ip), self.virtual_port),
                            )
                            .with_context(|| "Virtual server socket failed to listen")?;
                        if connection_attempts > 0 {
                            debug!(
                                "[{}] Virtual client retrying connection in 500ms",
                                self.virtual_port
                            );
                            // Not our first connection attempt, wait a little bit.
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    } else {
                        // Too many connection attempts
                        self.abort.store(true, Ordering::Relaxed);
                    }
                    connection_attempts += 1;
                    continue;
                }

                if client_socket.state() == TcpState::Established {
                    // Prevent reconnection if the server later closes.
                    has_connected = true;
                }

                if client_socket.can_recv() {
                    match client_socket.recv(|buffer| (buffer.len(), buffer.to_vec())) {
                        Ok(data) => {
                            trace!(
                                "[{}] Virtual client received {} bytes of data",
                                self.virtual_port,
                                data.len()
                            );
                            // Send it to the real client
                            if let Err(e) = self.data_to_real_client_tx.send(data).await {
                                error!("[{}] Failed to dispatch data from virtual client to real client: {:?}", self.virtual_port, e);
                            }
                        }
                        Err(e) => {
                            error!(
                                "[{}] Failed to read from virtual client socket: {:?}",
                                self.virtual_port, e
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
                            trace!("[{}] Shutting down virtual interface because client sent no more data, and server sent FIN (CLOSE-WAIT)", self.virtual_port);
                            self.abort.store(true, Ordering::Relaxed);
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
                                    self.virtual_port,
                                    sent,
                                    total,
                                );
                                tx_extra = Vec::from(&to_transfer_slice[sent..total]);
                            }
                            Err(e) => {
                                error!(
                                    "[{}] Failed to send slice via virtual client socket: {:?}",
                                    self.virtual_port, e
                                );
                            }
                        }
                    }
                }
            }

            if shutdown {
                break;
            }

            match virtual_interface.poll_delay(loop_start) {
                Some(smoltcp::time::Duration::ZERO) => {
                    continue;
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
        trace!("[{}] Virtual interface task terminated", self.virtual_port);
        self.abort.store(true, Ordering::Relaxed);
        Ok(())
    }
}
