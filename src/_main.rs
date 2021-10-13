#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use crate::client::ProxyClient;
use anyhow::Context;
use boringtun::device::peer::Peer;
use boringtun::noise::{Tunn, TunnResult};
use crossbeam_channel::{Receiver, RecvError, Sender};
use dashmap::DashMap;
use smoltcp::iface::InterfaceBuilder;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{SocketRef, SocketSet, TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{
    IpAddress, IpCidr, IpRepr, IpVersion, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, PrettyPrinter,
};

use crate::config::Config;
use crate::virtual_device::VirtualIpDevice;

mod client;
mod config;
mod virtual_device;

const MAX_PACKET: usize = 65536;

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init_custom_env("ONETUN_LOG");
    let config = Config::from_args().with_context(|| "Failed to read config")?;
    debug!("Parsed arguments: {:?}", config);

    info!(
        "Tunnelling [{}]->[{}] (via [{}] as peer {})",
        &config.source_addr, &config.dest_addr, &config.endpoint_addr, &config.source_peer_ip
    );

    let source_peer_ip = config.source_peer_ip;
    let dest_addr_ip = config.dest_addr.ip();
    let dest_addr_port = config.dest_addr.port();
    let endpoint_addr = config.endpoint_addr;

    // tx/rx for unencrypted IP packets to send through wireguard tunnel
    let (send_to_real_server_tx, send_to_real_server_rx) =
        crossbeam_channel::unbounded::<Vec<u8>>();

    // tx/rx for decrypted IP packets that were received through wireguard tunnel
    let (send_to_virtual_interface_tx, send_to_virtual_interface_rx) =
        crossbeam_channel::unbounded::<Vec<u8>>();

    // Initialize peer based on config
    let peer = Tunn::new(
        config.private_key.clone(),
        config.endpoint_public_key.clone(),
        None,
        None,
        0,
        None,
    )
    .map_err(|s| anyhow::anyhow!("{}", s))
    .with_context(|| "Failed to initialize peer")?;

    let peer = Arc::new(peer);

    let endpoint_socket =
        Arc::new(UdpSocket::bind("0.0.0.0:0").with_context(|| "Failed to bind endpoint socket")?);

    let (new_client_tx, new_client_rx) = crossbeam_channel::unbounded::<ProxyClient>();
    let (dead_client_tx, dead_client_rx) = crossbeam_channel::unbounded::<u16>();

    // tx/rx for IP packets the interface exchanged that should be filtered/routed
    let (send_to_ip_filter_tx, send_to_ip_filter_rx) = crossbeam_channel::unbounded::<Vec<u8>>();

    // Virtual interface thread
    {
        thread::spawn(move || {
            // Virtual device: generated IP packets will be send to ip_tx, and IP packets that should be polled should be sent to given ip_rx.
            let virtual_device =
                VirtualIpDevice::new(send_to_ip_filter_tx, send_to_virtual_interface_rx.clone());

            // Create a virtual interface that will generate the IP packets for us
            let mut virtual_interface = InterfaceBuilder::new(virtual_device)
                .ip_addrs([
                    // Interface handles IP packets for the sender and recipient
                    IpCidr::new(IpAddress::from(source_peer_ip), 32),
                    IpCidr::new(IpAddress::from(dest_addr_ip), 32),
                ])
                .any_ip(true)
                .finalize();

            // Server socket: this is a placeholder for the interface to route new connections to.
            // TODO: Determine if we even need buffers here.
            let server_socket = {
                static mut TCP_SERVER_RX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
                static mut TCP_SERVER_TX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
                let tcp_rx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_RX_DATA[..] });
                let tcp_tx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_TX_DATA[..] });
                let mut socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

                socket
                    .listen((IpAddress::from(dest_addr_ip), dest_addr_port))
                    .expect("Virtual server socket failed to listen");

                socket
            };

            // Socket set: there is always 1 TCP socket for the server, and the rest are client sockets created over time.
            let socket_set_entries = Vec::new();
            let mut socket_set = SocketSet::new(socket_set_entries);
            socket_set.add(server_socket);

            // Gate socket_set behind RwLock so we can add clients in the background
            let socket_set = Arc::new(RwLock::new(socket_set));
            let socket_set_1 = socket_set.clone();
            let socket_set_2 = socket_set.clone();

            let client_port_to_handle = Arc::new(DashMap::new());
            let client_port_to_handle_1 = client_port_to_handle.clone();

            let client_handle_to_client = Arc::new(DashMap::new());
            let client_handle_to_client_1 = client_handle_to_client.clone();
            let client_handle_to_client_2 = client_handle_to_client.clone();

            // Checks if there are new clients to initialize, and adds them to the socket_set
            thread::spawn(move || {
                let socket_set = socket_set_1;
                let client_handle_to_client = client_handle_to_client_1;

                loop {
                    let client = new_client_rx.recv().expect("failed to read new_client_rx");

                    // Create a virtual client socket for the client
                    let client_socket = {
                        static mut TCP_CLIENT_RX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
                        static mut TCP_CLIENT_TX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
                        let tcp_rx_buffer =
                            TcpSocketBuffer::new(unsafe { &mut TCP_CLIENT_RX_DATA[..] });
                        let tcp_tx_buffer =
                            TcpSocketBuffer::new(unsafe { &mut TCP_CLIENT_TX_DATA[..] });
                        let mut socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

                        socket
                            .connect(
                                (IpAddress::from(dest_addr_ip), dest_addr_port),
                                (IpAddress::from(source_peer_ip), client.virtual_port),
                            )
                            .expect("failed to connect virtual client");

                        socket
                    };

                    // Add to socket set: this makes the ip/port combination routable in the interface, so that IP packets
                    // received from WG actually go somewhere.
                    let mut socket_set = socket_set
                        .write()
                        .expect("failed to acquire lock on socket_set to add new client");
                    let client_handle = socket_set.add(client_socket);

                    // Map the client handle by port so we can look it up later
                    client_port_to_handle.insert(client.virtual_port, client_handle);
                    client_handle_to_client.insert(client_handle, client);
                }
            });

            // Checks if there are clients that disconnected, and removes them from the socket_set
            thread::spawn(move || {
                let dead_client_rx = dead_client_rx.clone();
                let socket_set = socket_set_2;
                let client_handle_to_client = client_handle_to_client_2;
                let client_port_to_handle = client_port_to_handle_1;

                loop {
                    let client_port = dead_client_rx
                        .recv()
                        .expect("failed to read dead_client_rx");

                    // Get handle, if any
                    let handle = client_port_to_handle.remove(&client_port);

                    // Remove handle from socket set and from map (handle -> client def)
                    if let Some((_, handle)) = handle {
                        // Remove socket set
                        let mut socket_set = socket_set
                            .write()
                            .expect("failed to acquire lock on socket_set to add new client");
                        socket_set.remove(handle);
                        client_handle_to_client.remove(&handle);
                        debug!("Removed client from socket set: vport={}", client_port);
                    }
                }
            });

            loop {
                let loop_start = Instant::now();

                // Poll virtual interface
                // Note: minimize lock time on socket set so new clients can fit in
                {
                    let mut socket_set = socket_set
                        .write()
                        .expect("failed to acquire lock on socket_set to poll interface");
                    match virtual_interface.poll(&mut socket_set, loop_start) {
                        Ok(processed) if processed => {
                            debug!("Virtual interface polled and processed some packets");
                        }
                        Err(e) => {
                            error!("Virtual interface poll error: {}", e);
                        }
                        _ => {}
                    }
                }

                {
                    let mut socket_set = socket_set
                        .write()
                        .expect("failed to acquire lock on socket_set to get client socket");
                    // Process packets for each client
                    for x in client_handle_to_client.iter() {
                        let client_handle = x.key();
                        let client_def = x.value();

                        let mut client_socket: SocketRef<TcpSocket> =
                            socket_set.get(*client_handle);

                        // Send data received from the real client as the virtual client
                        if client_socket.can_send() {
                            while !client_def.data_rx.is_empty() {
                                let to_send = client_def
                                    .data_rx
                                    .recv()
                                    .expect("failed to read from client data_rx channel");
                                client_socket.send_slice(&to_send).expect("virtual client failed to send data as received from data_rx channel");
                            }
                        }

                        // Send data received by the virtual client to the real client
                        if client_socket.can_recv() {
                            let data = client_socket
                                .recv(|b| (b.len(), b.to_vec()))
                                .expect("virtual client failed to recv");
                            client_def
                                .data_tx
                                .send(data)
                                .expect("failed to send data to client data_tx channel");
                        }
                    }
                }

                // Use poll_delay to know when is the next time to poll.
                {
                    let socket_set = socket_set
                        .read()
                        .expect("failed to acquire read lock on socket_set to poll_delay");

                    match virtual_interface.poll_delay(&socket_set, loop_start) {
                        Some(smoltcp::time::Duration::ZERO) => {}
                        Some(delay) => {
                            thread::sleep(std::time::Duration::from_millis(delay.millis()))
                        }
                        _ => thread::sleep(std::time::Duration::from_millis(1)),
                    }
                }
            }
        });
    }

    // Packet routing thread
    // Filters packets sent by the virtual interface, so that only the ones that should be sent
    // to the real server are.
    thread::spawn(move || {
        loop {
            let recv = send_to_ip_filter_rx
                .recv()
                .expect("failed to read send_to_ip_filter_rx channel");
            let src_addr: IpAddr = match IpVersion::of_packet(&recv) {
                Ok(v) => match v {
                    IpVersion::Ipv4 => {
                        match Ipv4Repr::parse(
                            &Ipv4Packet::new_unchecked(&recv),
                            &ChecksumCapabilities::ignored(),
                        ) {
                            Ok(packet) => Ipv4Addr::from(packet.src_addr).into(),
                            Err(e) => {
                                error!("Unable to determine source IPv4 from packet: {}", e);
                                continue;
                            }
                        }
                    }
                    IpVersion::Ipv6 => match Ipv6Repr::parse(&Ipv6Packet::new_unchecked(&recv)) {
                        Ok(packet) => Ipv6Addr::from(packet.src_addr).into(),
                        Err(e) => {
                            error!("Unable to determine source IPv6 from packet: {}", e);
                            continue;
                        }
                    },
                    _ => {
                        error!("Unable to determine IP version from packet: unspecified",);
                        continue;
                    }
                },
                Err(e) => {
                    error!("Unable to determine IP version from packet: {}", e);
                    continue;
                }
            };
            if src_addr == source_peer_ip {
                debug!(
                    "IP packet: {} bytes from {} to send to WG",
                    recv.len(),
                    src_addr
                );
                // Add to queue to be encapsulated and sent by other thread
                send_to_real_server_tx
                    .send(recv)
                    .expect("failed to write to send_to_real_server_tx channel");
            }
        }
    });

    // Thread that encapsulates and sends WG packets
    {
        let peer = peer.clone();
        let endpoint_socket = endpoint_socket.clone();

        thread::spawn(move || {
            let peer = peer.clone();
            loop {
                let mut send_buf = [0u8; MAX_PACKET];
                match send_to_real_server_rx.recv() {
                    Ok(next) => match peer.encapsulate(next.as_slice(), &mut send_buf) {
                        TunnResult::WriteToNetwork(packet) => {
                            endpoint_socket
                                .send_to(packet, endpoint_addr)
                                .expect("failed to send packet to wg endpoint");
                            debug!("Sent {} bytes through WG (encryped)", packet.len());
                        }
                        TunnResult::Err(e) => {
                            error!("Failed to encapsulate: {:?}", e);
                        }
                        TunnResult::Done => {
                            // Ignored
                        }
                        other => {
                            error!("Unexpected TunnResult during encapsulation: {:?}", other);
                        }
                    },
                    Err(e) => {
                        error!(
                            "Failed to consume from send_to_real_server_rx channel: {}",
                            e
                        );
                    }
                }
            }
        });
    }

    // Thread that decapulates WG IP packets and feeds them to the interface
    {
        let peer = peer.clone();
        let endpoint_socket = endpoint_socket.clone();

        thread::spawn(move || loop {
            // Listen on the network
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut send_buf = [0u8; MAX_PACKET];

            let n = match endpoint_socket.recv(&mut recv_buf) {
                Ok(n) => n,
                Err(e) => {
                    error!("Failed to read from endpoint socket: {}", e);
                    break;
                }
            };

            let data = &recv_buf[..n];
            match peer.decapsulate(None, data, &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    endpoint_socket
                        .send_to(packet, endpoint_addr)
                        .expect("failed to send packet to wg endpoint");
                    loop {
                        let mut send_buf = [0u8; MAX_PACKET];
                        match peer.decapsulate(None, &[], &mut send_buf) {
                            TunnResult::WriteToNetwork(packet) => {
                                endpoint_socket
                                    .send_to(packet, endpoint_addr)
                                    .expect("failed to send packet to wg endpoint");
                            }
                            _ => {
                                break;
                            }
                        }
                    }
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    debug!(
                        "Got {} bytes to send back to virtual interface",
                        packet.len()
                    );

                    // For debugging purposes: parse packet
                    {
                        match IpVersion::of_packet(&packet) {
                            Ok(IpVersion::Ipv4) => trace!(
                                "IPv4 packet received: {}",
                                PrettyPrinter::<Ipv4Packet<&mut [u8]>>::new("", &packet)
                            ),
                            Ok(IpVersion::Ipv6) => trace!(
                                "IPv6 packet received: {}",
                                PrettyPrinter::<Ipv6Packet<&mut [u8]>>::new("", &packet)
                            ),
                            _ => {}
                        }
                    }

                    send_to_virtual_interface_tx
                        .send(packet.to_vec())
                        .expect("failed to queue received wg packet");
                }
                TunnResult::WriteToTunnelV6(packet, _) => {
                    debug!(
                        "Got {} bytes to send back to virtual interface",
                        packet.len()
                    );
                    send_to_virtual_interface_tx
                        .send(packet.to_vec())
                        .expect("failed to queue received wg packet");
                }
                _ => {}
            }
        });
    }

    // Maintenance thread
    {
        let peer = peer.clone();
        let endpoint_socket = endpoint_socket.clone();

        thread::spawn(move || loop {
            let mut send_buf = [0u8; MAX_PACKET];
            match peer.update_timers(&mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    debug!("Sending maintenance message: {} bytes", packet.len());
                    endpoint_socket
                        .send_to(packet, endpoint_addr)
                        .expect("failed to send maintenance packet to endpoint address");
                }
                _ => {}
            }

            thread::sleep(Duration::from_millis(200));
        });
    }

    let proxy_listener = TcpListener::bind(config.source_addr).unwrap();
    for client_stream in proxy_listener.incoming() {
        client_stream
            .map(|client_stream| {
                let dead_client_tx = dead_client_tx.clone();

                // Pick a port
                // TODO: Pool
                let port = 60000;
                let (data_to_read_tx, data_to_read_rx) = crossbeam_channel::unbounded::<Vec<u8>>();
                let (data_to_send_tx, data_to_send_rx) = crossbeam_channel::unbounded::<Vec<u8>>();

                let client_addr = client_stream
                    .peer_addr()
                    .expect("client has no peer address");
                info!("[{}] Incoming connection from {}", port, client_addr);

                let client = ProxyClient {
                    virtual_port: port,
                    data_tx: data_to_send_tx,
                    data_rx: data_to_read_rx,
                };

                // Register the new client with the virtual interface
                new_client_tx.send(client.clone()).expect("failed to notify virtual interface of new client");

                // Reads data from the client
                thread::spawn(move || {
                    let mut client_stream = client_stream;

                    // todo: change this to tokio?
                    client_stream
                        .set_nonblocking(true)
                        .expect("failed to set nonblocking");

                    loop {
                        let mut buffer = [0; MAX_PACKET];
                        let read = client_stream.read(&mut buffer);
                        match read {
                            Ok(size) if size == 0 => {
                                info!("[{}] Connection closed by client: {}", port, client_addr);
                                break;
                            }
                            Ok(size) => {
                                debug!("[{}] Data received from client: {} bytes", port, size);
                                let data = &buffer[..size];
                                data_to_read_tx.send(data.to_vec())
                                    .unwrap_or_else(|e| error!("[{}] failed to send data to data_to_read_tx channel as received from client: {}", port, e));
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                // Ignore and continue
                            }
                            Err(e) => {
                                warn!("[{}] Connection error: {}", port, e);
                                break;
                            }
                        }

                        while !data_to_send_rx.is_empty() {
                            let recv = data_to_send_rx.recv().expect("failed to read data_to_send_rx");
                            client_stream
                                .write(recv.as_slice())
                                .unwrap_or_else(|e| {
                                    error!("[{}] failed to send write to client stream: {}", port, e);
                                    0
                                });
                        }
                    }

                    dead_client_tx.send(port).expect("failed to send to dead_client_tx channel");
                });
            })
            .unwrap_or_else(|e| error!("{:?}", e));
    }
    Ok(())
}
