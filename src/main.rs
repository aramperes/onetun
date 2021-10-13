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

use anyhow::Context;
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::device::peer::Peer;
use boringtun::noise::{Tunn, TunnResult};
use clap::{App, Arg};
use crossbeam_channel::{Receiver, RecvError, Sender};
use smoltcp::iface::InterfaceBuilder;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{SocketRef, SocketSet, TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{
    IpAddress, IpCidr, IpRepr, IpVersion, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
};

use crate::config::Config;
use crate::virtual_device::VirtualIpDevice;

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
                    debug!("Got {} bytes to send back to client", packet.len());
                    send_to_virtual_interface_tx
                        .send(packet.to_vec())
                        .expect("failed to queue received wg packet");
                }
                TunnResult::WriteToTunnelV6(packet, _) => {
                    debug!("Got {} bytes to send back to client", packet.len());
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
                let send_to_real_server_tx = send_to_real_server_tx.clone();
                let send_to_virtual_interface_rx = send_to_virtual_interface_rx.clone();

                // Pick a port
                // TODO: Pool
                let port = 60000;

                let client_addr = client_stream
                    .peer_addr()
                    .expect("client has no peer address");
                info!("[{}] Incoming connection from {}", port, client_addr);

                // tx/rx for data received from the client
                // this data is received
                let (send_to_virtual_client_tx, send_to_virtual_client_rx) = crossbeam_channel::unbounded::<Vec<u8>>();

                // tx/rx for packets received from the destination
                // this data is received from the WG endpoint; the IP packets are routed using the port number
                let (send_to_real_client_tx, send_to_real_client_rx) = crossbeam_channel::unbounded::<Vec<u8>>();

                // tx/rx for IP packets the interface exchanged that should be filtered/routed
                let (send_to_ip_filter_tx, send_to_ip_filter_rx) = crossbeam_channel::unbounded::<Vec<u8>>();

                let stopped = Arc::new(AtomicBool::new(false));
                let stopped_1 = Arc::clone(&stopped);
                let stopped_2 = Arc::clone(&stopped);

                // Reads data from the client
                thread::spawn(move || {
                    let stopped = stopped_1.clone();

                    let mut client_stream = client_stream;
                    client_stream
                        .set_nonblocking(true)
                        .expect("failed to set nonblocking");
                    loop {
                        if stopped.load(Ordering::Relaxed) {
                            break;
                        }

                        let mut buffer = [0; MAX_PACKET];
                        let read = client_stream.read(&mut buffer);
                        match read {
                            Ok(size) if size == 0 => {
                                info!("[{}] Connection closed by client: {}", port, client_addr);
                                stopped.store(true, Ordering::Relaxed);
                                break;
                            }
                            Ok(size) => {
                                debug!("[{}] Data received from client: {} bytes", port, size);
                                let data = &buffer[..size];
                                send_to_virtual_client_tx
                                    .send(data.to_vec())
                                    .unwrap_or_else(|e| error!("[{}] failed to send data to client_received_tx channel as received from client: {}", port, e));
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                // Ignore and continue
                            }
                            Err(e) => {
                                warn!("[{}] Connection error: {}", port, e);
                                stopped.store(true, Ordering::Relaxed);
                                break;
                            }
                        }

                        while !send_to_ip_filter_rx.is_empty() {
                            let recv = send_to_ip_filter_rx.recv().expect("failed to read send_to_ip_filter_rx");
                            let src_addr: IpAddr = match IpVersion::of_packet(&recv) {
                                Ok(v) => {
                                    match v {
                                        IpVersion::Ipv4 => {
                                            match Ipv4Repr::parse(&Ipv4Packet::new_unchecked(&recv), &ChecksumCapabilities::ignored()) {
                                                Ok(packet) => Ipv4Addr::from(packet.src_addr).into(),
                                                Err(e) => {
                                                    error!("[{}] Unable to determine source IPv4 from packet: {}", port, e);
                                                    continue;
                                                }
                                            }
                                        }
                                        IpVersion::Ipv6 => {
                                            match Ipv6Repr::parse(&Ipv6Packet::new_unchecked(&recv)) {
                                                Ok(packet) => Ipv6Addr::from(packet.src_addr).into(),
                                                Err(e) => {
                                                    error!("[{}] Unable to determine source IPv6 from packet: {}", port, e);
                                                    continue;
                                                }
                                            }
                                        }
                                        _ => {
                                            error!("[{}] Unable to determine IP version from packet: unspecified", port);
                                            continue;
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("[{}] Unable to determine IP version from packet: {}", port, e);
                                    continue;
                                }
                            };

                            if src_addr == source_peer_ip {
                                debug!("[{}] IP packet: {} bytes from {} to send to WG", port, recv.len(), src_addr);
                                // Add to queue to be encapsulated and sent by other thread
                                send_to_real_server_tx.send(recv).expect("failed to write to send_to_real_server_tx channel");
                            }
                        }

                        while !send_to_real_client_rx.is_empty() {
                            let recv = send_to_real_client_rx.recv().expect("failed to read destination_sent_rx");
                            client_stream
                                .write(recv.as_slice())
                                .unwrap_or_else(|e| {
                                    error!("[{}] failed to send write to client stream: {}", port, e);
                                    0
                                });
                        }
                    }
                });

                // This thread simulates the IP-layer communication between the client and server.
                // * When we get data from the 'real' client, we send it via the virtual client
                // * When the virtual client sends data, it generates IP packets, which are captures via ip_rx/ip_tx
                thread::spawn(move || {
                    let stopped = Arc::clone(&stopped_2);

                    let server_socket = {
                        static mut TCP_SERVER_RX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
                        static mut TCP_SERVER_TX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
                        let tcp_rx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_RX_DATA[..] });
                        let tcp_tx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_SERVER_TX_DATA[..] });
                        TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer)
                    };

                    let client_socket = {
                        static mut TCP_CLIENT_RX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
                        static mut TCP_CLIENT_TX_DATA: [u8; MAX_PACKET] = [0; MAX_PACKET];
                        let tcp_rx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_CLIENT_RX_DATA[..] });
                        let tcp_tx_buffer = TcpSocketBuffer::new(unsafe { &mut TCP_CLIENT_TX_DATA[..] });
                        TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer)
                    };

                    let mut socket_set_entries: [_; 2] = Default::default();
                    let mut socket_set = SocketSet::new(&mut socket_set_entries[..]);
                    let server_handle = socket_set.add(server_socket);
                    let client_handle = socket_set.add(client_socket);

                    // Virtual device
                    let device = VirtualIpDevice::new(send_to_ip_filter_tx, send_to_virtual_interface_rx.clone());

                    // Create a virtual interface to simulate TCP connection
                    let mut iface = InterfaceBuilder::new(device)
                        .ip_addrs([
                            // Interface handles IP packets for the sender and recipient
                            IpCidr::new(IpAddress::from(source_peer_ip), 32),
                            IpCidr::new(IpAddress::from(dest_addr_ip), 32),
                        ])
                        .any_ip(true)
                        .finalize();

                    // keeps track of whether the virtual clients needs to be initialized
                    let mut started = false;

                    loop {
                        let loop_start = Instant::now();
                        if stopped.load(Ordering::Relaxed) {
                            debug!("[{}] Killing virtual thread", port);
                            break;
                        }

                        match iface.poll(&mut socket_set, loop_start) {
                            Ok(processed) => {
                                if processed {
                                    debug!("[{}] virtual iface polled and processed some packets", port);
                                }
                            }
                            Err(e) => {
                                error!("[{}] virtual iface poll error: {:?}", port, e);
                                break;
                            }
                        }

                        // Spawn a server socket so the virtual interface allows routing
                        // Note: the server socket is never read, since the IP packets are intercepted
                        // at the interface level.
                        {
                            let mut server_socket: SocketRef<TcpSocket> = socket_set.get(server_handle);
                            if !started {
                                // Open the virtual server socket
                                match server_socket.listen((IpAddress::from(dest_addr_ip), dest_addr_port)) {
                                    Ok(_) => {
                                        debug!("[{}] Virtual server listening: {}", port, server_socket.local_endpoint());
                                    }
                                    Err(e) => {
                                        error!("[{}] Virtual server failed to listen: {}", port, e);
                                        break;
                                    }
                                }
                            }
                        }

                        // Virtual client
                        {
                            let mut client_socket: SocketRef<TcpSocket> = socket_set.get(client_handle);
                            if !started {
                                client_socket.connect(
                                    (IpAddress::from(dest_addr_ip), dest_addr_port),
                                    (IpAddress::from(source_peer_ip), port),
                                )
                                    .expect("failed to connect virtual client");
                                debug!("[{}] Virtual client connected", port);
                            }
                            if client_socket.can_send() {
                                while !send_to_virtual_client_rx.is_empty() {
                                    let to_send = send_to_virtual_client_rx.recv().expect("failed to read from client_received_rx channel");
                                    client_socket.send_slice(to_send.as_slice()).expect("virtual client failed to send data from channel");
                                }
                            }
                            if client_socket.can_recv() {
                                let data = client_socket.recv(|b| (b.len(), b.to_vec())).expect("failed to recv");
                                send_to_real_client_tx.send(data).expect("failed to send to channel send_to_real_client_tx");
                            }
                            if !client_socket.is_open() {
                                warn!("[{}] Client socket is no longer open", port);
                                break;
                            }
                        }

                        // After the first loop, the client and server have started
                        started = true;

                        match iface.poll_delay(&socket_set, loop_start) {
                            Some(smoltcp::time::Duration::ZERO) => {}
                            Some(delay) => std::thread::sleep(std::time::Duration::from_millis(delay.millis())),
                            _ => {}
                        }
                    }

                    // if this thread ends, end the other ones too
                    debug!("[{}] Virtual thread stopped", port);
                    stopped.store(true, Ordering::Relaxed);
                });
                // * When the real destination sends IP packets (via WG endpoint), we send it via the device/interface
            })
            .unwrap_or_else(|e| error!("{:?}", e));
    }
    Ok(())
}
