#[macro_use]
extern crate log;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::device::peer::Peer;
use boringtun::noise::{Tunn, TunnResult};
use clap::{App, Arg};
use packet::ip::Protocol;
use packet::Builder;
use smoltcp::wire::Ipv4Packet;

use crate::config::Config;

mod config;

const MAX_PACKET: usize = 65536;

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init_custom_env("ONETUN_LOG");
    let config = Config::from_args().with_context(|| "Failed to read config")?;
    debug!("Parsed arguments: {:?}", config);

    let peer = Arc::new(
        Tunn::new(
            config.private_key.clone(),
            config.endpoint_public_key.clone(),
            None,
            None,
            0,
            None,
        )
        .map_err(|s| anyhow::anyhow!("{}", s))
        .with_context(|| "Failed to initialize peer")?,
    );

    let source_sock = Arc::new(
        UdpSocket::bind(&config.source_addr).with_context(|| "Failed to bind source socket")?,
    );

    let endpoint_sock =
        Arc::new(UdpSocket::bind("0.0.0.0:0").with_context(|| "Failed to bind endpoint socket")?);

    let endpoint_addr = config.endpoint_addr;

    let source_peer_addr = SocketAddr::new(config.source_peer_ip, 1234);
    let destination_addr = config.dest_addr;

    let close = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(3);

    // thread 1: read from endpoint, forward to peer
    {
        let close = close.clone();
        let peer = peer.clone();
        let source_sock = source_sock.clone();
        let endpoint_sock = endpoint_sock.clone();

        handles.push(thread::spawn(move || loop {
            // Listen on the network
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut send_buf = [0u8; MAX_PACKET];

            let n = match endpoint_sock.recv(&mut recv_buf) {
                Ok(n) => n,
                Err(_) => {
                    if close.load(Ordering::Relaxed) {
                        return;
                    }
                    continue;
                }
            };

            let data = &recv_buf[..n];
            match peer.decapsulate(None, data, &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    send_packet(packet, endpoint_sock.clone(), endpoint_addr).unwrap();
                    loop {
                        let mut send_buf = [0u8; MAX_PACKET];
                        match peer.decapsulate(None, &[], &mut send_buf) {
                            TunnResult::WriteToNetwork(packet) => {
                                send_packet(packet, endpoint_sock.clone(), endpoint_addr).unwrap();
                            }
                            _ => {
                                break;
                            }
                        }
                    }
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    source_sock.send(packet).unwrap();
                }
                TunnResult::WriteToTunnelV6(packet, _) => {
                    source_sock.send(packet).unwrap();
                }
                _ => {}
            }
        }));
    }

    // thread 2: read from peer socket
    {
        let close = close.clone();
        let peer = peer.clone();
        let source_sock = source_sock.clone();
        let endpoint_sock = endpoint_sock.clone();

        handles.push(thread::spawn(move || loop {
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut send_buf = [0u8; MAX_PACKET];

            let n = match source_sock.recv(&mut recv_buf) {
                Ok(n) => n,
                Err(_) => {
                    if close.load(Ordering::Relaxed) {
                        return;
                    }
                    continue;
                }
            };

            let data = &recv_buf[..n];

            // TODO: Support TCP
            let ip_packet =
                wrap_data_packet(Protocol::Udp, data, source_peer_addr, destination_addr)
                    .expect("Failed to wrap data packet");

            debug!("Crafted IP packet: {:#?}", ip_packet);

            match peer.encapsulate(ip_packet.as_slice(), &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    send_packet(packet, endpoint_sock.clone(), endpoint_addr).unwrap();
                }
                TunnResult::Err(e) => {
                    error!("Failed to encapsulate: {:?}", e);
                }
                other => {
                    error!("Unexpected TunnResult during encapsulation: {:?}", other);
                }
            }
        }));
    }

    // thread 3: maintenance
    {
        let close = close.clone();
        let peer = peer.clone();
        let endpoint_sock = endpoint_sock.clone();

        handles.push(thread::spawn(move || loop {
            if close.load(Ordering::Relaxed) {
                return;
            }

            let mut send_buf = [0u8; MAX_PACKET];
            match peer.update_timers(&mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    send_packet(packet, endpoint_sock.clone(), endpoint_addr).unwrap();
                }
                _ => {}
            }

            thread::sleep(Duration::from_millis(200));
        }));
    }

    info!(
        "Tunnelling [{}]->[{}] (via [{}] as peer {})",
        &config.source_addr, &config.dest_addr, &config.endpoint_addr, &config.source_peer_ip
    );

    for handle in handles {
        handle.join().expect("Failed to join thread")
    }

    Ok(())
}

// wraps a UDP packet with an IP layer packet with the wanted source & destination addresses
fn wrap_data_packet(
    proto: Protocol,
    data: &[u8],
    source: SocketAddr,
    destination: SocketAddr,
) -> anyhow::Result<Vec<u8>> {
    match source {
        SocketAddr::V4(source) => {
            let mut builder = packet::ip::v4::Builder::default();

            builder = builder
                .source(*source.ip())
                .with_context(|| "Failed to set packet source")?;
            builder = builder
                .payload(data)
                .with_context(|| "Failed to set packet payload")?;
            builder = builder
                .protocol(proto)
                .with_context(|| "Failed to set packet protocol")?;
            builder = builder
                .dscp(0)
                .with_context(|| "Failed to set packet dcsp")?;
            builder = builder
                .id(12345)
                .with_context(|| "Failed to set packet ID")?;
            builder = builder
                .ttl(16)
                .with_context(|| "Failed to set packet TTL")?;

            match destination {
                SocketAddr::V4(destination) => {
                    builder = builder
                        .destination(*destination.ip())
                        .with_context(|| "Failed to set packet destination")?;
                }
                SocketAddr::V6(_) => {
                    return Err(anyhow::anyhow!(
                        "cannot use ipv6 destination with ipv4 source"
                    ));
                }
            }

            builder
                .build()
                .with_context(|| "Failed to build ipv4 packet")
        }
        SocketAddr::V6(_) => {
            todo!("ipv6 support")
        }
    }
}

fn send_packet(
    packet: &[u8],
    endpoint_socket: Arc<UdpSocket>,
    endpoint_addr: SocketAddr,
) -> anyhow::Result<usize> {
    // todo: replace addr with peer_addr
    let size = endpoint_socket
        .send_to(packet, endpoint_addr)
        .with_context(|| "Failed to send packet")?;
    Ok(size)
}
