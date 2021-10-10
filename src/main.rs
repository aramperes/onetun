#[macro_use]
extern crate log;

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::device::peer::Peer;
use boringtun::noise::{Tunn, TunnResult};
use clap::{App, Arg};

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

    let peer_ip = config.source_peer_ip;

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

            debug!("Got packet from endpoint sock: {} bytes", n);

            match peer.decapsulate(None, &recv_buf[..n], &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    send_mocked_packet(packet, endpoint_sock.clone(), endpoint_addr, peer_ip)
                        .unwrap();
                    loop {
                        let mut send_buf = [0u8; MAX_PACKET];
                        match peer.decapsulate(None, &[], &mut send_buf) {
                            TunnResult::WriteToNetwork(packet) => {
                                send_mocked_packet(
                                    packet,
                                    endpoint_sock.clone(),
                                    endpoint_addr,
                                    peer_ip,
                                )
                                .unwrap();
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

            debug!("Got packet from source sock: {} bytes", n);

            match peer.encapsulate(&recv_buf[..n], &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    send_mocked_packet(packet, endpoint_sock.clone(), endpoint_addr, peer_ip)
                        .unwrap();
                }
                _ => {}
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
                    send_mocked_packet(packet, endpoint_sock.clone(), endpoint_addr, peer_ip)
                        .unwrap();
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

fn send_mocked_packet(
    packet: &[u8],
    endpoint_socket: Arc<UdpSocket>,
    endpoint_addr: SocketAddr,
    peer_addr: IpAddr,
) -> anyhow::Result<usize> {
    // todo: replace addr with peer_addr
    endpoint_socket
        .send_to(packet, endpoint_addr)
        .with_context(|| "Failed to send mocked packet")
}
