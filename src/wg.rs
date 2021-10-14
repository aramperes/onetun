use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use boringtun::noise::{Tunn, TunnResult};
use tokio::net::UdpSocket;

use crate::config::Config;
use crate::MAX_PACKET;

/// The capacity of the broadcast channel for received IP packets.
const BROADCAST_CAPACITY: usize = 1_000_000;

pub struct WireGuardTunnel {
    /// `boringtun` peer/tunnel implementation, used for crypto & WG protocol.
    peer: Box<Tunn>,
    /// The UDP socket for the public WireGuard endpoint to connect to.
    udp: UdpSocket,
    /// The address of the public WireGuard endpoint (UDP).
    endpoint: SocketAddr,
    /// Broadcast sender for received IP packets.
    ip_broadcast_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
}

impl WireGuardTunnel {
    /// Initialize a new WireGuard tunnel.
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        let peer = Self::create_tunnel(&config)?;
        let udp = UdpSocket::bind("0.0.0.0:0")
            .await
            .with_context(|| "Failed to create UDP socket for WireGuard connection")?;
        let endpoint = config.endpoint_addr;
        let (ip_broadcast_tx, _) = tokio::sync::broadcast::channel(BROADCAST_CAPACITY);

        Ok(Self {
            peer,
            udp,
            endpoint,
            ip_broadcast_tx,
        })
    }

    /// Encapsulates and sends an IP packet through to the WireGuard endpoint.
    pub async fn send_ip_packet(&self, packet: &[u8]) -> anyhow::Result<()> {
        let mut send_buf = [0u8; MAX_PACKET];
        match self.peer.encapsulate(packet, &mut send_buf) {
            TunnResult::WriteToNetwork(packet) => {
                self.udp
                    .send_to(packet, self.endpoint)
                    .await
                    .with_context(|| "Failed to send encrypted IP packet to WireGuard endpoint.")?;
                debug!(
                    "Sent {} bytes to WireGuard endpoint (encrypted IP packet)",
                    packet.len()
                );
            }
            TunnResult::Err(e) => {
                error!("Failed to encapsulate IP packet: {:?}", e);
            }
            TunnResult::Done => {
                // Ignored
            }
            other => {
                error!(
                    "Unexpected WireGuard state during encapsulation: {:?}",
                    other
                );
            }
        };
        Ok(())
    }

    /// Create a new receiver for broadcasted IP packets, received from the WireGuard endpoint.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Vec<u8>> {
        self.ip_broadcast_tx.subscribe()
    }

    /// WireGuard Routine task. Handles Handshake, keep-alive, etc.
    pub async fn routine_task(&self) -> ! {
        trace!("Starting WireGuard routine task");

        loop {
            let mut send_buf = [0u8; MAX_PACKET];
            match self.peer.update_timers(&mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    debug!(
                        "Sending routine packet of {} bytes to WireGuard endpoint",
                        packet.len()
                    );
                    match self.udp.send_to(packet, self.endpoint).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!(
                                "Failed to send routine packet to WireGuard endpoint: {:?}",
                                e
                            );
                        }
                    };
                }
                TunnResult::Err(e) => {
                    error!(
                        "Failed to prepare routine packet for WireGuard endpoint: {:?}",
                        e
                    );
                }
                TunnResult::Done => {
                    // Sleep for a bit
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                other => {
                    warn!("Unexpected WireGuard routine task state: {:?}", other);
                }
            }
        }
    }

    /// WireGuard consumption task. Receives encrypted packets from the WireGuard endpoint,
    /// decapsulates them, and broadcasts newly received IP packets.
    pub async fn consume_task(&self) -> ! {
        trace!("Starting WireGuard consumption task");

        loop {
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut send_buf = [0u8; MAX_PACKET];

            let size = match self.udp.recv(&mut recv_buf).await {
                Ok(size) => size,
                Err(e) => {
                    error!("Failed to read from WireGuard endpoint: {:?}", e);
                    // Sleep a little bit and try again
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };

            let data = &recv_buf[..size];
            match self.peer.decapsulate(None, data, &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    match self.udp.send_to(packet, self.endpoint).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}", e);
                            continue;
                        }
                    };
                    loop {
                        let mut send_buf = [0u8; MAX_PACKET];
                        match self.peer.decapsulate(None, &[], &mut send_buf) {
                            TunnResult::WriteToNetwork(packet) => {
                                match self.udp.send_to(packet, self.endpoint).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!("Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}", e);
                                        break;
                                    }
                                };
                            }
                            _ => {
                                break;
                            }
                        }
                    }
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    debug!(
                        "WireGuard endpoint sent IP packet of {} bytes",
                        packet.len()
                    );

                    // For debugging purposes: parse packet
                    trace_ip_packet(packet);

                    // Broadcast IP packet
                    match self.ip_broadcast_tx.send(packet.to_vec()) {
                        Ok(n) => {
                            trace!("Broadcasted received IP packet to {} recipients", n);
                        }
                        Err(e) => {
                            error!(
                                "Failed to broadcast received IP packet to recipients: {:?}",
                                e
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn create_tunnel(config: &Config) -> anyhow::Result<Box<Tunn>> {
        Tunn::new(
            config.private_key.clone(),
            config.endpoint_public_key.clone(),
            None,
            config.keepalive_seconds,
            0,
            None,
        )
        .map_err(|s| anyhow::anyhow!("{}", s))
        .with_context(|| "Failed to initialize boringtun Tunn")
    }
}

fn trace_ip_packet(packet: &[u8]) {
    use smoltcp::wire::*;

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
