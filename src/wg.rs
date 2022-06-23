use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::Bus;
use anyhow::Context;
use boringtun::noise::{Tunn, TunnResult};
use log::Level;
use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet};
use tokio::net::UdpSocket;

use crate::config::{Config, PortProtocol};
use crate::events::Event;

/// The capacity of the channel for received IP packets.
pub const DISPATCH_CAPACITY: usize = 1_000;
const MAX_PACKET: usize = 65536;

/// A WireGuard tunnel. Encapsulates and decapsulates IP packets
/// to be sent to and received from a remote UDP endpoint.
/// This tunnel supports at most 1 peer IP at a time, but supports simultaneous ports.
pub struct WireGuardTunnel {
    pub(crate) source_peer_ip: IpAddr,
    /// `boringtun` peer/tunnel implementation, used for crypto & WG protocol.
    peer: Box<Tunn>,
    /// The UDP socket for the public WireGuard endpoint to connect to.
    udp: UdpSocket,
    /// The address of the public WireGuard endpoint (UDP).
    pub(crate) endpoint: SocketAddr,
    /// Event bus
    bus: Bus,
}

impl WireGuardTunnel {
    /// Initialize a new WireGuard tunnel.
    pub async fn new(config: &Config, bus: Bus) -> anyhow::Result<Self> {
        let source_peer_ip = config.source_peer_ip;
        let peer = Self::create_tunnel(config)?;
        let endpoint = config.endpoint_addr;
        let udp = if let Some(host) = config.host_addr {
            UdpSocket::bind(host).await
        } else {
            UdpSocket::bind(match endpoint {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            })
            .await
        }
        .with_context(|| "Failed to create UDP socket for WireGuard connection")?;

        Ok(Self {
            source_peer_ip,
            peer,
            udp,
            endpoint,
            bus,
        })
    }

    /// Encapsulates and sends an IP packet through to the WireGuard endpoint.
    pub async fn send_ip_packet(&self, packet: &[u8]) -> anyhow::Result<()> {
        trace_ip_packet("Sending IP packet", packet);
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

    pub async fn produce_task(&self) -> ! {
        trace!("Starting WireGuard production task");
        let mut endpoint = self.bus.new_endpoint();

        loop {
            if let Event::OutboundInternetPacket(data) = endpoint.recv().await {
                match self.send_ip_packet(&data).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("{:?}", e);
                    }
                }
            }
        }
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
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                other => {
                    warn!("Unexpected WireGuard routine task state: {:?}", other);
                }
            }
        }
    }

    /// WireGuard consumption task. Receives encrypted packets from the WireGuard endpoint,
    /// decapsulates them, and dispatches newly received IP packets.
    pub async fn consume_task(&self) -> ! {
        trace!("Starting WireGuard consumption task");
        let endpoint = self.bus.new_endpoint();

        loop {
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut send_buf = [0u8; MAX_PACKET];

            let size = match self.udp.recv(&mut recv_buf).await {
                Ok(size) => size,
                Err(e) => {
                    error!("Failed to read from WireGuard endpoint: {:?}", e);
                    // Sleep a little bit and try again
                    tokio::time::sleep(Duration::from_millis(1)).await;
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
                    trace_ip_packet("Received IP packet", packet);

                    if let Some(proto) = self.route_protocol(packet) {
                        endpoint.send(Event::InboundInternetPacket(proto, packet.into()));
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

    /// Determine the inner protocol of the incoming IP packet (TCP/UDP).
    fn route_protocol(&self, packet: &[u8]) -> Option<PortProtocol> {
        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => Ipv4Packet::new_checked(&packet)
                .ok()
                // Only care if the packet is destined for this tunnel
                .filter(|packet| Ipv4Addr::from(packet.dst_addr()) == self.source_peer_ip)
                .and_then(|packet| match packet.protocol() {
                    IpProtocol::Tcp => Some(PortProtocol::Tcp),
                    IpProtocol::Udp => Some(PortProtocol::Udp),
                    // Unrecognized protocol, so we cannot determine where to route
                    _ => None,
                }),
            Ok(IpVersion::Ipv6) => Ipv6Packet::new_checked(&packet)
                .ok()
                // Only care if the packet is destined for this tunnel
                .filter(|packet| Ipv6Addr::from(packet.dst_addr()) == self.source_peer_ip)
                .and_then(|packet| match packet.next_header() {
                    IpProtocol::Tcp => Some(PortProtocol::Tcp),
                    IpProtocol::Udp => Some(PortProtocol::Udp),
                    // Unrecognized protocol, so we cannot determine where to route
                    _ => None,
                }),
            _ => None,
        }
    }
}

fn trace_ip_packet(message: &str, packet: &[u8]) {
    if log_enabled!(Level::Trace) {
        use smoltcp::wire::*;

        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv4Packet<&mut [u8]>>::new("", &packet)
            ),
            Ok(IpVersion::Ipv6) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv6Packet<&mut [u8]>>::new("", &packet)
            ),
            _ => {}
        }
    }
}
