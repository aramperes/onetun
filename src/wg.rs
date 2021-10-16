use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use boringtun::noise::{Tunn, TunnResult};
use futures::lock::Mutex;
use log::Level;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, IpProtocol, IpVersion, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl,
    TcpPacket, TcpRepr, TcpSeqNumber,
};
use tokio::net::UdpSocket;
use tokio::sync::broadcast::error::RecvError;

use crate::config::Config;
use crate::port_pool::PortPool;
use crate::MAX_PACKET;

/// The capacity of the broadcast channel for received IP packets.
const BROADCAST_CAPACITY: usize = 1_000;

/// A WireGuard tunnel. Encapsulates and decapsulates IP packets
/// to be sent to and received from a remote UDP endpoint.
/// This tunnel supports at most 1 peer IP at a time, but supports simultaneous ports.
pub struct WireGuardTunnel {
    source_peer_ip: IpAddr,
    /// `boringtun` peer/tunnel implementation, used for crypto & WG protocol.
    peer: Box<Tunn>,
    /// The UDP socket for the public WireGuard endpoint to connect to.
    udp: UdpSocket,
    /// The address of the public WireGuard endpoint (UDP).
    endpoint: SocketAddr,
    /// Broadcast sender for received IP packets.
    ip_broadcast_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    /// Sink so that the broadcaster doesn't close. A repeating task should drain this as much as possible.
    ip_broadcast_rx_sink: Mutex<tokio::sync::broadcast::Receiver<Vec<u8>>>,
    /// Port pool.
    port_pool: Arc<PortPool>,
}

impl WireGuardTunnel {
    /// Initialize a new WireGuard tunnel.
    pub async fn new(config: &Config, port_pool: Arc<PortPool>) -> anyhow::Result<Self> {
        let source_peer_ip = config.source_peer_ip;
        let peer = Self::create_tunnel(config)?;
        let udp = UdpSocket::bind("0.0.0.0:0")
            .await
            .with_context(|| "Failed to create UDP socket for WireGuard connection")?;
        let endpoint = config.endpoint_addr;
        let (ip_broadcast_tx, ip_broadcast_rx_sink) =
            tokio::sync::broadcast::channel(BROADCAST_CAPACITY);

        Ok(Self {
            source_peer_ip,
            peer,
            udp,
            endpoint,
            ip_broadcast_tx,
            ip_broadcast_rx_sink: Mutex::new(ip_broadcast_rx_sink),
            port_pool,
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
                    tokio::time::sleep(Duration::from_millis(1)).await;
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

                    match self.route_ip_packet(packet) {
                        RouteResult::Broadcast => {
                            // Broadcast IP packet
                            if self.ip_broadcast_tx.receiver_count() > 1 {
                                match self.ip_broadcast_tx.send(packet.to_vec()) {
                                    Ok(n) => {
                                        trace!(
                                            "Broadcasted received IP packet to {} virtual interfaces",
                                            n - 1
                                        );
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to broadcast received IP packet to recipients: {}",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                        RouteResult::TcpReset(packet) => {
                            trace!("Resetting dead TCP connection after packet from WireGuard endpoint");
                            self.send_ip_packet(&packet)
                                .await
                                .unwrap_or_else(|e| error!("Failed to sent TCP reset: {:?}", e));
                        }
                        RouteResult::Drop => {
                            trace!("Dropped incoming IP packet from WireGuard endpoint");
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// A repeating task that drains the default IP broadcast channel receiver.
    /// It is necessary to keep this receiver alive to prevent the overall channel from closing,
    /// so draining its backlog regularly is required to avoid memory leaks.
    pub async fn broadcast_drain_task(&self) {
        trace!("Starting IP broadcast sink drain task");

        loop {
            let mut sink = self.ip_broadcast_rx_sink.lock().await;
            match sink.recv().await {
                Ok(_) => {
                    trace!("Drained a packet from IP broadcast sink");
                }
                Err(e) => match e {
                    RecvError::Closed => {
                        trace!("IP broadcast sink finished draining: channel closed");
                        break;
                    }
                    RecvError::Lagged(_) => {
                        warn!("IP broadcast sink is falling behind");
                    }
                },
            }
        }

        trace!("Stopped IP broadcast sink drain");
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

    /// Makes a decision on the handling of an incoming IP packet.
    fn route_ip_packet(&self, packet: &[u8]) -> RouteResult {
        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => Ipv4Packet::new_checked(&packet)
                .ok()
                // Only care if the packet is destined for this tunnel
                .filter(|packet| Ipv4Addr::from(packet.dst_addr()) == self.source_peer_ip)
                .map(|packet| match packet.protocol() {
                    IpProtocol::Tcp => Some(self.route_tcp_segment(
                        IpVersion::Ipv4,
                        packet.src_addr().into(),
                        packet.dst_addr().into(),
                        packet.payload(),
                    )),
                    // Unrecognized protocol, so we'll allow it.
                    _ => Some(RouteResult::Broadcast),
                })
                .flatten()
                .unwrap_or(RouteResult::Drop),
            Ok(IpVersion::Ipv6) => Ipv6Packet::new_checked(&packet)
                .ok()
                // Only care if the packet is destined for this tunnel
                .filter(|packet| Ipv6Addr::from(packet.dst_addr()) == self.source_peer_ip)
                .map(|packet| match packet.next_header() {
                    IpProtocol::Tcp => Some(self.route_tcp_segment(
                        IpVersion::Ipv6,
                        packet.src_addr().into(),
                        packet.dst_addr().into(),
                        packet.payload(),
                    )),
                    // Unrecognized protocol, so we'll allow it.
                    _ => Some(RouteResult::Broadcast),
                })
                .flatten()
                .unwrap_or(RouteResult::Drop),
            _ => RouteResult::Drop,
        }
    }

    /// Makes a decision on the handling of an incoming TCP segment.
    fn route_tcp_segment(
        &self,
        ip_version: IpVersion,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        segment: &[u8],
    ) -> RouteResult {
        TcpPacket::new_checked(segment)
            .ok()
            .map(|tcp| {
                if self.port_pool.is_in_use(tcp.dst_port()) {
                    RouteResult::Broadcast
                } else if tcp.rst() {
                    RouteResult::Drop
                } else {
                    // Port is not in use, but it's a TCP packet so we'll craft a RST.
                    RouteResult::TcpReset(craft_tcp_rst_reply(
                        ip_version,
                        src_addr,
                        tcp.src_port(),
                        dst_addr,
                        tcp.dst_port(),
                        tcp.ack_number(),
                    ))
                }
            })
            .unwrap_or(RouteResult::Drop)
    }
}

/// Craft an IP packet containing a TCP RST segment, given an IP version,
/// source address (the one to reply to), destination address (the one the reply comes from),
/// and the ACK number received in the initiating TCP segment.
fn craft_tcp_rst_reply(
    ip_version: IpVersion,
    source_addr: IpAddress,
    source_port: u16,
    dest_addr: IpAddress,
    dest_port: u16,
    ack_number: TcpSeqNumber,
) -> Vec<u8> {
    let tcp_repr = TcpRepr {
        src_port: dest_port,
        dst_port: source_port,
        control: TcpControl::Rst,
        seq_number: ack_number,
        ack_number: None,
        window_len: 0,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        payload: &[],
    };

    let mut tcp_buffer = vec![0u8; 20];
    let mut tcp_packet = &mut TcpPacket::new_unchecked(&mut tcp_buffer);
    tcp_repr.emit(
        &mut tcp_packet,
        &dest_addr,
        &source_addr,
        &ChecksumCapabilities::default(),
    );

    let mut ip_buffer = vec![0u8; MAX_PACKET];

    let (header_len, total_len) = match ip_version {
        IpVersion::Ipv4 => {
            let dest_addr = match dest_addr {
                IpAddress::Ipv4(dest_addr) => dest_addr,
                _ => panic!(),
            };
            let source_addr = match source_addr {
                IpAddress::Ipv4(source_addr) => source_addr,
                _ => panic!(),
            };

            let mut ip_packet = &mut Ipv4Packet::new_unchecked(&mut ip_buffer);
            let ip_repr = Ipv4Repr {
                src_addr: dest_addr,
                dst_addr: source_addr,
                protocol: IpProtocol::Tcp,
                payload_len: tcp_buffer.len(),
                hop_limit: 64,
            };
            ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
            (
                ip_packet.header_len() as usize,
                ip_packet.total_len() as usize,
            )
        }
        IpVersion::Ipv6 => {
            let dest_addr = match dest_addr {
                IpAddress::Ipv6(dest_addr) => dest_addr,
                _ => panic!(),
            };
            let source_addr = match source_addr {
                IpAddress::Ipv6(source_addr) => source_addr,
                _ => panic!(),
            };
            let mut ip_packet = &mut Ipv6Packet::new_unchecked(&mut ip_buffer);
            let ip_repr = Ipv6Repr {
                src_addr: dest_addr,
                dst_addr: source_addr,
                next_header: IpProtocol::Tcp,
                payload_len: tcp_buffer.len(),
                hop_limit: 64,
            };
            ip_repr.emit(&mut ip_packet);
            (ip_packet.header_len(), ip_packet.total_len())
        }
        _ => panic!(),
    };

    ip_buffer[header_len..total_len].copy_from_slice(&tcp_buffer);
    let packet: &[u8] = &ip_buffer[..total_len];
    packet.to_vec()
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

enum RouteResult {
    /// The packet can be broadcasted to the virtual interfaces
    Broadcast,
    /// The packet is not routable so it may be reset.
    TcpReset(Vec<u8>),
    /// The packet can be safely ignored.
    Drop,
}
