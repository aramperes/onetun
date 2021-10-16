use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::Context;
use boringtun::noise::{Tunn, TunnResult};
use log::Level;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, IpProtocol, IpVersion, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl,
    TcpPacket, TcpRepr, TcpSeqNumber,
};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::MAX_PACKET;

/// The capacity of the channel for received IP packets.
const DISPATCH_CAPACITY: usize = 1_000;

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
    /// Maps virtual ports to the corresponding IP packet dispatcher.
    virtual_port_ip_tx: lockfree::map::Map<u16, tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// IP packet dispatcher for unroutable packets. `None` if not initialized.
    sink_ip_tx: RwLock<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>,
}

impl WireGuardTunnel {
    /// Initialize a new WireGuard tunnel.
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        let source_peer_ip = config.source_peer_ip;
        let peer = Self::create_tunnel(config)?;
        let udp = UdpSocket::bind("0.0.0.0:0")
            .await
            .with_context(|| "Failed to create UDP socket for WireGuard connection")?;
        let endpoint = config.endpoint_addr;
        let virtual_port_ip_tx = lockfree::map::Map::new();

        Ok(Self {
            source_peer_ip,
            peer,
            udp,
            endpoint,
            virtual_port_ip_tx,
            sink_ip_tx: RwLock::new(None),
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

    /// Register a virtual interface (using its assigned virtual port) with the given IP packet `Sender`.
    pub fn register_virtual_interface(
        &self,
        virtual_port: u16,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<Vec<u8>>> {
        let existing = self.virtual_port_ip_tx.get(&virtual_port);
        if existing.is_some() {
            Err(anyhow::anyhow!("Cannot register virtual interface with virtual port {} because it is already registered", virtual_port))
        } else {
            let (sender, receiver) = tokio::sync::mpsc::channel(DISPATCH_CAPACITY);
            self.virtual_port_ip_tx.insert(virtual_port, sender);
            Ok(receiver)
        }
    }

    /// Register a virtual interface (using its assigned virtual port) with the given IP packet `Sender`.
    pub async fn register_sink_interface(
        &self,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<Vec<u8>>> {
        let (sender, receiver) = tokio::sync::mpsc::channel(DISPATCH_CAPACITY);

        let mut sink_ip_tx = self.sink_ip_tx.write().await;
        *sink_ip_tx = Some(sender);

        Ok(receiver)
    }

    /// Releases the virtual interface from IP dispatch.
    pub fn release_virtual_interface(&self, virtual_port: u16) {
        self.virtual_port_ip_tx.remove(&virtual_port);
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
                        RouteResult::Dispatch(port) => {
                            let sender = self.virtual_port_ip_tx.get(&port);
                            if let Some(sender_guard) = sender {
                                let sender = sender_guard.val();
                                match sender.send(packet.to_vec()).await {
                                    Ok(_) => {
                                        trace!(
                                            "Dispatched received IP packet to virtual port {}",
                                            port
                                        );
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to dispatch received IP packet to virtual port {}: {}",
                                            port, e
                                        );
                                    }
                                }
                            } else {
                                warn!("[{}] Race condition: failed to get virtual port sender after it was dispatched", port);
                            }
                        }
                        RouteResult::TcpReset => {
                            trace!("Resetting dead TCP connection after packet from WireGuard endpoint");
                            self.route_ip_sink(packet).await.unwrap_or_else(|e| {
                                error!("Failed to send TCP reset to sink: {:?}", e)
                            });
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
                    IpProtocol::Tcp => Some(self.route_tcp_segment(packet.payload())),
                    // Unrecognized protocol, so we cannot determine where to route
                    _ => Some(RouteResult::Drop),
                })
                .flatten()
                .unwrap_or(RouteResult::Drop),
            Ok(IpVersion::Ipv6) => Ipv6Packet::new_checked(&packet)
                .ok()
                // Only care if the packet is destined for this tunnel
                .filter(|packet| Ipv6Addr::from(packet.dst_addr()) == self.source_peer_ip)
                .map(|packet| match packet.next_header() {
                    IpProtocol::Tcp => Some(self.route_tcp_segment(packet.payload())),
                    // Unrecognized protocol, so we cannot determine where to route
                    _ => Some(RouteResult::Drop),
                })
                .flatten()
                .unwrap_or(RouteResult::Drop),
            _ => RouteResult::Drop,
        }
    }

    /// Makes a decision on the handling of an incoming TCP segment.
    fn route_tcp_segment(&self, segment: &[u8]) -> RouteResult {
        TcpPacket::new_checked(segment)
            .ok()
            .map(|tcp| {
                if self.virtual_port_ip_tx.get(&tcp.dst_port()).is_some() {
                    RouteResult::Dispatch(tcp.dst_port())
                } else if tcp.rst() {
                    RouteResult::Drop
                } else {
                    RouteResult::TcpReset
                }
            })
            .unwrap_or(RouteResult::Drop)
    }

    /// Route a packet to the IP sink interface.
    async fn route_ip_sink(&self, packet: &[u8]) -> anyhow::Result<()> {
        let ip_sink_tx = self.sink_ip_tx.read().await;

        if let Some(ip_sink_tx) = &*ip_sink_tx {
            ip_sink_tx
                .send(packet.to_vec())
                .await
                .with_context(|| "Failed to dispatch IP packet to sink interface")
        } else {
            warn!(
                "Could not dispatch unroutable IP packet to sink because interface is not active."
            );
            Ok(())
        }
    }
}

/// Craft an IP packet containing a TCP RST segment, given an IP version,
/// source address (the one to reply to), destination address (the one the reply comes from),
/// and the ACK number received in the initiating TCP segment.
fn _craft_tcp_rst_reply(
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
    /// Dispatch the packet to the virtual port.
    Dispatch(u16),
    /// The packet is not routable so it may be reset.
    TcpReset,
    /// The packet can be safely ignored.
    Drop,
}
