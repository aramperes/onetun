use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use priority_queue::double_priority_queue::DoublePriorityQueue;
use rand::seq::SliceRandom;
use rand::thread_rng;
use tokio::net::UdpSocket;

use crate::config::{PortForwardConfig, PortProtocol};
use crate::events::{Bus, Event};
use crate::virtual_iface::VirtualPort;

const MAX_PACKET: usize = 65536;
const MIN_PORT: u16 = 1000;
const MAX_PORT: u16 = 60999;
const PORT_RANGE: Range<u16> = MIN_PORT..MAX_PORT;

/// How long to keep the UDP peer address assigned to its virtual specified port, in seconds.
/// TODO: Make this configurable by the CLI
const UDP_TIMEOUT_SECONDS: u64 = 60;

/// To prevent port-flooding, we set a limit on the amount of open ports per IP address.
/// TODO: Make this configurable by the CLI
const PORTS_PER_IP: usize = 100;

/// Starts the server that listens on UDP datagrams.
pub async fn udp_proxy_server(
    port_forward: PortForwardConfig,
    port_pool: UdpPortPool,
    bus: Bus,
) -> anyhow::Result<()> {
    let mut endpoint = bus.new_endpoint();
    let socket = UdpSocket::bind(port_forward.source)
        .await
        .context("Failed to bind on UDP proxy address")?;

    let mut buffer = [0u8; MAX_PACKET];
    loop {
        tokio::select! {
            to_send_result = next_udp_datagram(&socket, &mut buffer, port_pool.clone()) => {
                match to_send_result {
                    Ok(Some((port, data))) => {
                        endpoint.send(Event::LocalData(port_forward, port, data));
                    }
                    Ok(None) => {
                        continue;
                    }
                    Err(e) => {
                        error!(
                            "Failed to read from client UDP socket: {:?}",
                            e
                        );
                        break;
                    }
                }
            }
            event = endpoint.recv() => {
                if let Event::RemoteData(virtual_port, data) = event {
                    if let Some(peer) = port_pool.get_peer_addr(virtual_port).await {
                        // Have remote data to send to the local client
                        if let Err(e) = socket.writable().await {
                            error!("[{}] Failed to check if writable: {:?}", virtual_port, e);
                        }
                        let expected = data.len();
                        let mut sent = 0;
                        loop {
                            if sent >= expected {
                                break;
                            }
                            match socket.send_to(&data[sent..expected], peer).await {
                                Ok(written) => {
                                    debug!("[{}] Sent {} (expected {}) bytes to local client", virtual_port, written, expected);
                                    sent += written;
                                    if sent < expected {
                                        debug!("[{}] Will try to resend remaining {} bytes to local client", virtual_port, (expected - written));
                                    }
                                },
                                Err(e) => {
                                    error!("[{}] Failed to send {} bytes to local client: {:?}", virtual_port, expected, e);
                                    break;
                                }
                            }
                        }
                        port_pool.update_last_transmit(virtual_port).await;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn next_udp_datagram(
    socket: &UdpSocket,
    buffer: &mut [u8],
    port_pool: UdpPortPool,
) -> anyhow::Result<Option<(VirtualPort, Bytes)>> {
    let (size, peer_addr) = socket
        .recv_from(buffer)
        .await
        .context("Failed to accept incoming UDP datagram")?;

    // Assign a 'virtual port': this is a unique port number used to route IP packets
    // received from the WireGuard tunnel. It is the port number that the virtual client will
    // listen on.
    let port = match port_pool.next(peer_addr).await {
        Ok(port) => port,
        Err(e) => {
            error!(
                "Failed to assign virtual port number for UDP datagram from [{}]: {:?}",
                peer_addr, e
            );
            return Ok(None);
        }
    };

    debug!(
        "[{}] Received datagram of {} bytes from {}",
        port, size, peer_addr
    );

    port_pool.update_last_transmit(port).await;

    let data = buffer[..size].to_vec();
    Ok(Some((port, data.into())))
}

/// A pool of virtual ports available for TCP connections.
#[derive(Clone)]
pub struct UdpPortPool {
    inner: Arc<tokio::sync::RwLock<UdpPortPoolInner>>,
}

impl Default for UdpPortPool {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpPortPool {
    /// Initializes a new pool of virtual ports.
    pub fn new() -> Self {
        let mut inner = UdpPortPoolInner::default();
        let mut ports: Vec<u16> = PORT_RANGE.collect();
        ports.shuffle(&mut thread_rng());
        ports
            .into_iter()
            .for_each(|p| inner.queue.push_back(p) as ());
        Self {
            inner: Arc::new(tokio::sync::RwLock::new(inner)),
        }
    }

    /// Requests a free port from the pool. An error is returned if none is available (exhausted max capacity).
    pub async fn next(&self, peer_addr: SocketAddr) -> anyhow::Result<VirtualPort> {
        // A port found to be reused. This is outside of the block because the read lock cannot be upgraded to a write lock.
        let mut port_reuse: Option<u16> = None;

        {
            let inner = self.inner.read().await;
            if let Some(port) = inner.port_by_peer_addr.get(&peer_addr) {
                return Ok(VirtualPort::new(*port, PortProtocol::Udp));
            }

            // Count how many ports are being used by the peer IP
            let peer_ip = peer_addr.ip();
            let peer_port_count = inner
                .peer_port_usage
                .get(&peer_ip)
                .map(|v| v.len())
                .unwrap_or_default();

            if peer_port_count >= PORTS_PER_IP {
                // Return least recently used port in this IP's pool
                port_reuse = Some(
                    *(inner
                        .peer_port_usage
                        .get(&peer_ip)
                        .unwrap()
                        .peek_min()
                        .unwrap()
                        .0),
                );
                warn!(
                    "Peer [{}] is re-using active virtual port {} due to self-exhaustion.",
                    peer_addr,
                    port_reuse.unwrap()
                );
            }
        }

        let mut inner = self.inner.write().await;

        let port = port_reuse
            .or_else(|| inner.queue.pop_front())
            .or_else(|| {
                // If there is no port to reuse, and the port pool is exhausted, take the last recently used port overall,
                // as long as the last transmission exceeds the deadline
                let last: (&u16, &Instant) = inner.port_usage.peek_min().unwrap();
                if Instant::now().duration_since(*last.1).as_secs() > UDP_TIMEOUT_SECONDS {
                    warn!(
                        "Peer [{}] is re-using inactive virtual port {} due to global exhaustion.",
                        peer_addr, last.0
                    );
                    Some(*last.0)
                } else {
                    None
                }
            })
            .context("Virtual port pool is exhausted")?;

        inner.port_by_peer_addr.insert(peer_addr, port);
        inner.peer_addr_by_port.insert(port, peer_addr);
        Ok(VirtualPort::new(port, PortProtocol::Udp))
    }

    /// Notify that the given virtual port has received or transmitted a UDP datagram.
    pub async fn update_last_transmit(&self, port: VirtualPort) {
        let mut inner = self.inner.write().await;
        if let Some(peer) = inner.peer_addr_by_port.get(&port.num()).copied() {
            let pq: &mut DoublePriorityQueue<u16, Instant> = inner
                .peer_port_usage
                .entry(peer.ip())
                .or_insert_with(Default::default);
            pq.push(port.num(), Instant::now());
        }
        let pq: &mut DoublePriorityQueue<u16, Instant> = &mut inner.port_usage;
        pq.push(port.num(), Instant::now());
    }

    pub async fn get_peer_addr(&self, port: VirtualPort) -> Option<SocketAddr> {
        let inner = self.inner.read().await;
        inner.peer_addr_by_port.get(&port.num()).copied()
    }
}

/// Non thread-safe inner logic for UDP port pool.
#[derive(Debug, Default)]
struct UdpPortPoolInner {
    /// Remaining ports in the pool.
    queue: VecDeque<u16>,
    /// The port assigned by peer IP/port. This is used to lookup an existing virtual port
    /// for an incoming UDP datagram.
    port_by_peer_addr: HashMap<SocketAddr, u16>,
    /// The socket address assigned to a peer IP/port. This is used to send a UDP datagram to
    /// the real peer address, given the virtual port.
    peer_addr_by_port: HashMap<u16, SocketAddr>,
    /// Keeps an ordered map of the most recently used virtual ports by a peer (client) IP.
    peer_port_usage: HashMap<IpAddr, DoublePriorityQueue<u16, Instant>>,
    /// Keeps an ordered map of the most recently used virtual ports in general.
    port_usage: DoublePriorityQueue<u16, Instant>,
}
