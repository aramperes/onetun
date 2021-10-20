use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use rand::seq::SliceRandom;
use rand::thread_rng;
use tokio::net::UdpSocket;

use crate::config::{PortForwardConfig, PortProtocol};
use crate::virtual_iface::VirtualPort;
use crate::wg::WireGuardTunnel;

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

pub async fn udp_proxy_server(
    port_forward: PortForwardConfig,
    port_pool: UdpPortPool,
    wg: Arc<WireGuardTunnel>,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(port_forward.source)
        .await
        .with_context(|| "Failed to bind on UDP proxy address")?;

    let mut buffer = [0u8; MAX_PACKET];
    loop {
        let (size, peer_addr) = socket
            .recv_from(&mut buffer)
            .await
            .with_context(|| "Failed to accept incoming UDP datagram")?;

        let _wg = wg.clone();
        let _data = &buffer[..size].to_vec();

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
                continue;
            }
        };

        let port = VirtualPort(port, PortProtocol::Udp);
        debug!(
            "[{}] Received datagram of {} bytes from {}",
            port, size, peer_addr
        );
    }
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

    /// Requests a free port from the pool. An error is returned if none is available (exhaused max capacity).
    pub async fn next(&self, peer_addr: SocketAddr) -> anyhow::Result<u16> {
        {
            let inner = self.inner.read().await;
            if let Some(port) = inner.port_by_peer_addr.get(&peer_addr) {
                return Ok(*port);
            }
        }

        let mut inner = self.inner.write().await;
        let port = inner
            .queue
            .pop_front()
            .with_context(|| "UDP virtual port pool is exhausted")?;
        inner.port_by_peer_addr.insert(peer_addr, port);
        Ok(port)
    }
}

/// Non thread-safe inner logic for UDP port pool.
#[derive(Debug, Default)]
struct UdpPortPoolInner {
    /// Remaining ports in the pool.
    queue: VecDeque<u16>,
    /// The port assigned by peer IP/port.
    port_by_peer_addr: HashMap<SocketAddr, u16>,
}
