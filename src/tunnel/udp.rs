use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use rand::seq::SliceRandom;
use rand::thread_rng;
use tokio::net::UdpSocket;

use crate::config::{PortForwardConfig, PortProtocol};
use crate::virtual_iface::udp::UdpVirtualInterface;
use crate::virtual_iface::{VirtualInterfacePoll, VirtualPort};
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
    // Abort signal
    let abort = Arc::new(AtomicBool::new(false));

    // data_to_real_client_(tx/rx): This task reads the data from this mpsc channel to send back
    // to the real client.
    let (data_to_real_client_tx, mut data_to_real_client_rx) =
        tokio::sync::mpsc::channel::<(VirtualPort, Vec<u8>)>(1_000);

    // data_to_real_server_(tx/rx): This task sends the data received from the real client to the
    // virtual interface (virtual server socket).
    let (data_to_virtual_server_tx, data_to_virtual_server_rx) =
        tokio::sync::mpsc::channel::<(VirtualPort, Vec<u8>)>(1_000);

    {
        // Spawn virtual interface
        // Note: contrary to TCP, there is only one UDP virtual interface
        let virtual_interface = UdpVirtualInterface::new(
            port_forward,
            wg,
            data_to_real_client_tx,
            data_to_virtual_server_rx,
        );
        let abort = abort.clone();
        tokio::spawn(async move {
            virtual_interface.poll_loop().await.unwrap_or_else(|e| {
                error!("Virtual interface poll loop failed unexpectedly: {}", e);
                abort.store(true, Ordering::Relaxed);
            });
        });
    }

    let socket = UdpSocket::bind(port_forward.source)
        .await
        .with_context(|| "Failed to bind on UDP proxy address")?;

    let mut buffer = [0u8; MAX_PACKET];
    loop {
        if abort.load(Ordering::Relaxed) {
            break;
        }
        tokio::select! {
            to_send_result = next_udp_datagram(&socket, &mut buffer, port_pool.clone()) => {
                match to_send_result {
                    Ok(Some((port, data))) => {
                        data_to_virtual_server_tx.send((port, data)).await.unwrap_or_else(|e| {
                            error!(
                                "Failed to dispatch data to UDP virtual interface: {:?}",
                                e
                            );
                        });
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
            data_recv_result = data_to_real_client_rx.recv() => {
                if let Some((port, data)) = data_recv_result {
                    if let Some(peer_addr) = port_pool.get_peer_addr(port.0).await {
                        if let Err(e) = socket.send_to(&data, peer_addr).await {
                            error!(
                                "[{}] Failed to send UDP datagram to real client ({}): {:?}",
                                port,
                                peer_addr,
                                e,
                            );
                        }
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
) -> anyhow::Result<Option<(VirtualPort, Vec<u8>)>> {
    let (size, peer_addr) = socket
        .recv_from(buffer)
        .await
        .with_context(|| "Failed to accept incoming UDP datagram")?;

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
    let port = VirtualPort(port, PortProtocol::Udp);

    debug!(
        "[{}] Received datagram of {} bytes from {}",
        port, size, peer_addr
    );

    let data = buffer[..size].to_vec();
    Ok(Some((port, data)))
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
    pub async fn next(&self, peer_addr: SocketAddr) -> anyhow::Result<u16> {
        {
            let inner = self.inner.read().await;
            if let Some(port) = inner.port_by_peer_addr.get(&peer_addr) {
                return Ok(*port);
            }
        }

        // TODO: When the port pool is exhausted, it should re-queue the least recently used port.
        // TODO: Limit number of ports in use by peer IP

        let mut inner = self.inner.write().await;
        let port = inner
            .queue
            .pop_front()
            .with_context(|| "UDP virtual port pool is exhausted")?;
        inner.port_by_peer_addr.insert(peer_addr, port);
        inner.peer_addr_by_port.insert(port, peer_addr);
        Ok(port)
    }

    pub async fn get_peer_addr(&self, port: u16) -> Option<SocketAddr> {
        let inner = self.inner.read().await;
        inner.peer_addr_by_port.get(&port).copied()
    }
}

/// Non thread-safe inner logic for UDP port pool.
#[derive(Debug, Default)]
struct UdpPortPoolInner {
    /// Remaining ports in the pool.
    queue: VecDeque<u16>,
    /// The port assigned by peer IP/port.
    port_by_peer_addr: HashMap<SocketAddr, u16>,
    /// The socket address assigned to a peer IP/port.
    peer_addr_by_port: HashMap<u16, SocketAddr>,
}
