use std::sync::Arc;

use anyhow::Context;
use tokio::net::UdpSocket;

use crate::config::PortForwardConfig;
use crate::wg::WireGuardTunnel;

const MAX_PACKET: usize = 65536;

/// How long to keep the UDP peer address assigned to its virtual specified port, in seconds.
/// TODO: Make this configurable by the CLI
const UDP_TIMEOUT_SECONDS: u64 = 60;

/// To prevent port-flooding, we set a limit on the amount of open ports per IP address.
/// TODO: Make this configurable by the CLI
const PORTS_PER_IP: usize = 100;

pub async fn udp_proxy_server(
    port_forward: PortForwardConfig,
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
        debug!("Received datagram of {} bytes from {}", size, peer_addr);

        // Assign a 'virtual port': this is a unique port number used to route IP packets
        // received from the WireGuard tunnel. It is the port number that the virtual client will
        // listen on.
        // Since UDP is connection-less, the port is assigned to the source SocketAddr for up to `UDP_TIMEOUT_SECONDS`;
        // every datagram resets the timer for that SocketAddr. Each IP address also has a limit of active connections,
        // discarding the LRU ports.
        // TODO: UDP Port Pool
    }
}
