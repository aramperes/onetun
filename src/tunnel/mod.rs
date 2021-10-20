use std::net::IpAddr;
use std::sync::Arc;

use crate::config::{PortForwardConfig, PortProtocol};
use crate::tunnel::tcp::TcpPortPool;
use crate::wg::WireGuardTunnel;

pub mod tcp;
#[allow(unused)]
pub mod udp;

pub async fn port_forward(
    port_forward: PortForwardConfig,
    source_peer_ip: IpAddr,
    tcp_port_pool: TcpPortPool,
    wg: Arc<WireGuardTunnel>,
) -> anyhow::Result<()> {
    info!(
        "Tunneling {} [{}]->[{}] (via [{}] as peer {})",
        port_forward.protocol,
        port_forward.source,
        port_forward.destination,
        &wg.endpoint,
        source_peer_ip
    );

    match port_forward.protocol {
        PortProtocol::Tcp => tcp::tcp_proxy_server(port_forward, tcp_port_pool, wg).await,
        PortProtocol::Udp => udp::udp_proxy_server(port_forward, /* udp_port_pool, */ wg).await,
    }
}
