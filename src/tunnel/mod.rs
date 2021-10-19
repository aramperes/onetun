use std::net::IpAddr;
use std::sync::Arc;

use crate::config::{PortForwardConfig, PortProtocol};
use crate::port_pool::PortPool;
use crate::wg::WireGuardTunnel;

mod tcp;

pub async fn port_forward(
    port_forward: PortForwardConfig,
    source_peer_ip: IpAddr,
    port_pool: Arc<PortPool>,
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
        PortProtocol::Tcp => tcp::tcp_proxy_server(port_forward, port_pool, wg).await,
        PortProtocol::Udp => Err(anyhow::anyhow!("UDP isn't supported just yet.")),
    }
}
