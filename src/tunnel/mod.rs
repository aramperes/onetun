use std::net::IpAddr;
use std::sync::Arc;

use crate::config::{PortForwardConfig, PortProtocol};
use crate::events::Bus;
use crate::tunnel::tcp::TcpPortPool;
use crate::tunnel::udp::UdpPortPool;
use crate::wg::WireGuardTunnel;

pub mod tcp;
pub mod udp;

pub async fn port_forward(
    port_forward: PortForwardConfig,
    source_peer_ip: IpAddr,
    tcp_port_pool: TcpPortPool,
    udp_port_pool: UdpPortPool,
    wg: Arc<WireGuardTunnel>,
    bus: Bus,
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
        PortProtocol::Tcp => {
            if port_forward.remote {
                tcp::tcp_remote_dispatcher(port_forward, bus).await
            } else {
                tcp::tcp_proxy_server(port_forward, tcp_port_pool, bus).await
            }
        }
        PortProtocol::Udp => {
            if port_forward.remote {
                udp::udp_remote_dispatcher(port_forward, udp_port_pool, bus).await
            } else {
                udp::udp_proxy_server(port_forward, udp_port_pool, bus).await
            }
        }
    }
}
