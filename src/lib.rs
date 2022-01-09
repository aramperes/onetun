#[macro_use]
extern crate log;

use std::sync::Arc;

use anyhow::Context;

use crate::config::{Config, PortProtocol};
use crate::events::Bus;
use crate::tunnel::tcp::TcpPortPool;
use crate::tunnel::udp::UdpPortPool;
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::tcp::TcpVirtualInterface;
use crate::virtual_iface::udp::UdpVirtualInterface;
use crate::virtual_iface::VirtualInterfacePoll;
use crate::wg::WireGuardTunnel;

pub mod config;
pub mod events;
#[cfg(feature = "pcap")]
pub mod pcap;
pub mod tunnel;
pub mod virtual_device;
pub mod virtual_iface;
pub mod wg;

/// Starts the onetun tunnels in separate tokio tasks.
///
/// Note: This future completes immediately.
pub async fn start_tunnels(config: Config, bus: Bus) -> anyhow::Result<()> {
    // Initialize the port pool for each protocol
    let tcp_port_pool = TcpPortPool::new();
    let udp_port_pool = UdpPortPool::new();

    #[cfg(feature = "pcap")]
    if let Some(pcap_file) = config.pcap_file.clone() {
        // Start packet capture
        let bus = bus.clone();
        tokio::spawn(async move { pcap::capture(pcap_file, bus).await });
    }

    let wg = WireGuardTunnel::new(&config, bus.clone())
        .await
        .context("Failed to initialize WireGuard tunnel")?;
    let wg = Arc::new(wg);

    {
        // Start routine task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.routine_task().await });
    }

    {
        // Start consumption task for WireGuard
        let wg = wg.clone();
        tokio::spawn(Box::pin(async move { wg.consume_task().await }));
    }

    {
        // Start production task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.produce_task().await });
    }

    if config
        .port_forwards
        .iter()
        .any(|pf| pf.protocol == PortProtocol::Tcp)
    {
        // TCP device
        let bus = bus.clone();
        let device =
            VirtualIpDevice::new(PortProtocol::Tcp, bus.clone(), config.max_transmission_unit);

        // Start TCP Virtual Interface
        let port_forwards = config.port_forwards.clone();
        let iface = TcpVirtualInterface::new(port_forwards, bus, config.source_peer_ip);
        tokio::spawn(async move { iface.poll_loop(device).await });
    }

    if config
        .port_forwards
        .iter()
        .any(|pf| pf.protocol == PortProtocol::Udp)
        || config
            .remote_port_forwards
            .iter()
            .any(|pf| pf.protocol == PortProtocol::Udp)
    {
        // UDP device
        let bus = bus.clone();
        let device =
            VirtualIpDevice::new(PortProtocol::Udp, bus.clone(), config.max_transmission_unit);

        // Start UDP Virtual Interface
        let port_forwards = config.port_forwards.clone();
        let remote_port_forwards = config.remote_port_forwards.clone();
        let iface = UdpVirtualInterface::new(
            port_forwards,
            remote_port_forwards,
            bus,
            config.source_peer_ip,
        );
        tokio::spawn(async move { iface.poll_loop(device).await });
    }

    {
        let port_forwards = config.port_forwards;
        let source_peer_ip = config.source_peer_ip;

        port_forwards
            .into_iter()
            .map(|pf| {
                (
                    pf,
                    wg.clone(),
                    tcp_port_pool.clone(),
                    udp_port_pool.clone(),
                    bus.clone(),
                )
            })
            .for_each(move |(pf, wg, tcp_port_pool, udp_port_pool, bus)| {
                tokio::spawn(async move {
                    tunnel::port_forward(pf, source_peer_ip, tcp_port_pool, udp_port_pool, wg, bus)
                        .await
                        .unwrap_or_else(|e| error!("Port-forward failed for {} : {}", pf, e))
                });
            });
    }

    {
        let remote_port_forwards = config.remote_port_forwards;

        remote_port_forwards
            .into_iter()
            .map(|pf| {
                (
                    pf,
                    wg.clone(),
                    tcp_port_pool.clone(),
                    udp_port_pool.clone(),
                    bus.clone(),
                )
            })
            .for_each(move |(pf, wg, tcp_port_pool, udp_port_pool, bus)| {
                tokio::spawn(async move {
                    tunnel::remote_port_forward(pf, tcp_port_pool, udp_port_pool, wg, bus)
                        .await
                        .unwrap_or_else(|e| error!("Remote port-forward failed for {} : {}", pf, e))
                });
            });
    }

    Ok(())
}
