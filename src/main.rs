#[macro_use]
extern crate log;

use std::sync::Arc;

use anyhow::Context;

use crate::config::Config;
use crate::tunnel::tcp::TcpPortPool;
use crate::tunnel::udp::UdpPortPool;
use crate::wg::WireGuardTunnel;

pub mod config;
pub mod ip_sink;
pub mod tunnel;
pub mod virtual_device;
pub mod virtual_iface;
pub mod wg;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_args().with_context(|| "Failed to read config")?;
    init_logger(&config)?;

    for warning in &config.warnings {
        warn!("{}", warning);
    }

    // Initialize the port pool for each protocol
    let tcp_port_pool = TcpPortPool::new();
    let udp_port_pool = UdpPortPool::new();

    let wg = WireGuardTunnel::new(&config)
        .await
        .with_context(|| "Failed to initialize WireGuard tunnel")?;
    let wg = Arc::new(wg);

    {
        // Start routine task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.routine_task().await });
    }

    {
        // Start consumption task for WireGuard
        let wg = wg.clone();
        tokio::spawn(async move { wg.consume_task().await });
    }

    {
        // Start IP sink task for incoming IP packets
        let wg = wg.clone();
        tokio::spawn(async move { ip_sink::run_ip_sink_interface(wg).await });
    }

    {
        let port_forwards = config.port_forwards;
        let source_peer_ip = config.source_peer_ip;

        port_forwards
            .into_iter()
            .map(|pf| (pf, wg.clone(), tcp_port_pool.clone(), udp_port_pool.clone()))
            .for_each(move |(pf, wg, tcp_port_pool, udp_port_pool)| {
                tokio::spawn(async move {
                    tunnel::port_forward(pf, source_peer_ip, tcp_port_pool, udp_port_pool, wg)
                        .await
                        .unwrap_or_else(|e| error!("Port-forward failed for {} : {}", pf, e))
                });
            });
    }

    futures::future::pending().await
}

fn init_logger(config: &Config) -> anyhow::Result<()> {
    let mut builder = pretty_env_logger::formatted_builder();
    builder.parse_filters(&config.log);
    builder
        .try_init()
        .with_context(|| "Failed to initialize logger")
}
