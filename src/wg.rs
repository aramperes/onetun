use anyhow::Context;
use boringtun::noise::{Tunn, TunnResult};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::config::Config;
use crate::MAX_PACKET;

pub fn create_tunnel(config: &Config) -> anyhow::Result<Box<Tunn>> {
    Tunn::new(
        config.private_key.clone(),
        config.endpoint_public_key.clone(),
        None,
        None,
        0,
        None,
    )
    .map_err(|s| anyhow::anyhow!("{}", s))
    .with_context(|| "Failed to initialize peer")
}

/// WireGuard Routine task. Handles Handshake, keep-alive, etc.
pub async fn routine(
    peer: Arc<Box<Tunn>>,
    wireguard_udp: Arc<UdpSocket>,
    endpoint_addr: SocketAddr,
) {
    debug!("Started WireGuard routine thread");
    loop {
        let mut send_buf = [0u8; MAX_PACKET];
        match peer.update_timers(&mut send_buf) {
            TunnResult::WriteToNetwork(packet) => {
                debug!(
                    "Sending routine packet of {} bytes to WireGuard endpoint",
                    packet.len()
                );
                match wireguard_udp.send_to(packet, endpoint_addr).await {
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
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            other => {
                warn!("Unexpected WireGuard routine task state: {:?}", other);
            }
        }
    }
}
