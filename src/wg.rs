use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use boringtun::noise::{Tunn, TunnResult};
use tokio::net::UdpSocket;

use crate::config::Config;
use crate::MAX_PACKET;

pub struct WireGuardTunnel {
    /// `boringtun` peer/tunnel implementation, used for crypto & WG protocol.
    peer: Box<Tunn>,
    /// The UDP socket for the public WireGuard endpoint to connect to.
    udp: UdpSocket,
    /// The address of the public WireGuard endpoint (UDP).
    endpoint: SocketAddr,
}

impl WireGuardTunnel {
    /// Initialize a new WireGuard tunnel.
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        let peer = Self::create_tunnel(&config)?;
        let udp = UdpSocket::bind("0.0.0.0:0")
            .await
            .with_context(|| "Failed to create UDP socket for WireGuard connection")?;
        let endpoint = config.endpoint_addr;

        Ok(Self {
            peer,
            udp,
            endpoint,
        })
    }

    /// WireGuard Routine task. Handles Handshake, keep-alive, etc.
    pub async fn routine_task(&self) -> ! {
        trace!("Starting WireGuard routine task");

        loop {
            let mut send_buf = [0u8; MAX_PACKET];
            match self.peer.update_timers(&mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    debug!(
                        "Sending routine packet of {} bytes to WireGuard endpoint",
                        packet.len()
                    );
                    match self.udp.send_to(packet, self.endpoint).await {
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

    fn create_tunnel(config: &Config) -> anyhow::Result<Box<Tunn>> {
        Tunn::new(
            config.private_key.clone(),
            config.endpoint_public_key.clone(),
            None,
            None,
            0,
            None,
        )
        .map_err(|s| anyhow::anyhow!("{}", s))
        .with_context(|| "Failed to initialize boringtun Tunn")
    }
}
