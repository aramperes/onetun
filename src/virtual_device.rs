use crate::wg::WireGuardTunnel;
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use std::sync::Arc;

/// A virtual device that processes IP packets. IP packets received from the WireGuard endpoint
/// are made available to this device using a broadcast channel receiver. IP packets sent from this device
/// are asynchronously sent out to the WireGuard tunnel.
pub struct VirtualIpDevice {
    /// Tunnel to send IP packets to.
    wg: Arc<WireGuardTunnel>,
    /// Broadcast channel receiver for received IP packets.
    ip_broadcast_rx: tokio::sync::broadcast::Receiver<Vec<u8>>,
}

impl VirtualIpDevice {
    pub fn new(wg: Arc<WireGuardTunnel>) -> Self {
        let ip_broadcast_rx = wg.subscribe();

        Self {
            wg,
            ip_broadcast_rx,
        }
    }
}

impl<'a> Device<'a> for VirtualIpDevice {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        match self.ip_broadcast_rx.try_recv() {
            Ok(buffer) => Some((
                Self::RxToken { buffer },
                Self::TxToken {
                    wg: self.wg.clone(),
                },
            )),
            Err(_) => None,
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            wg: self.wg.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.medium = Medium::Ip;
        cap.max_transmission_unit = 65535;
        cap
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(&mut self.buffer)
    }
}

#[doc(hidden)]
pub struct TxToken {
    wg: Arc<WireGuardTunnel>,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buffer = Vec::new();
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        tokio::spawn(async move {
            match self.wg.send_ip_packet(&buffer).await {
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to send IP packet to WireGuard endpoint: {:?}", e);
                }
            }
        });
        result
    }
}
