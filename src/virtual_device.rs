use crate::virtual_iface::VirtualPort;
use crate::wg::{WireGuardTunnel, DISPATCH_CAPACITY};
use anyhow::Context;
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use std::sync::Arc;

/// A virtual device that processes IP packets. IP packets received from the WireGuard endpoint
/// are made available to this device using a channel receiver. IP packets sent from this device
/// are asynchronously sent out to the WireGuard tunnel.
pub struct VirtualIpDevice {
    /// Tunnel to send IP packets to.
    wg: Arc<WireGuardTunnel>,
    /// Channel receiver for received IP packets.
    ip_dispatch_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl VirtualIpDevice {
    /// Registers a virtual IP device for a single virtual client.
    pub fn new(virtual_port: VirtualPort, wg: Arc<WireGuardTunnel>) -> anyhow::Result<Self> {
        let (ip_dispatch_tx, ip_dispatch_rx) = tokio::sync::mpsc::channel(DISPATCH_CAPACITY);

        wg.register_virtual_interface(virtual_port, ip_dispatch_tx)
            .with_context(|| "Failed to register IP dispatch for virtual interface")?;

        Ok(Self { wg, ip_dispatch_rx })
    }

    pub async fn new_sink(wg: Arc<WireGuardTunnel>) -> anyhow::Result<Self> {
        let ip_dispatch_rx = wg
            .register_sink_interface()
            .await
            .with_context(|| "Failed to register IP dispatch for sink virtual interface")?;
        Ok(Self { wg, ip_dispatch_rx })
    }
}

impl<'a> Device<'a> for VirtualIpDevice {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        match self.ip_dispatch_rx.try_recv() {
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
        cap.max_transmission_unit = 1420;
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
