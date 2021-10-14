use crate::wg::WireGuardTunnel;
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use std::sync::Arc;

#[derive(Clone)]
pub struct VirtualIpDevice {
    /// Tunnel to send IP packets to.
    wg: Arc<WireGuardTunnel>,
}

impl VirtualIpDevice {
    pub fn new(wg: Arc<WireGuardTunnel>) -> Self {
        Self { wg }
    }
}

impl<'a> Device<'a> for VirtualIpDevice {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let mut consumer = self.wg.subscribe();
        match consumer.try_recv() {
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
        match futures::executor::block_on(self.wg.send_ip_packet(&buffer)) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to send IP packet to WireGuard endpoint: {:?}", e);
            }
        }
        result
    }
}
