use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

#[derive(Clone)]
pub struct VirtualIpDevice {
    /// Channel for packets sent by the interface.
    ip_tx: crossbeam_channel::Sender<Vec<u8>>,
    ip_rx: crossbeam_channel::Receiver<Vec<u8>>,
}

impl VirtualIpDevice {
    pub fn new(
        ip_tx: crossbeam_channel::Sender<Vec<u8>>,
        ip_rx: crossbeam_channel::Receiver<Vec<u8>>,
    ) -> Self {
        Self { ip_tx, ip_rx }
    }
}

impl<'a> Device<'a> for VirtualIpDevice {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        if !self.ip_rx.is_empty() {
            let buffer = self.ip_rx.recv().expect("failed to read ip_rx");
            Some((
                RxToken { buffer },
                TxToken {
                    ip_tx: self.ip_tx.clone(),
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            ip_tx: self.ip_tx.clone(),
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
    ip_tx: crossbeam_channel::Sender<Vec<u8>>,
}

impl<'a> smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buffer = Vec::new();
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        self.ip_tx
            .send(buffer.clone())
            .expect("failed to send to ip_tx");
        result
    }
}
