use crate::config::PortProtocol;
use crate::events::{BusSender, Event};
use crate::Bus;
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// A virtual device that processes IP packets through smoltcp and WireGuard.
pub struct VirtualIpDevice {
    /// Max transmission unit (bytes)
    max_transmission_unit: usize,
    /// Channel receiver for received IP packets.
    bus_sender: BusSender,
    /// Local queue for packets received from the bus that need to go through the smoltcp interface.
    process_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl VirtualIpDevice {
    /// Initializes a new virtual IP device.
    pub fn new(protocol: PortProtocol, bus: Bus, max_transmission_unit: usize) -> Self {
        let mut bus_endpoint = bus.new_endpoint();
        let bus_sender = bus_endpoint.sender();
        let process_queue = Arc::new(Mutex::new(VecDeque::new()));

        {
            let process_queue = process_queue.clone();
            tokio::spawn(async move {
                loop {
                    match bus_endpoint.recv().await {
                        Event::InboundInternetPacket(ip_proto, data) if ip_proto == protocol => {
                            let mut queue = process_queue
                                .lock()
                                .expect("Failed to acquire process queue lock");
                            queue.push_back(data);
                            bus_endpoint.send(Event::VirtualDeviceFed(ip_proto));
                        }
                        _ => {}
                    }
                }
            });
        }

        Self {
            bus_sender,
            process_queue,
            max_transmission_unit,
        }
    }
}

impl<'a> Device<'a> for VirtualIpDevice {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let next = {
            let mut queue = self
                .process_queue
                .lock()
                .expect("Failed to acquire process queue lock");
            queue.pop_front()
        };
        match next {
            Some(buffer) => Some((
                Self::RxToken { buffer },
                Self::TxToken {
                    sender: self.bus_sender.clone(),
                },
            )),
            None => None,
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            sender: self.bus_sender.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.medium = Medium::Ip;
        cap.max_transmission_unit = self.max_transmission_unit;
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
    sender: BusSender,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buffer = Vec::new();
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        self.sender.send(Event::OutboundInternetPacket(buffer));
        result
    }
}
