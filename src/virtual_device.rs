use crate::config::PortProtocol;
use crate::events::{BusSender, Event};
use crate::Bus;
use bytes::{BufMut, Bytes, BytesMut};
use smoltcp::{
    phy::{DeviceCapabilities, Medium},
    time::Instant,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

/// A virtual device that processes IP packets through smoltcp and WireGuard.
pub struct VirtualIpDevice {
    /// Max transmission unit (bytes)
    max_transmission_unit: usize,
    /// Channel receiver for received IP packets.
    bus_sender: BusSender,
    /// Local queue for packets received from the bus that need to go through the smoltcp interface.
    process_queue: Arc<Mutex<VecDeque<Bytes>>>,
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

impl smoltcp::phy::Device for VirtualIpDevice {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let next = {
            let mut queue = self
                .process_queue
                .lock()
                .expect("Failed to acquire process queue lock");
            queue.pop_front()
        };
        match next {
            Some(buffer) => Some((
                Self::RxToken {
                    buffer: {
                        let mut buf = BytesMut::new();
                        buf.put(buffer);
                        buf
                    },
                },
                Self::TxToken {
                    sender: self.bus_sender.clone(),
                },
            )),
            None => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
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
    buffer: BytesMut,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

#[doc(hidden)]
pub struct TxToken {
    sender: BusSender,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.sender
            .send(Event::OutboundInternetPacket(buffer.into()));
        result
    }
}
