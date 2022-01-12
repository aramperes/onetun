use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::config::PortForwardConfig;
use crate::virtual_iface::VirtualPort;
use crate::PortProtocol;

/// Events that go on the bus between the local server, smoltcp, and WireGuard.
#[derive(Debug, Clone)]
pub enum Event {
    /// Dumb event with no data.
    Dumb,
    /// A new connection with the local server was initiated, and the given virtual port was assigned.
    ClientConnectionInitiated(PortForwardConfig, VirtualPort),
    /// A connection was dropped from the pool and should be closed in all interfaces.
    ClientConnectionDropped(VirtualPort),
    /// Data received by the local server that should be sent to the virtual server.
    LocalData(PortForwardConfig, VirtualPort, Vec<u8>),
    /// Data received by the remote server that should be sent to the local client.
    RemoteData(VirtualPort, Vec<u8>),
    /// IP packet received from the WireGuard tunnel that should be passed through the corresponding virtual device.
    InboundInternetPacket(PortProtocol, Vec<u8>),
    /// IP packet to be sent through the WireGuard tunnel as crafted by the virtual device.
    OutboundInternetPacket(Vec<u8>),
    /// Notifies that a virtual device read an IP packet.
    VirtualDeviceFed(PortProtocol),
}

impl Display for Event {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::Dumb => {
                write!(f, "Dumb{{}}")
            }
            Event::ClientConnectionInitiated(pf, vp) => {
                write!(f, "ClientConnectionInitiated{{ pf={} vp={} }}", pf, vp)
            }
            Event::ClientConnectionDropped(vp) => {
                write!(f, "ClientConnectionDropped{{ vp={} }}", vp)
            }
            Event::LocalData(pf, vp, data) => {
                let size = data.len();
                write!(f, "LocalData{{ pf={} vp={} size={} }}", pf, vp, size)
            }
            Event::RemoteData(vp, data) => {
                let size = data.len();
                write!(f, "RemoteData{{ vp={} size={} }}", vp, size)
            }
            Event::InboundInternetPacket(proto, data) => {
                let size = data.len();
                write!(
                    f,
                    "InboundInternetPacket{{ proto={} size={} }}",
                    proto, size
                )
            }
            Event::OutboundInternetPacket(data) => {
                let size = data.len();
                write!(f, "OutboundInternetPacket{{ size={} }}", size)
            }
            Event::VirtualDeviceFed(proto) => {
                write!(f, "VirtualDeviceFed{{ proto={} }}", proto)
            }
        }
    }
}

#[derive(Clone)]
pub struct Bus {
    counter: Arc<AtomicU32>,
    bus: Arc<tokio::sync::broadcast::Sender<(u32, Event)>>,
}

impl Bus {
    /// Creates a new event bus.
    pub fn new() -> Self {
        let (bus, _) = tokio::sync::broadcast::channel(1000);
        let bus = Arc::new(bus);
        let counter = Arc::new(AtomicU32::default());
        Self { bus, counter }
    }

    /// Creates a new endpoint on the event bus.
    pub fn new_endpoint(&self) -> BusEndpoint {
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        let tx = (*self.bus).clone();
        let rx = self.bus.subscribe();

        let tx = BusSender { id, tx };
        BusEndpoint { id, tx, rx }
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BusEndpoint {
    id: u32,
    tx: BusSender,
    rx: tokio::sync::broadcast::Receiver<(u32, Event)>,
}

impl BusEndpoint {
    /// Sends the event on the bus. Note that the messages sent by this endpoint won't reach itself.
    pub fn send(&self, event: Event) {
        self.tx.send(event)
    }

    /// Returns the unique sequential ID of this endpoint.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Awaits the next `Event` on the bus to be read.
    pub async fn recv(&mut self) -> Event {
        loop {
            match self.rx.recv().await {
                Ok((id, event)) => {
                    if id == self.id {
                        // If the event was sent by this endpoint, it is skipped
                        continue;
                    } else {
                        return event;
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to read event bus from endpoint #{}: {:?}",
                        self.id, e
                    );
                    return futures::future::pending().await;
                }
            }
        }
    }

    /// Creates a new sender for this endpoint that can be cloned.
    pub fn sender(&self) -> BusSender {
        self.tx.clone()
    }
}

#[derive(Clone)]
pub struct BusSender {
    id: u32,
    tx: tokio::sync::broadcast::Sender<(u32, Event)>,
}

impl BusSender {
    /// Sends the event on the bus. Note that the messages sent by this endpoint won't reach itself.
    pub fn send(&self, event: Event) {
        trace!("#{} -> {}", self.id, event);
        match self.tx.send((self.id, event)) {
            Ok(_) => {}
            Err(_) => error!("Failed to send event to bus from endpoint #{}", self.id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bus() {
        let bus = Bus::new();

        let mut endpoint_1 = bus.new_endpoint();
        let mut endpoint_2 = bus.new_endpoint();
        let mut endpoint_3 = bus.new_endpoint();

        assert_eq!(endpoint_1.id(), 0);
        assert_eq!(endpoint_2.id(), 1);
        assert_eq!(endpoint_3.id(), 2);

        endpoint_1.send(Event::Dumb);
        let recv_2 = endpoint_2.recv().await;
        let recv_3 = endpoint_3.recv().await;
        assert!(matches!(recv_2, Event::Dumb));
        assert!(matches!(recv_3, Event::Dumb));

        endpoint_2.send(Event::Dumb);
        let recv_1 = endpoint_1.recv().await;
        let recv_3 = endpoint_3.recv().await;
        assert!(matches!(recv_1, Event::Dumb));
        assert!(matches!(recv_3, Event::Dumb));
    }
}
