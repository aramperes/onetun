#![allow(dead_code)]
use std::net::IpAddr;

use crate::{Bus, PortProtocol};
use async_trait::async_trait;

use crate::config::PortForwardConfig;
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::VirtualInterfacePoll;

const MAX_PACKET: usize = 65536;

pub struct UdpVirtualInterface {
    source_peer_ip: IpAddr,
    port_forwards: Vec<PortForwardConfig>,
    device: VirtualIpDevice,
    bus: Bus,
}

impl UdpVirtualInterface {
    /// Initialize the parameters for a new virtual interface.
    /// Use the `poll_loop()` future to start the virtual interface poll loop.
    pub fn new(
        port_forwards: Vec<PortForwardConfig>,
        bus: Bus,
        device: VirtualIpDevice,
        source_peer_ip: IpAddr,
    ) -> Self {
        Self {
            port_forwards: port_forwards
                .into_iter()
                .filter(|f| matches!(f.protocol, PortProtocol::Udp))
                .collect(),
            device,
            source_peer_ip,
            bus,
        }
    }
}

#[async_trait]
impl VirtualInterfacePoll for UdpVirtualInterface {
    async fn poll_loop(self) -> anyhow::Result<()> {
        // TODO: Create smoltcp virtual device and interface
        // TODO: Create smoltcp virtual servers for `port_forwards`
        // TODO: listen on events
        futures::future::pending().await
    }
}
