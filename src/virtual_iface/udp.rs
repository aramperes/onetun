use crate::config::PortForwardConfig;
use crate::events::Event;
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::{VirtualInterfacePoll, VirtualPort};
use crate::{Bus, PortProtocol};
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::udp::{self, UdpMetadata},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpVersion},
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    time::Duration,
};

const MAX_PACKET: usize = 65536;

pub struct UdpVirtualInterface {
    source_peer_ip: IpAddr,
    port_forwards: Vec<PortForwardConfig>,
    bus: Bus,
    sockets: SocketSet<'static>,
}

impl UdpVirtualInterface {
    /// Initialize the parameters for a new virtual interface.
    /// Use the `poll_loop()` future to start the virtual interface poll loop.
    pub fn new(port_forwards: Vec<PortForwardConfig>, bus: Bus, source_peer_ip: IpAddr) -> Self {
        Self {
            port_forwards: port_forwards
                .into_iter()
                .filter(|f| matches!(f.protocol, PortProtocol::Udp))
                .collect(),
            source_peer_ip,
            bus,
            sockets: SocketSet::new([]),
        }
    }

    fn new_server_socket(port_forward: PortForwardConfig) -> anyhow::Result<udp::Socket<'static>> {
        static mut UDP_SERVER_RX_META: [udp::PacketMetadata; 0] = [];
        static mut UDP_SERVER_RX_DATA: [u8; 0] = [];
        static mut UDP_SERVER_TX_META: [udp::PacketMetadata; 0] = [];
        static mut UDP_SERVER_TX_DATA: [u8; 0] = [];
        let udp_rx_buffer =
            udp::PacketBuffer::new(unsafe { &mut UDP_SERVER_RX_META[..] }, unsafe {
                &mut UDP_SERVER_RX_DATA[..]
            });
        let udp_tx_buffer =
            udp::PacketBuffer::new(unsafe { &mut UDP_SERVER_TX_META[..] }, unsafe {
                &mut UDP_SERVER_TX_DATA[..]
            });
        let mut socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);
        socket
            .bind((
                IpAddress::from(port_forward.destination.ip()),
                port_forward.destination.port(),
            ))
            .context("UDP virtual server socket failed to bind")?;
        Ok(socket)
    }

    fn new_client_socket(
        source_peer_ip: IpAddr,
        client_port: VirtualPort,
    ) -> anyhow::Result<udp::Socket<'static>> {
        let rx_meta = vec![udp::PacketMetadata::EMPTY; 10];
        let tx_meta = vec![udp::PacketMetadata::EMPTY; 10];
        let rx_data = vec![0u8; MAX_PACKET];
        let tx_data = vec![0u8; MAX_PACKET];
        let udp_rx_buffer = udp::PacketBuffer::new(rx_meta, rx_data);
        let udp_tx_buffer = udp::PacketBuffer::new(tx_meta, tx_data);
        let mut socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);
        socket
            .bind((IpAddress::from(source_peer_ip), client_port.num()))
            .context("UDP virtual client failed to bind")?;
        Ok(socket)
    }

    fn addresses(&self) -> Vec<IpCidr> {
        let mut addresses = HashSet::new();
        addresses.insert(IpAddress::from(self.source_peer_ip));
        for config in self.port_forwards.iter() {
            addresses.insert(IpAddress::from(config.destination.ip()));
        }
        addresses
            .into_iter()
            .map(|addr| IpCidr::new(addr, addr_length(&addr)))
            .collect()
    }
}

#[async_trait]
impl VirtualInterfacePoll for UdpVirtualInterface {
    async fn poll_loop(mut self, mut device: VirtualIpDevice) -> anyhow::Result<()> {
        // Create CIDR block for source peer IP + each port forward IP
        let addresses = self.addresses();
        let config = Config::new(HardwareAddress::Ip);

        // Create virtual interface (contains smoltcp state machine)
        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|ip_addrs| {
            addresses.into_iter().for_each(|addr| {
                ip_addrs
                    .push(addr)
                    .expect("maximum number of IPs in UDP interface reached");
            });
        });

        // Create virtual server for each port forward
        for port_forward in self.port_forwards.iter() {
            let server_socket = UdpVirtualInterface::new_server_socket(*port_forward)?;
            self.sockets.add(server_socket);
        }

        // The next time to poll the interface. Can be None for instant poll.
        let mut next_poll: Option<tokio::time::Instant> = None;

        // Bus endpoint to read events
        let mut endpoint = self.bus.new_endpoint();

        // Maps virtual port to its client socket handle
        let mut port_client_handle_map: HashMap<VirtualPort, SocketHandle> = HashMap::new();

        // Data packets to send from a virtual client
        let mut send_queue: HashMap<VirtualPort, VecDeque<(PortForwardConfig, Bytes)>> =
            HashMap::new();

        loop {
            tokio::select! {
                _ = match (next_poll, port_client_handle_map.len()) {
                    (None, 0) => tokio::time::sleep(Duration::MAX),
                    (None, _) => tokio::time::sleep(Duration::ZERO),
                    (Some(until), _) => tokio::time::sleep_until(until),
                } => {
                    let loop_start = smoltcp::time::Instant::now();

                    if iface.poll(loop_start, &mut device, &mut self.sockets) {
                        log::trace!("UDP virtual interface polled some packets to be processed");
                    }

                    for (virtual_port, client_handle) in port_client_handle_map.iter() {
                        let client_socket = self.sockets.get_mut::<udp::Socket>(*client_handle);
                        if client_socket.can_send() {
                            if let Some(send_queue) = send_queue.get_mut(virtual_port) {
                                let to_transfer = send_queue.pop_front();
                                if let Some((port_forward, data)) = to_transfer {
                                    client_socket
                                        .send_slice(
                                            &data,
                                            UdpMetadata::from(port_forward.destination),
                                        )
                                        .unwrap_or_else(|e| {
                                            error!(
                                                "[{}] Failed to send data to virtual server: {:?}",
                                                virtual_port, e
                                            );
                                        });
                                }
                            }
                        }
                        if client_socket.can_recv() {
                            match client_socket.recv() {
                                Ok((data, _peer)) => {
                                    if !data.is_empty() {
                                        endpoint.send(Event::RemoteData(*virtual_port, data.to_vec().into()));
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to read from virtual client socket: {:?}", e
                                    );
                                }
                            }
                        }
                    }

                    // The virtual interface determines the next time to poll (this is to reduce unnecessary polls)
                    next_poll = match iface.poll_delay(loop_start, &self.sockets) {
                        Some(smoltcp::time::Duration::ZERO) => None,
                        Some(delay) => {
                            trace!("UDP Virtual interface delayed next poll by {}", delay);
                            Some(tokio::time::Instant::now() + Duration::from_millis(delay.total_millis()))
                        },
                        None => None,
                    };
                }
                event = endpoint.recv() => {
                    match event {
                        Event::LocalData(port_forward, virtual_port, data) => {
                            if let Some(send_queue) = send_queue.get_mut(&virtual_port) {
                                // Client socket already exists
                                send_queue.push_back((port_forward, data));
                            } else {
                                // Client socket does not exist
                                let client_socket = UdpVirtualInterface::new_client_socket(self.source_peer_ip, virtual_port)?;
                                let client_handle = self.sockets.add(client_socket);

                                // Add handle to map
                                port_client_handle_map.insert(virtual_port, client_handle);
                                send_queue.insert(virtual_port, VecDeque::from(vec![(port_forward, data)]));
                            }
                            next_poll = None;
                        }
                        Event::VirtualDeviceFed(PortProtocol::Udp) => {
                            next_poll = None;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

const fn addr_length(addr: &IpAddress) -> u8 {
    match addr.version() {
        IpVersion::Ipv4 => 32,
        IpVersion::Ipv6 => 128,
    }
}
