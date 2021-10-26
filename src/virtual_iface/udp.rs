use anyhow::Context;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use smoltcp::iface::InterfaceBuilder;
use smoltcp::socket::{SocketHandle, SocketSet, UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::{IpAddress, IpCidr};

use crate::config::PortForwardConfig;
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::{VirtualInterfacePoll, VirtualPort};
use crate::wg::{WireGuardTunnel, DISPATCH_CAPACITY};

const MAX_PACKET: usize = 65536;

pub struct UdpVirtualInterface {
    port_forward: PortForwardConfig,
    wg: Arc<WireGuardTunnel>,
    data_to_real_client_tx: tokio::sync::mpsc::Sender<(VirtualPort, Vec<u8>)>,
    data_to_virtual_server_rx: tokio::sync::mpsc::Receiver<(VirtualPort, Vec<u8>)>,
}

impl UdpVirtualInterface {
    pub fn new(
        port_forward: PortForwardConfig,
        wg: Arc<WireGuardTunnel>,
        data_to_real_client_tx: tokio::sync::mpsc::Sender<(VirtualPort, Vec<u8>)>,
        data_to_virtual_server_rx: tokio::sync::mpsc::Receiver<(VirtualPort, Vec<u8>)>,
    ) -> Self {
        Self {
            port_forward,
            wg,
            data_to_real_client_tx,
            data_to_virtual_server_rx,
        }
    }
}

#[async_trait]
impl VirtualInterfacePoll for UdpVirtualInterface {
    async fn poll_loop(self) -> anyhow::Result<()> {
        // Data receiver to dispatch using virtual client sockets
        let mut data_to_virtual_server_rx = self.data_to_virtual_server_rx;

        // The IP to bind client sockets to
        let source_peer_ip = self.wg.source_peer_ip;

        // The IP/port to bind the server socket to
        let destination = self.port_forward.destination;

        // Initialize a channel for IP packets.
        // The "base transmitted" is cloned so that each virtual port can register a sender in the tunnel.
        // The receiver is given to the device so that the Virtual Interface can process incoming IP packets from the tunnel.
        let (base_ip_dispatch_tx, ip_dispatch_rx) = tokio::sync::mpsc::channel(DISPATCH_CAPACITY);

        let device = VirtualIpDevice::new(self.wg.clone(), ip_dispatch_rx);
        let mut virtual_interface = InterfaceBuilder::new(device)
            .ip_addrs([
                // Interface handles IP packets for the sender and recipient
                IpCidr::new(source_peer_ip.into(), 32),
                IpCidr::new(destination.ip().into(), 32),
            ])
            .finalize();

        // Server socket: this is a placeholder for the interface.
        let server_socket: anyhow::Result<UdpSocket> = {
            static mut UDP_SERVER_RX_META: [UdpPacketMetadata; 0] = [];
            static mut UDP_SERVER_RX_DATA: [u8; 0] = [];
            static mut UDP_SERVER_TX_META: [UdpPacketMetadata; 0] = [];
            static mut UDP_SERVER_TX_DATA: [u8; 0] = [];
            let udp_rx_buffer =
                UdpSocketBuffer::new(unsafe { &mut UDP_SERVER_RX_META[..] }, unsafe {
                    &mut UDP_SERVER_RX_DATA[..]
                });
            let udp_tx_buffer =
                UdpSocketBuffer::new(unsafe { &mut UDP_SERVER_TX_META[..] }, unsafe {
                    &mut UDP_SERVER_TX_DATA[..]
                });
            let mut socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);

            socket
                .bind((IpAddress::from(destination.ip()), destination.port()))
                .with_context(|| "UDP virtual server socket failed to listen")?;

            Ok(socket)
        };

        let mut socket_set = SocketSet::new(vec![]);
        let _server_handle = socket_set.add(server_socket?);

        // A map of virtual port to client socket.
        let mut client_sockets: HashMap<VirtualPort, SocketHandle> = HashMap::new();

        // The next instant required to poll the virtual interface
        // None means "immediate poll required".
        let mut next_poll: Option<tokio::time::Instant> = None;

        loop {
            let wg = self.wg.clone();
            tokio::select! {
                // Wait the recommended amount of time by smoltcp, and poll again.
                _ = match next_poll {
                    None => tokio::time::sleep(Duration::ZERO),
                    Some(until) => tokio::time::sleep_until(until)
                } => {
                    let loop_start = smoltcp::time::Instant::now();

                    match virtual_interface.poll(&mut socket_set, loop_start) {
                        Ok(processed) if processed => {
                            trace!("UDP virtual interface polled some packets to be processed");
                        }
                        Err(e) => error!("UDP virtual interface poll error: {:?}", e),
                        _ => {}
                    }

                    // Loop through each client socket and check if there is any data to send back
                    // to the real client.
                    for (virtual_port, client_socket_handle) in client_sockets.iter() {
                        let mut client_socket = socket_set.get::<UdpSocket>(*client_socket_handle);
                        match client_socket.recv() {
                            Ok((data, _peer)) => {
                                // Send the data back to the real client using MPSC channel
                                self.data_to_real_client_tx
                                    .send((*virtual_port, data.to_vec()))
                                    .await
                                    .unwrap_or_else(|e| {
                                        error!(
                                            "[{}] Failed to dispatch data from virtual client to real client: {:?}",
                                            virtual_port, e
                                        );
                                    });
                            }
                            Err(smoltcp::Error::Exhausted) => {}
                            Err(e) => {
                                error!(
                                    "[{}] Failed to read from virtual client socket: {:?}",
                                    virtual_port, e
                                );
                            }
                        }
                    }

                    next_poll = match virtual_interface.poll_delay(&socket_set, loop_start) {
                        Some(smoltcp::time::Duration::ZERO) => None,
                        Some(delay) => Some(tokio::time::Instant::now() + Duration::from_millis(delay.millis())),
                        None => None,
                    }
                }
                // Wait for data to be received from the real client
                data_recv_result = data_to_virtual_server_rx.recv() => {
                    if let Some((client_port, data)) = data_recv_result {
                        // Register the socket in WireGuard Tunnel (overrides any previous registration as well)
                        wg.register_virtual_interface(client_port, base_ip_dispatch_tx.clone())
                            .unwrap_or_else(|e| {
                                error!(
                                    "[{}] Failed to register UDP socket in WireGuard tunnel: {:?}",
                                    client_port, e
                                );
                            });

                        let client_socket_handle = client_sockets.entry(client_port).or_insert_with(|| {
                            let rx_meta = vec![UdpPacketMetadata::EMPTY; 10];
                            let tx_meta = vec![UdpPacketMetadata::EMPTY; 10];
                            let rx_data = vec![0u8; MAX_PACKET];
                            let tx_data = vec![0u8; MAX_PACKET];
                            let udp_rx_buffer = UdpSocketBuffer::new(rx_meta, rx_data);
                            let udp_tx_buffer = UdpSocketBuffer::new(tx_meta, tx_data);
                            let mut socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);

                            socket
                                .bind((IpAddress::from(wg.source_peer_ip), client_port.0))
                                .unwrap_or_else(|e| {
                                    error!(
                                        "[{}] UDP virtual client socket failed to bind: {:?}",
                                        client_port, e
                                    );
                                });

                            socket_set.add(socket)
                        });

                        let mut client_socket = socket_set.get::<UdpSocket>(*client_socket_handle);
                        client_socket
                            .send_slice(
                                &data,
                                (IpAddress::from(destination.ip()), destination.port()).into(),
                            )
                            .unwrap_or_else(|e| {
                                error!(
                                    "[{}] Failed to send data to virtual server: {:?}",
                                    client_port, e
                                );
                            });
                    }
                }
            }
        }
    }
}
