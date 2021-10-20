use anyhow::Context;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use smoltcp::iface::InterfaceBuilder;
use smoltcp::socket::{SocketSet, UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::{IpAddress, IpCidr};

use crate::config::PortForwardConfig;
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::{VirtualInterfacePoll, VirtualPort};
use crate::wg::{WireGuardTunnel, DISPATCH_CAPACITY};

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

        loop {
            let _loop_start = smoltcp::time::Instant::now();
            let wg = self.wg.clone();
            // TODO: smoltcp UDP

            if let Ok((client_port, data)) = data_to_virtual_server_rx.try_recv() {
                // Register the socket in WireGuard Tunnel if not already
                if !wg.is_registered(client_port) {
                    wg.register_virtual_interface(client_port, base_ip_dispatch_tx.clone())
                        .unwrap_or_else(|e| {
                            error!(
                                "[{}] Failed to register UDP socket in WireGuard tunnel",
                                client_port
                            );
                        });
                }

                // TODO: Find the matching client socket and send
                // Echo for now
                self.data_to_real_client_tx
                    .send((client_port, data))
                    .await
                    .unwrap_or_else(|e| {
                        error!(
                            "[{}] Failed to dispatch data from virtual client to real client: {:?}",
                            client_port, e
                        );
                    });
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // Ok(())
    }
}
