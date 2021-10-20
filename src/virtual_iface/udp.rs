use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::config::PortForwardConfig;
use crate::virtual_iface::{VirtualInterfacePoll, VirtualPort};
use crate::wg::WireGuardTunnel;

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
        let _source_peer_ip = self.wg.source_peer_ip;

        // The IP/port to bind the server socket to
        let _destination = self.port_forward.destination;

        loop {
            let _loop_start = smoltcp::time::Instant::now();
            // TODO: smoltcp UDP

            if let Ok((client_port, data)) = data_to_virtual_server_rx.try_recv() {
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
