#[derive(Clone)]
pub struct ProxyClient {
    /// Unique identifier for this client (used as a port number in the virtual interface).
    pub virtual_port: u16,
    /// For sending data to the client.
    pub data_tx: crossbeam_channel::Sender<Vec<u8>>,
    /// For receiving data from the client.
    pub data_rx: crossbeam_channel::Receiver<Vec<u8>>,
}
