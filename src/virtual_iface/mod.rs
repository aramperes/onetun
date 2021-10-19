pub mod tcp;

use async_trait::async_trait;

#[async_trait]
pub trait VirtualInterfacePoll {
    /// Initializes the virtual interface and processes incoming data to be dispatched
    /// to the WireGuard tunnel and to the real client.
    async fn poll_loop(mut self) -> anyhow::Result<()>;
}
