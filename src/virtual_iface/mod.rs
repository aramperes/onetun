pub mod tcp;
pub mod udp;

use crate::config::PortProtocol;
use async_trait::async_trait;
use std::fmt::{Display, Formatter};

#[async_trait]
pub trait VirtualInterfacePoll {
    /// Initializes the virtual interface and processes incoming data to be dispatched
    /// to the WireGuard tunnel and to the real client.
    async fn poll_loop(mut self) -> anyhow::Result<()>;
}

/// Virtual port.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct VirtualPort(pub u16, pub PortProtocol);

impl Display for VirtualPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}:{}]", self.0, self.1)
    }
}
