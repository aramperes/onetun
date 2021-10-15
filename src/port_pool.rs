use std::ops::Range;

use anyhow::Context;

const MIN_PORT: u16 = 32768;
const MAX_PORT: u16 = 60999;
const PORT_RANGE: Range<u16> = MIN_PORT..MAX_PORT;

pub struct PortPool {
    /// Remaining ports
    inner: lockfree::queue::Queue<u16>,
    /// Ports in use
    taken: lockfree::set::Set<u16>,
}

impl Default for PortPool {
    fn default() -> Self {
        Self::new()
    }
}

impl PortPool {
    pub fn new() -> Self {
        let inner = lockfree::queue::Queue::default();
        PORT_RANGE.for_each(|p| inner.push(p) as ());
        Self {
            inner,
            taken: lockfree::set::Set::new(),
        }
    }

    pub fn next(&self) -> anyhow::Result<u16> {
        let port = self
            .inner
            .pop()
            .with_context(|| "Virtual port pool is exhausted")?;
        self.taken
            .insert(port)
            .ok()
            .with_context(|| "Failed to insert taken")?;
        Ok(port)
    }

    pub fn release(&self, port: u16) {
        self.inner.push(port);
        self.taken.remove(&port);
    }

    pub fn is_in_use(&self, port: u16) -> bool {
        self.taken.contains(&port)
    }
}
