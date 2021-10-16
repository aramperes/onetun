use std::ops::Range;

use anyhow::Context;
use rand::seq::SliceRandom;
use rand::thread_rng;

const MIN_PORT: u16 = 32768;
const MAX_PORT: u16 = 60999;
const PORT_RANGE: Range<u16> = MIN_PORT..MAX_PORT;

/// A pool of virtual ports available.
/// This structure is thread-safe and lock-free; you can use it safely in an `Arc`.
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
    /// Initializes a new pool of virtual ports.
    pub fn new() -> Self {
        let inner = lockfree::queue::Queue::default();
        let mut ports: Vec<u16> = PORT_RANGE.collect();
        ports.shuffle(&mut thread_rng());
        ports.into_iter().for_each(|p| inner.push(p) as ());
        Self {
            inner,
            taken: lockfree::set::Set::new(),
        }
    }

    /// Requests a free port from the pool. An error is returned if none is available (exhaused max capacity).
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

    /// Releases a port back into the pool.
    pub fn release(&self, port: u16) {
        self.inner.push(port);
        self.taken.remove(&port);
    }

    /// Whether the given port is in use by a virtual interface.
    pub fn is_in_use(&self, port: u16) -> bool {
        self.taken.contains(&port)
    }
}
