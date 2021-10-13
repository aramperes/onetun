use std::ops::Range;

use anyhow::Context;

const MIN_PORT: u16 = 32768;
const MAX_PORT: u16 = 60999;
const PORT_RANGE: Range<u16> = MIN_PORT..MAX_PORT;

pub struct PortPool {
    inner: lockfree::queue::Queue<u16>,
}

impl PortPool {
    pub fn new() -> Self {
        let inner = lockfree::queue::Queue::default();
        PORT_RANGE.for_each(|p| inner.push(p) as ());
        Self {
            inner,
        }
    }

    pub fn next(&self) -> anyhow::Result<u16> {
        self.inner
            .pop()
            .with_context(|| "Virtual port pool is exhausted")
    }

    pub fn release(&self, port: u16) {
        self.inner.push(port);
    }
}
