//! Middleware for setting a timeout on the response.

mod body;
mod future;
mod layer;

use std::time::Duration;

pub use self::{
    body::TimeoutBody,
    layer::{ResponseBodyTimeout, ResponseBodyTimeoutLayer, Timeout, TimeoutLayer},
};

#[derive(Debug, Clone, Default)]
pub struct TimeoutOptions {
    total: Option<Duration>,
    read: Option<Duration>,
}

impl TimeoutOptions {
    /// Get a mutable reference to the read timeout.
    #[inline]
    pub fn read_timeout_mut(&mut self, read: Duration) -> &mut Self {
        self.read = Some(read);
        self
    }

    /// Get a mutable reference to the total timeout.
    #[inline]
    pub fn total_timeout_mut(&mut self, total: Duration) -> &mut Self {
        self.total = Some(total);
        self
    }
}
