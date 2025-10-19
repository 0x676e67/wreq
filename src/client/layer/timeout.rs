//! Middleware for setting a timeout on the response.

mod body;
mod future;
mod layer;

use std::time::Duration;

pub use self::{
    body::TimeoutBody,
    layer::{ResponseBodyTimeout, ResponseBodyTimeoutLayer, Timeout, TimeoutLayer},
};

#[derive(Clone, Copy, Default)]
pub struct TimeoutOptions {
    total_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
}

impl TimeoutOptions {
    /// Sets the read timeout for the options.
    #[inline]
    pub fn read_timeout(&mut self, read_timeout: Duration) -> &mut Self {
        self.read_timeout = Some(read_timeout);
        self
    }

    /// Sets the total timeout for the options.
    #[inline]
    pub fn total_timeout(&mut self, total_timeout: Duration) -> &mut Self {
        self.total_timeout = Some(total_timeout);
        self
    }
}
