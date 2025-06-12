use std::time::Duration;
use tower::Layer;

use super::{ResponseBodyTimeout, TotalTimeout};

#[derive(Clone)]
pub struct TotalTimeoutLayer {
    timeout: Option<Duration>,
}

impl TotalTimeoutLayer {
    /// Create a timeout from a duration
    pub const fn new(timeout: Option<Duration>) -> Self {
        TotalTimeoutLayer { timeout }
    }
}

impl<S> Layer<S> for TotalTimeoutLayer {
    type Service = TotalTimeout<S>;

    fn layer(&self, service: S) -> Self::Service {
        TotalTimeout::new(service, self.timeout)
    }
}

/// Applies a [`TimeoutBody`] to the response body.
#[derive(Clone)]
pub struct ResponseBodyTimeoutLayer {
    read_timeout: Option<Duration>,
    total_timeout: Option<Duration>,
}

impl ResponseBodyTimeoutLayer {
    /// Creates a new [`ResponseBodyTimeoutLayer`].
    pub const fn new(total_timeout: Option<Duration>, read_timeout: Option<Duration>) -> Self {
        Self {
            read_timeout,
            total_timeout,
        }
    }
}

impl<S> Layer<S> for ResponseBodyTimeoutLayer {
    type Service = ResponseBodyTimeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseBodyTimeout {
            inner,
            read_timeout: self.read_timeout,
            total_timeout: self.total_timeout,
        }
    }
}
