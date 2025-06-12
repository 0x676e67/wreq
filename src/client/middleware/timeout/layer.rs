use std::time::Duration;
use tower::Layer;

use super::{ResponseBodyTimeout, TotalTimeout};

#[derive(Clone)]
pub struct TotalTimeoutLayer {
    timeout: Duration,
}

impl TotalTimeoutLayer {
    /// Create a timeout from a duration
    pub const fn new(timeout: Duration) -> Self {
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
    timeout: Duration,
}

impl ResponseBodyTimeoutLayer {
    /// Creates a new [`ResponseBodyTimeoutLayer`].
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl<S> Layer<S> for ResponseBodyTimeoutLayer {
    type Service = ResponseBodyTimeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseBodyTimeout {
            inner,
            timeout: self.timeout,
        }
    }
}
