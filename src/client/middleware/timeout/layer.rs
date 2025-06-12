use std::time::Duration;
use tower::Layer;

use super::TotalTimeout;

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
