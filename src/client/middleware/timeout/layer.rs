use std::time::Duration;

use tower::Layer;

use super::{ResponseBodyTimeout, Timeout};
use crate::{
    config::{RequestReadTimeout, RequestTotalTimeout},
    core::ext::RequestConfig,
};

#[derive(Clone)]
pub struct TimeoutLayer {
    total_timeout: RequestConfig<RequestTotalTimeout>,
    read_timeout: RequestConfig<RequestReadTimeout>,
}

impl TimeoutLayer {
    /// Create a timeout from a duration
    pub const fn new(total_timeout: Option<Duration>, read_timeout: Option<Duration>) -> Self {
        TimeoutLayer {
            total_timeout: RequestConfig::new(total_timeout),
            read_timeout: RequestConfig::new(read_timeout),
        }
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = Timeout<S>;

    fn layer(&self, service: S) -> Self::Service {
        Timeout {
            inner: service,
            total_timeout: self.total_timeout,
            read_timeout: self.read_timeout,
        }
    }
}

/// Applies a [`TimeoutBody`] to the response body.
#[derive(Clone)]
pub struct ResponseBodyTimeoutLayer {
    total_timeout: RequestConfig<RequestTotalTimeout>,
    read_timeout: RequestConfig<RequestReadTimeout>,
}

impl ResponseBodyTimeoutLayer {
    /// Creates a new [`ResponseBodyTimeoutLayer`].
    pub const fn new(total_timeout: Option<Duration>, read_timeout: Option<Duration>) -> Self {
        Self {
            total_timeout: RequestConfig::new(total_timeout),
            read_timeout: RequestConfig::new(read_timeout),
        }
    }
}

impl<S> Layer<S> for ResponseBodyTimeoutLayer {
    type Service = ResponseBodyTimeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseBodyTimeout {
            inner,
            total_timeout: self.total_timeout,
            read_timeout: self.read_timeout,
        }
    }
}
