mod future;
mod layer;

use crate::config::RequestTotalTimeout;
use crate::core::ext::RequestConfig;

use self::future::ResponseFuture;
use http::{Request, Response};
use std::task::{Context, Poll};
use std::time::Duration;
use tower::BoxError;
use tower_service::Service;

pub use self::layer::TotalTimeoutLayer;

/// Timeout middleware for HTTP requests only.
#[derive(Clone)]
pub struct TotalTimeout<T> {
    inner: T,
    timeout: Option<Duration>,
}

impl<T> TotalTimeout<T> {
    /// Creates a new [`HttpTimeout`]
    pub const fn new(inner: T, timeout: Option<Duration>) -> Self {
        TotalTimeout { inner, timeout }
    }
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for TotalTimeout<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let sleep = RequestConfig::<RequestTotalTimeout>::remove(req.extensions_mut())
            .or(self.timeout)
            .map(tokio::time::sleep);
        let uri = req.uri().clone();
        let response = self.inner.call(req);
        ResponseFuture::new(response, sleep, uri)
    }
}
