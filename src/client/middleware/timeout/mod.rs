mod body;
mod future;
mod layer;

use crate::config::{RequestReadTimeout, RequestTotalTimeout};
use crate::core::ext::RequestConfig;

use self::future::{ResponseBodyTimeoutFuture, ResponseFuture};
use http::{Request, Response};
use std::task::{Context, Poll};
use std::time::Duration;
use tower::BoxError;
use tower_service::Service;

pub use self::{
    body::TimeoutBody,
    layer::{ResponseBodyTimeoutLayer, TotalTimeoutLayer},
};

/// Timeout middleware for HTTP requests only.
#[derive(Clone)]
pub struct TotalTimeout<T> {
    inner: T,
    timeout: Duration,
}

impl<T> TotalTimeout<T> {
    /// Creates a new [`HttpTimeout`]
    pub const fn new(inner: T, timeout: Duration) -> Self {
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
        let sleep = tokio::time::sleep(
            RequestConfig::<RequestTotalTimeout>::remove(req.extensions_mut())
                .unwrap_or(self.timeout),
        );

        let uri = req.uri().clone();
        let response = self.inner.call(req);
        ResponseFuture {
            response,
            sleep,
            uri,
        }
    }
}

/// Applies a [`TimeoutBody`] to the response body.
#[derive(Clone)]
pub struct ResponseBodyTimeout<S> {
    inner: S,
    timeout: Duration,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseBodyTimeout<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = Response<TimeoutBody<ResBody>>;
    type Error = S::Error;
    type Future = ResponseBodyTimeoutFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let timeout = RequestConfig::<RequestReadTimeout>::remove(req.extensions_mut())
            .unwrap_or(self.timeout);

        ResponseBodyTimeoutFuture {
            inner: self.inner.call(req),
            timeout,
        }
    }
}
