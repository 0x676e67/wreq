use std::{
    task::{Context, Poll},
    time::Duration,
};

use http::{Request, Response};
use tower::Layer;
use tower_service::Service;

use super::future::{ResponseBodyTimeoutFuture, ResponseFuture};
use crate::{
    client::middleware::timeout::TimeoutBody,
    config::{RequestReadTimeout, RequestTotalTimeout},
    core::ext::RequestConfig,
    error::BoxError,
};

/// [`Layer`] that applies a [`Timeout`] middleware to a service.
// This layer allows you to set a total timeout and a read timeout for requests.
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

/// Middleware that applies both a total timeout and a per-read timeout to the response body of a
/// request with a [`Service`].
#[derive(Clone)]
pub struct Timeout<T> {
    inner: T,
    total_timeout: RequestConfig<RequestTotalTimeout>,
    read_timeout: RequestConfig<RequestReadTimeout>,
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for Timeout<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = ResponseFuture<S::Future>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let total_timeout = self
            .total_timeout
            .fetch(req.extensions())
            .copied()
            .map(tokio::time::sleep);

        let read_timeout = self
            .read_timeout
            .fetch(req.extensions())
            .copied()
            .map(tokio::time::sleep);

        let uri = req.uri().clone();
        let response = self.inner.call(req);
        ResponseFuture {
            response,
            total_timeout,
            read_timeout,
            uri,
        }
    }
}

/// [`Layer`] that applies a [`ResponseBodyTimeout`] middleware to a service.
// This layer allows you to set a total timeout and a read timeout for the response body.
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

/// Middleware that timeouts the response body of a request with a [`Service`] to a total timeout
/// and a read timeout.
#[derive(Clone)]
pub struct ResponseBodyTimeout<S> {
    inner: S,
    total_timeout: RequestConfig<RequestTotalTimeout>,
    read_timeout: RequestConfig<RequestReadTimeout>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseBodyTimeout<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = Response<TimeoutBody<ResBody>>;
    type Error = S::Error;
    type Future = ResponseBodyTimeoutFuture<S::Future>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let total_timeout = self.total_timeout.fetch(req.extensions()).copied();
        let read_timeout = self.read_timeout.fetch(req.extensions()).copied();
        ResponseBodyTimeoutFuture {
            inner: self.inner.call(req),
            total_timeout,
            read_timeout,
        }
    }
}
