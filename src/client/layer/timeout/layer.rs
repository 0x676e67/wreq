use std::{
    task::{Context, Poll},
    time::Duration,
};

use http::{Request, Response};
use tower::{Layer, Service};

use super::future::{ResponseBodyTimeoutFuture, ResponseFuture};
use crate::{
    client::layer::{
        config::RequestTimeoutOptions,
        timeout::{TimeoutBody, TimeoutOptions},
    },
    core::ext::RequestConfig,
    error::BoxError,
};

/// [`Layer`] that applies a [`Timeout`] middleware to a service.
// This layer allows you to set a total timeout and a read timeout for requests.
#[derive(Clone)]
pub struct TimeoutLayer {
    timeout: RequestConfig<RequestTimeoutOptions>,
}

impl TimeoutLayer {
    /// Create a new [`TimeoutLayer`].
    pub const fn new(options: TimeoutOptions) -> Self {
        TimeoutLayer {
            timeout: RequestConfig::new(Some(options)),
        }
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = Timeout<S>;

    fn layer(&self, service: S) -> Self::Service {
        Timeout {
            inner: service,
            timeout: self.timeout,
        }
    }
}

/// Middleware that applies both a total timeout and a per-read timeout to the response body of a
/// request with a [`Service`].
#[derive(Clone)]
pub struct Timeout<T> {
    inner: T,
    timeout: RequestConfig<RequestTimeoutOptions>,
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
        let (total_timeout, read_timeout) = resolve_timeout_config(&self.timeout, req.extensions());
        let total_timeout = total_timeout.map(tokio::time::sleep);
        let read_timeout = read_timeout.map(tokio::time::sleep);

        ResponseFuture {
            response: self.inner.call(req),
            total_timeout,
            read_timeout,
        }
    }
}

/// [`Layer`] that applies a [`ResponseBodyTimeout`] middleware to a service.
// This layer allows you to set a total timeout and a read timeout for the response body.
#[derive(Clone)]
pub struct ResponseBodyTimeoutLayer {
    timeout: RequestConfig<RequestTimeoutOptions>,
}

impl ResponseBodyTimeoutLayer {
    /// Creates a new [`ResponseBodyTimeoutLayer`].
    pub const fn new(options: TimeoutOptions) -> Self {
        Self {
            timeout: RequestConfig::new(Some(options)),
        }
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

/// Middleware that timeouts the response body of a request with a [`Service`] to a total timeout
/// and a read timeout.
#[derive(Clone)]
pub struct ResponseBodyTimeout<S> {
    inner: S,
    timeout: RequestConfig<RequestTimeoutOptions>,
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
        let (total_timeout, read_timeout) = resolve_timeout_config(&self.timeout, req.extensions());
        ResponseBodyTimeoutFuture {
            inner: self.inner.call(req),
            total_timeout,
            read_timeout,
        }
    }
}

#[inline]
fn resolve_timeout_config(
    layer_opts: &RequestConfig<RequestTimeoutOptions>,
    extensions: &http::Extensions,
) -> (Option<Duration>, Option<Duration>) {
    let request_opts = layer_opts.fetch(extensions);

    match (layer_opts.as_ref(), request_opts) {
        (Some(layer_opts), Some(request_opts)) => (
            request_opts.total_timeout.or(layer_opts.total_timeout),
            request_opts.read_timeout.or(layer_opts.read_timeout),
        ),
        (Some(layer_opts), None) => (layer_opts.total_timeout, layer_opts.read_timeout),
        (None, Some(request_opts)) => (request_opts.total_timeout, request_opts.read_timeout),
        (None, None) => (None, None),
    }
}
