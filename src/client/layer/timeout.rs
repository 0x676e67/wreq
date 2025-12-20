//! Middleware for setting a timeout on the response.

mod body;
mod future;

use std::{
    task::{Context, Poll},
    time::Duration,
};

use http::{Request, Response};
use tower::{Layer, Service};

pub use self::body::TimeoutBody;
use self::future::{ResponseBodyTimeoutFuture, ResponseFuture};
use crate::{config::RequestConfig, error::BoxError};

/// Options for configuring timeouts.
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

impl_request_config_value!(TimeoutOptions);

/// [`Layer`] that applies a [`Timeout`] middleware to a service.
// This layer allows you to set a total timeout and a read timeout for requests.
#[derive(Clone)]
pub struct TimeoutLayer {
    timeout: RequestConfig<TimeoutOptions>,
}

impl TimeoutLayer {
    /// Create a new [`TimeoutLayer`].
    #[inline(always)]
    pub const fn new(options: TimeoutOptions) -> Self {
        TimeoutLayer {
            timeout: RequestConfig::new(Some(options)),
        }
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = Timeout<S>;

    #[inline(always)]
    fn layer(&self, service: S) -> Self::Service {
        Timeout {
            inner: service,
            timeout: self.timeout,
        }
    }
}

/// Middleware that applies total and per-read timeouts to a [`Service`] response body.
#[derive(Clone)]
pub struct Timeout<T> {
    inner: T,
    timeout: RequestConfig<TimeoutOptions>,
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

    #[inline(always)]
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let (total_timeout, read_timeout) = fetch_timeout_options(&self.timeout, req.extensions());
        ResponseFuture {
            response: self.inner.call(req),
            total_timeout: total_timeout.map(tokio::time::sleep),
            read_timeout: read_timeout.map(tokio::time::sleep),
        }
    }
}

/// [`Layer`] that applies a [`ResponseBodyTimeout`] middleware to a service.
// This layer allows you to set a total timeout and a read timeout for the response body.
#[derive(Clone)]
pub struct ResponseBodyTimeoutLayer {
    timeout: RequestConfig<TimeoutOptions>,
}

impl ResponseBodyTimeoutLayer {
    /// Creates a new [`ResponseBodyTimeoutLayer`].
    #[inline(always)]
    pub const fn new(options: TimeoutOptions) -> Self {
        Self {
            timeout: RequestConfig::new(Some(options)),
        }
    }
}

impl<S> Layer<S> for ResponseBodyTimeoutLayer {
    type Service = ResponseBodyTimeout<S>;

    #[inline(always)]
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
    timeout: RequestConfig<TimeoutOptions>,
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

    #[inline(always)]
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let (total_timeout, read_timeout) = fetch_timeout_options(&self.timeout, req.extensions());
        ResponseBodyTimeoutFuture {
            inner: self.inner.call(req),
            total_timeout,
            read_timeout,
        }
    }
}

fn fetch_timeout_options(
    opts: &RequestConfig<TimeoutOptions>,
    extensions: &http::Extensions,
) -> (Option<Duration>, Option<Duration>) {
    match (opts.as_ref(), opts.fetch(extensions)) {
        (Some(opts), Some(request_opts)) => (
            request_opts.total_timeout.or(opts.total_timeout),
            request_opts.read_timeout.or(opts.read_timeout),
        ),
        (Some(opts), None) => (opts.total_timeout, opts.read_timeout),
        (None, Some(opts)) => (opts.total_timeout, opts.read_timeout),
        (None, None) => (None, None),
    }
}
