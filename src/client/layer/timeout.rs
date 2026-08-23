//! Middleware for setting a timeout on the response.

pub mod body;
mod future;

use std::{
    task::{Context, Poll},
    time::Duration,
};

use http::{Request, Response};
use tower::{BoxError, Layer, Service};
use wreq_proto::rt::Timer as _;

use self::{
    body::TimeoutBody,
    future::{ResponseBodyTimeoutFuture, ResponseFuture},
};
use crate::{config::RequestConfig, rt::Timer};

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
    timer: Timer,
    timeout: RequestConfig<TimeoutOptions>,
}

impl TimeoutLayer {
    /// Create a new [`TimeoutLayer`].
    pub fn new(timer: Timer, options: TimeoutOptions) -> Self {
        TimeoutLayer {
            timer,
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
            timer: self.timer.clone(),
            timeout: self.timeout,
        }
    }
}

/// Middleware that applies request and response-body timeouts to a [`Service`].
#[derive(Clone)]
pub struct Timeout<T> {
    inner: T,
    timer: Timer,
    timeout: RequestConfig<TimeoutOptions>,
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for Timeout<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = BoxError>,
{
    type Response = Response<TimeoutBody<ResBody>>;
    type Error = BoxError;
    type Future = ResponseFuture<ResponseBodyTimeoutFuture<S::Future>>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    #[inline(always)]
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let (total_timeout, read_timeout) = fetch_timeout_options(&self.timeout, req.extensions());
        // `total_timeout` is a budget for the *whole* request (head + body), so
        // the deadline must be computed once, here, and reused for the body
        // wrapper below. Re-deriving a fresh `timer.sleep(total_timeout)` once
        // the body starts (as this used to do) restarts the clock and lets the
        // body alone consume the full duration a second time.
        let total_deadline = total_timeout.map(|timeout| self.timer.now() + timeout);
        ResponseFuture {
            fut: ResponseBodyTimeoutFuture {
                fut: self.inner.call(req),
                timer: self.timer.clone(),
                total_deadline,
                read_timeout,
            },
            total_timeout: total_deadline.map(|deadline| self.timer.sleep_until(deadline)),
            read_timeout: read_timeout.map(|timeout| self.timer.sleep(timeout)),
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
