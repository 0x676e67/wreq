//! Runtime-neutral deadline for one connector call.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use tower::{BoxError, Layer, Service};

use crate::{
    conn::request::ConnectRequest,
    error::TimedOut,
    rt::{BoxSleep, DynRuntime, Timer as _},
};

/// Middleware layer to use [`Timeout`].
#[derive(Clone)]
pub(crate) struct TimeoutLayer {
    timeout: Option<Duration>,
    runtime: DynRuntime,
}

/// Bounds each connector call by one deadline, started in `call` after readiness waits.
/// It covers everything beneath: user layers, proxy setup and the transport handshakes.
#[derive(Clone)]
pub(crate) struct Timeout<S> {
    inner: S,
    timeout: Option<Duration>,
    runtime: DynRuntime,
}

pin_project! {
    /// Owns one in-flight connection and its optional timeout sleep.
    ///
    /// The connection is polled first; while it remains pending, the sleep can end the attempt.
    /// Dropping this future drops both operations.
    pub struct ResponseFuture<F> {
        #[pin]
        future: F,
        sleep: Option<BoxSleep>,
    }
}

// ===== impl TimeoutLayer =====

impl TimeoutLayer {
    pub(crate) fn new(timeout: Option<Duration>, runtime: DynRuntime) -> Self {
        Self { timeout, runtime }
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = Timeout<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        Timeout {
            inner,
            timeout: self.timeout,
            runtime: self.runtime.clone(),
        }
    }
}

// ===== impl Timeout =====

impl<S> Service<ConnectRequest> for Timeout<S>
where
    S: Service<ConnectRequest>,
    S::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = ResponseFuture<S::Future>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: ConnectRequest) -> Self::Future {
        ResponseFuture {
            future: self.inner.call(request),
            sleep: self.timeout.map(|timeout| self.runtime.sleep(timeout)),
        }
    }
}

// ===== impl ResponseFuture =====

impl<F, T, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<T, E>>,
    E: Into<BoxError>,
{
    type Output = Result<T, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.future.poll(cx) {
            Poll::Ready(result) => return Poll::Ready(result.map_err(Into::into)),
            Poll::Pending => {}
        }

        if let Some(sleep) = this.sleep.as_mut()
            && Pin::new(&mut *sleep).poll(cx).is_ready()
        {
            return Poll::Ready(Err(Box::new(TimedOut)));
        }

        Poll::Pending
    }
}
