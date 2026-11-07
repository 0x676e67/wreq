//! Runtime-neutral timeout middleware for connector services.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use tower::{BoxError, Layer, Service};

use crate::{
    error::TimedOut,
    rt::{BoxSleep, RuntimeHandle, Timer},
};

/// Adds a connection timeout using the client's timer provider.
/// The timer starts when the service is called.
#[derive(Clone)]
pub(in crate::conn) struct TimeoutLayer {
    timer: Arc<dyn Timer>,
    timeout: Option<Duration>,
}

/// Creates a separate deadline for each connection attempt.
/// Readiness waits before `call` are outside the deadline.
#[derive(Clone)]
pub struct Timeout<S> {
    inner: S,
    timer: Arc<dyn Timer>,
    timeout: Option<Duration>,
}

pin_project! {
    /// Owns one in-flight connection and its optional timeout sleep.
    ///
    /// The connection is polled first; while it remains pending, the sleep can end the attempt.
    /// Dropping this future drops both operations.
    pub struct TimeoutFuture<F> {
        #[pin]
        future: F,
        sleep: Option<BoxSleep>,
    }
}

// ===== impl TimeoutLayer =====

impl TimeoutLayer {
    pub(in crate::conn) fn new(runtime: RuntimeHandle, timeout: Option<Duration>) -> Self {
        Self {
            timer: runtime.timer(),
            timeout,
        }
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = Timeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Timeout {
            inner,
            timer: self.timer.clone(),
            timeout: self.timeout,
        }
    }
}

// ===== impl Timeout =====

impl<S, Request> Service<Request> for Timeout<S>
where
    S: Service<Request>,
    S::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = TimeoutFuture<S::Future>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let future = self.inner.call(request);
        let sleep = self.timeout.map(|timeout| self.timer.sleep(timeout));
        TimeoutFuture::new(future, sleep)
    }
}

// ===== impl TimeoutFuture =====

impl<F> TimeoutFuture<F> {
    pub(in crate::conn) fn new(future: F, sleep: Option<BoxSleep>) -> Self {
        Self { future, sleep }
    }
}

impl<F, T, E> Future for TimeoutFuture<F>
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
