//! Runtime-neutral deadline for one connector call.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use tower::{BoxError, Layer, Service};

use crate::{
    conn::request::ConnectRequest,
    error::{ProxyConnect, TimedOut},
    rt::{BoxSleep, DynRuntime, Timer as _},
};

/// Middleware layer to use [`Deadline`].
#[derive(Clone)]
pub(crate) struct DeadlineLayer {
    timeout: Option<Duration>,
    runtime: DynRuntime,
}

/// Bounds each connector call by one deadline, started in `call` after readiness waits.
/// It covers everything beneath: user layers, proxy setup and the transport handshakes.
/// Expiry during a [`ProxyStage`] is a proxy connect error, like a failure of that stage.
#[derive(Clone)]
pub(crate) struct Deadline<S> {
    inner: S,
    timeout: Option<Duration>,
    runtime: DynRuntime,
}

/// Counts the proxy stages a connector call is in: reaching the proxy and negotiating its
/// tunnel or association, but not the target handshake through it. Clones share the count.
/// Untracked by default; [`Deadline`] tracks the requests it bounds.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProxyStage(Option<Arc<AtomicUsize>>);

/// Leaves a [`ProxyStage`] when dropped, so errors and cancellation leave it too.
#[must_use = "the proxy stage ends when the guard is dropped"]
pub(crate) struct ProxyStageGuard(Option<Arc<AtomicUsize>>);

pin_project! {
    /// Owns one in-flight connection, its optional timeout sleep and the stage it reports.
    ///
    /// The connection is polled first; while it remains pending, the sleep can end the attempt.
    /// Dropping this future drops both operations.
    pub struct ResponseFuture<F> {
        #[pin]
        future: F,
        sleep: Option<BoxSleep>,
        stage: ProxyStage,
    }
}

// ===== impl DeadlineLayer =====

impl DeadlineLayer {
    pub(crate) fn new(timeout: Option<Duration>, runtime: DynRuntime) -> Self {
        Self { timeout, runtime }
    }
}

impl<S> Layer<S> for DeadlineLayer {
    type Service = Deadline<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        Deadline {
            inner,
            timeout: self.timeout,
            runtime: self.runtime.clone(),
        }
    }
}

// ===== impl Deadline =====

impl<S> Service<ConnectRequest> for Deadline<S>
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

    fn call(&mut self, mut request: ConnectRequest) -> Self::Future {
        let stage = match self.timeout {
            Some(_) => request.track_proxy_stage(),
            None => ProxyStage::default(),
        };
        ResponseFuture {
            future: self.inner.call(request),
            sleep: self.timeout.map(|timeout| self.runtime.sleep(timeout)),
            stage,
        }
    }
}

// ===== impl ProxyStage =====

impl ProxyStage {
    /// Creates a stage whose count a deadline can read.
    pub(super) fn tracked() -> Self {
        Self(Some(Arc::new(AtomicUsize::new(0))))
    }

    /// Enters the stage until the returned guard drops.
    pub(super) fn enter(&self) -> ProxyStageGuard {
        if let Some(count) = &self.0 {
            count.fetch_add(1, Ordering::Relaxed);
        }
        ProxyStageGuard(self.0.clone())
    }

    fn is_active(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(|count| count.load(Ordering::Relaxed) > 0)
    }
}

// ===== impl ProxyStageGuard =====

impl Drop for ProxyStageGuard {
    fn drop(&mut self) {
        if let Some(count) = &self.0 {
            count.fetch_sub(1, Ordering::Relaxed);
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
            let error: BoxError = if this.stage.is_active() {
                Box::new(ProxyConnect::Source(Box::new(TimedOut)))
            } else {
                Box::new(TimedOut)
            };
            return Poll::Ready(Err(error));
        }

        Poll::Pending
    }
}
