//! Tokio executor and timer.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use netty::rt::{Executor, Sleep, Timer};
use pin_project_lite::pin_project;

/// Spawns futures with [`tokio::spawn`].
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioExecutor;

/// Drives timeouts with [`tokio::time`].
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioTimer;

pin_project! {
    /// Adapts [`tokio::time::Sleep`] to the [`Sleep`] trait.
    struct TokioSleep {
        #[pin]
        inner: tokio::time::Sleep,
    }
}

// ===== impl TokioExecutor =====

impl<Fut> Executor<Fut> for TokioExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    #[inline]
    fn execute(&self, fut: Fut) {
        tokio::spawn(fut);
    }
}

// ===== impl TokioTimer =====

impl Timer for TokioTimer {
    #[inline]
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep(duration),
        })
    }

    #[inline]
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep_until(deadline.into()),
        })
    }

    #[inline]
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into()
    }

    #[inline]
    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        sleep.as_mut().reset(new_deadline);
    }
}

// ===== impl TokioSleep =====

impl Future for TokioSleep {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

impl Sleep for TokioSleep {
    #[inline]
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.project().inner.reset(deadline.into());
    }
}
