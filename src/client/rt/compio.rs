#![allow(dead_code)]
//! Compio-based executor and timer for wreq.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use send_wrapper::SendWrapper;
use wreq_proto::rt::{Executor, Sleep, Timer};

/// Future executor that utilises the `compio` runtime.
#[non_exhaustive]
#[derive(Default, Debug, Clone)]
pub struct CompioExecutor {
    _priv: (),
}

impl CompioExecutor {
    #[inline]
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<Fut> Executor<Fut> for CompioExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    #[inline]
    fn execute(&self, fut: Fut) {
        compio::runtime::spawn(fut).detach();
    }
}

/// A Timer that uses the compio runtime.
#[non_exhaustive]
#[derive(Default, Clone, Debug)]
pub struct CompioTimer {
    _priv: (),
}

impl CompioTimer {
    #[inline]
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

/// A sleep future wrapping a compio timer via SendWrapper.
///
/// compio futures are `!Send` (thread-per-core), so we wrap in `SendWrapper`
/// to satisfy wreq's `Send` bounds.
struct CompioSleep {
    inner: SendWrapper<Pin<Box<dyn Future<Output = ()>>>>,
}

impl CompioSleep {
    fn new(fut: impl Future<Output = ()> + 'static) -> Self {
        let boxed: Pin<Box<dyn Future<Output = ()>>> = Box::pin(fut);
        Self {
            inner: SendWrapper::new(boxed),
        }
    }
}

impl Timer for CompioTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(CompioSleep::new(compio::time::sleep(duration)))
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(CompioSleep::new(compio::time::sleep_until(deadline)))
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        *sleep = self.sleep_until(new_deadline);
    }
}

impl Future for CompioSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

impl Sleep for CompioSleep {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        let this = self.get_mut();
        let fut: Pin<Box<dyn Future<Output = ()>>> = Box::pin(compio::time::sleep_until(deadline));
        this.inner = SendWrapper::new(fut);
    }
}

impl std::fmt::Debug for CompioSleep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompioSleep").finish_non_exhaustive()
    }
}
