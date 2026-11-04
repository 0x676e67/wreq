//! Compio executor, timer and I/O adapter.
//!
//! Compio is thread-per-core and its futures are `!Send`, so they are wrapped in
//! [`SendWrapper`](send_wrapper::SendWrapper), which panics if they are touched from another
//! thread.

pub mod io;

// Tokio takes precedence for the executor and timer when both runtimes are enabled.
if_compio_rt! {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
        time::{Duration, Instant},
    };

    use netty::rt::{Executor, Sleep, Timer};
    use send_wrapper::SendWrapper;

    /// Spawns futures on the current compio runtime.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct CompioExecutor;

    /// Drives timeouts with [`compio::time`].
    #[derive(Clone, Copy, Debug, Default)]
    pub struct CompioTimer;

    /// Adapts a compio sleep future to the [`Sleep`] trait.
    struct CompioSleep(SendWrapper<Pin<Box<dyn Future<Output = ()>>>>);

    // ===== impl CompioExecutor =====

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

    // ===== impl CompioTimer =====

    impl Timer for CompioTimer {
        #[inline]
        fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
            Box::pin(CompioSleep::new(compio::time::sleep(duration)))
        }

        #[inline]
        fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
            Box::pin(CompioSleep::new(compio::time::sleep_until(deadline)))
        }

        #[inline]
        fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
            sleep.as_mut().reset(new_deadline);
        }
    }

    // ===== impl CompioSleep =====

    impl CompioSleep {
        #[inline]
        fn new(fut: impl Future<Output = ()> + 'static) -> Self {
            Self(SendWrapper::new(Box::pin(fut)))
        }
    }

    impl Future for CompioSleep {
        type Output = ();

        #[inline]
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Pin::new(&mut self.get_mut().0).poll(cx)
        }
    }

    impl Sleep for CompioSleep {
        #[inline]
        fn reset(self: Pin<&mut Self>, deadline: Instant) {
            *self.get_mut() = Self::new(compio::time::sleep_until(deadline));
        }
    }
}
