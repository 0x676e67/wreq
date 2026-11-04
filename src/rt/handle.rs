//! Shared runtime ownership and private protocol runtime adapters.
//!
//! [`RuntimeHandle`] connects the public [`Runtime`] contract to the executor and
//! timer traits required by the protocol implementation. Generic protocol tasks
//! are boxed at this boundary; [`BoxSleep`] transfers its existing allocation.
//! Timer providers come from [`Runtime::new_timer`], which controls their sharing.

use std::{
    future::Future,
    ops::Deref,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::future::BoxFuture;
use netty::rt;

use super::{BoxSleep, IntoRuntime, Runtime, Timer};

/// Shares one selected runtime across connection, protocol and pool services.
///
/// Created with the client builder, this handle keeps the runtime alive while
/// services or background tasks retain a clone. Clones share the same `Arc`.
///
/// [`Deref`] exposes the runtime's capabilities. Timer operations obtain a provider
/// on demand; callers can retain the returned `Arc<dyn Timer>` independently.
#[derive(Clone)]
pub(crate) struct RuntimeHandle(Arc<dyn Runtime>);

impl RuntimeHandle {
    /// Shares a runtime value or reuses an existing `Arc` through [`IntoRuntime`].
    #[inline]
    pub(crate) fn new(runtime: impl IntoRuntime) -> Self {
        Self(runtime.into_shared())
    }

    /// Obtains a timer provider through [`Runtime::new_timer`].
    /// The runtime decides whether to allocate or reuse a provider; callers may
    /// retain and clone the returned `Arc` for repeated timer operations.
    #[inline]
    pub(crate) fn timer(&self) -> Arc<dyn Timer> {
        self.0.new_timer()
    }

    /// Submits an already boxed task to the selected runtime.
    /// Forwards ownership without another allocation or a handle clone.
    #[inline]
    pub(crate) fn execute(&self, fut: BoxFuture<'static, ()>) {
        self.0.execute(fut);
    }
}

impl Deref for RuntimeHandle {
    type Target = dyn Runtime;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl Timer for RuntimeHandle {
    #[inline]
    fn sleep(&self, duration: Duration) -> BoxSleep {
        self.timer().sleep(duration)
    }

    #[inline]
    fn sleep_until(&self, deadline: Instant) -> BoxSleep {
        self.timer().sleep_until(deadline)
    }

    #[inline]
    fn now(&self) -> Instant {
        self.timer().now()
    }
}

impl<F> rt::Executor<F> for RuntimeHandle
where
    F: Future<Output = ()> + Send + 'static,
{
    #[inline]
    fn execute(&self, fut: F) {
        self.execute(Box::pin(fut));
    }
}

impl rt::Timer for RuntimeHandle {
    #[inline]
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn rt::Sleep>> {
        Timer::sleep(self, duration).into_inner()
    }

    #[inline]
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn rt::Sleep>> {
        Timer::sleep_until(self, deadline).into_inner()
    }

    #[inline]
    fn now(&self) -> Instant {
        Timer::now(self)
    }

    #[inline]
    fn reset(&self, sleep: &mut Pin<Box<dyn rt::Sleep>>, deadline: Instant) {
        sleep.as_mut().reset(deadline);
    }
}
