//! Shared runtime ownership and private protocol runtime adapters.
//!
//! [`DynRuntime`] connects the public [`Runtime`] contract to the executor and
//! timer traits required by the protocol implementation and, with HTTP/3, to the
//! QUIC runtime. Generic protocol tasks are boxed at this boundary; protocol timers
//! reuse the [`BoxSleep`] allocation, and each QUIC connection boxes its one timer.
//! The runtime is its own [`Timer`], so every protocol layer shares one executor and clock.

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
/// Created with the client builder, this runtime stays alive while services or
/// background tasks retain a clone. Clones share the same `Arc`.
///
/// [`Deref`] exposes the runtime's capabilities, and timer operations forward to it.
#[derive(Clone, Debug)]
pub(crate) struct DynRuntime(Arc<dyn Runtime>);

impl DynRuntime {
    /// Shares a runtime value or reuses an existing `Arc` through [`IntoRuntime`].
    #[inline]
    pub(crate) fn new(runtime: impl IntoRuntime) -> Self {
        Self(runtime.into_shared())
    }

    /// Shares the runtime as a timer provider by cloning the existing `Arc`.
    #[inline]
    pub(crate) fn timer(&self) -> Arc<dyn Timer> {
        self.0.clone()
    }

    /// Submits an already boxed task to the selected runtime.
    /// Forwards ownership without another allocation or a runtime clone.
    #[inline]
    #[track_caller]
    pub(crate) fn execute(&self, fut: BoxFuture<'static, ()>) {
        self.0.execute(fut);
    }

    /// Shares this runtime with a QUIC endpoint.
    #[cfg(feature = "http3")]
    #[inline]
    pub(crate) fn quic(&self) -> Arc<dyn ::quic::Runtime> {
        Arc::new(self.clone())
    }
}

impl Deref for DynRuntime {
    type Target = dyn Runtime;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl Timer for DynRuntime {
    #[inline]
    fn sleep(&self, duration: Duration) -> BoxSleep {
        self.0.sleep(duration)
    }

    #[inline]
    fn sleep_until(&self, deadline: Instant) -> BoxSleep {
        self.0.sleep_until(deadline)
    }

    #[inline]
    fn now(&self) -> Instant {
        self.0.now()
    }
}

impl<F> rt::Executor<F> for DynRuntime
where
    F: Future<Output = ()> + Send + 'static,
{
    #[inline]
    fn execute(&self, fut: F) {
        self.execute(Box::pin(fut));
    }
}

impl rt::Timer for DynRuntime {
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

#[cfg(feature = "http3")]
impl ::quic::Runtime for DynRuntime {
    #[inline]
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn ::quic::AsyncTimer>> {
        Box::pin(Timer::sleep_until(self, deadline))
    }

    #[inline]
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.execute(future);
    }

    #[inline]
    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<Box<dyn ::quic::AsyncUdpSocket>> {
        self.0.udp_socket(socket)
    }

    #[inline]
    fn now(&self) -> Instant {
        Timer::now(self)
    }
}
