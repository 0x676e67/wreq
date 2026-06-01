//! Runtime components — executor and timer abstractions.
//!
//! This module provides [`Executor`] and [`Timer`], the two runtime primitives
//! used by the HTTP client for spawning background tasks and driving timeouts.
//!
//! # Feature flags
//!
//! At least one of the following features must be enabled:
//!
//! - `tokio-rt` — uses [tokio] as the underlying runtime (default).
//! - `compio-rt` — uses [compio] as the underlying runtime.
//!
//! When both are enabled, `tokio-rt` takes precedence for both [`Executor`]
//! and [`Timer`].  When neither is enabled, [`Executor::default`] and
//! [`Timer::default`] return empty placeholders that panic on use, so a
//! runtime feature flag **must** be active in practice.
//!
//! [tokio]: https://docs.rs/tokio
//! [compio]: https://docs.rs/compio

#[cfg(unix)]
use std::path::Path;
use std::{
    future::Future,
    net::{SocketAddr, TcpStream},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

#[cfg(unix)]
use wreq_rt::rt::Connecting;
use wreq_rt::rt::{
    self, Connector, Resolver, Resolving,
    timer::{Sleep, Timer},
};

/// A heap-allocated, type-erased future that is [`Send`] and resolves to `()`.
///
/// This is the concrete future type passed to [`rt::Executor::execute`] by the
/// client's background task machinery.  Callers do not need to construct this
/// type directly; the [`rt::Executor<F>`] blanket implementation boxes and
/// pins any qualifying `F` automatically.
pub type BoxSendFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub trait Runtime<Fut>:
    rt::Executor<Fut> + Timer + Connector + Resolver + Send + Sync + 'static
{
}

impl<T, Fut> Runtime<Fut> for T where
    T: rt::Executor<Fut> + Timer + Connector + Resolver + Send + Sync + 'static
{
}

/// A handle to an async task executor.
///
/// `Executor` is used by the HTTP client to spawn background tasks such as
/// connection-pool cleanup and keep-alive management, without coupling the
/// client to a specific async runtime.
///
/// # Default behavior
///
/// [`Executor::default`] picks the runtime-appropriate implementation based
/// on the active feature flags:
///
/// | Feature flags active              | Executor          |
/// |-----------------------------------|-------------------|
/// | `tokio-rt` only                   | `TokioExecutor`   |
/// | `compio-rt` only                  | `CompioExecutor`  |
/// | both `tokio-rt` and `compio-rt`   | `TokioExecutor`   |
/// | neither                           | empty (panics)    |
#[derive(Clone)]
pub struct Executor(Arc<dyn Runtime<BoxSendFuture>>);

impl Executor {
    /// Creates an [`Executor`] backed by a custom implementation.
    #[inline]
    pub fn new<E>(exec: E) -> Self
    where
        E: Runtime<BoxSendFuture>,
    {
        Executor(Arc::new(exec))
    }
}

impl<Fut> rt::Executor<Fut> for Executor
where
    Fut: Future<Output = ()> + Send + 'static,
{
    /// Place the future into the executor to be run.
    #[track_caller]
    #[inline(always)]
    fn execute(&self, fut: Fut) {
        self.0.execute(Box::pin(fut))
    }
}

impl Resolver for Executor {
    /// Performs a DNS resolution.
    #[track_caller]
    #[inline(always)]
    fn lookup(&self, host: Box<str>) -> Resolving {
        self.0.lookup(host)
    }
}

impl Timer for Executor {
    /// Returns a future that resolves after `duration`.
    #[inline]
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        self.0.sleep(duration)
    }

    /// Returns the current time according to the underlying runtime.
    #[inline]
    fn now(&self) -> Instant {
        self.0.now()
    }

    /// Returns a future that resolves at `deadline`.
    #[inline]
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        self.0.sleep_until(deadline)
    }

    /// Resets an in-flight sleep future to fire at `new_deadline` instead.
    #[inline]
    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        self.0.reset(sleep, new_deadline)
    }
}

impl Connector for Executor {
    /// Establish a TCP connection from the given socket to the address.
    #[inline(always)]
    fn tcp_connect(&self, socket: TcpStream, addr: SocketAddr) -> Connecting {
        self.0.tcp_connect(socket, addr)
    }

    /// Establish a Unix domain socket connection to the given path.
    #[cfg(unix)]
    #[inline(always)]
    fn unix_connect(&self, path: Arc<Path>) -> Connecting {
        self.0.unix_connect(path)
    }
}

impl Default for Executor {
    #[inline]
    fn default() -> Self {
        if_tokio_rt!(block: {
            return Executor(Arc::new(wreq_rt::rt::tokio::TokioRuntime::new()))
        });

        if_compio_rt!(block: {
            return Executor(Arc::new(wreq_rt::rt::compio::CompioRuntime::new()))
        });

        if_all_rt!(block: {
            return Executor(Arc::new(wreq_rt::rt::tokio::TokioRuntime::new()))
        });

        if_no_rt!(block:{
            panic!(
                "no async runtime feature enabled; at least one of `tokio-rt` or `compio-rt` must be active"
            );
        });
    }
}
