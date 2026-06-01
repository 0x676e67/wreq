//! Runtime glue for the client.
//!
//! This module defines [`RuntimeHandle`], a small wrapper around the runtime
//! traits the client needs for spawning tasks, sleeping, opening sockets, and
//! DNS.
//!
//! # Feature flags
//!
//! At least one of the following features must be enabled:
//!
//! - `tokio-rt` — uses [tokio] as the underlying runtime (default).
//! - `compio-rt` — uses [compio] as the underlying runtime.
//!
//! When both are enabled, `tokio-rt` wins. When neither is enabled,
//! [`RuntimeHandle::default`] panics.
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

use wreq_rt::{
    Executor,
    conn::{Connecting, Connector},
    dns::{DnsResolver, Resolving},
    timer::{Sleep, Timer},
};

/// A boxed `Send` future that resolves to `()`.
///
/// This is the concrete task type passed into [`Executor::execute`].
pub type BoxSendFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Runtime capabilities required by [`RuntimeHandle`].
pub trait Runtime<Fut>:
    Executor<Fut> + Timer + Connector + DnsResolver + Send + Sync + 'static
{
}

/// A shared runtime handle used by the client.
///
/// Besides spawning background work, it also forwards timer, connector, and
/// dns resolver calls to the selected runtime.
///
/// # Default behavior
///
/// [`RuntimeHandle::default`] picks a backend from the active feature flags:
///
/// | Feature flags active            | Backend         |
/// |---------------------------------|-----------------|
/// | `tokio-rt` only                 | `TokioRuntime`  |
/// | `compio-rt` only                | `CompioRuntime` |
/// | both `tokio-rt` and `compio-rt` | `TokioRuntime`  |
/// | neither                         | panic           |
#[derive(Clone)]
pub(crate) struct RuntimeHandle(Arc<dyn Runtime<BoxSendFuture>>);

// ===== impl Runtime =====

impl<T, Fut> Runtime<Fut> for T where
    T: Executor<Fut> + Timer + Connector + DnsResolver + Send + Sync + 'static
{
}

// ===== impl RuntimeHandle =====

impl RuntimeHandle {
    /// Creates a [`RuntimeHandle`] from a custom runtime.
    #[inline]
    pub fn new<R>(runtime: R) -> Self
    where
        R: Runtime<BoxSendFuture>,
    {
        RuntimeHandle(Arc::new(runtime))
    }
}

impl<Fut> Executor<Fut> for RuntimeHandle
where
    Fut: Future<Output = ()> + Send + 'static,
{
    /// Spawns the future on the underlying runtime.
    #[track_caller]
    #[inline(always)]
    fn execute(&self, fut: Fut) {
        self.0.execute(Box::pin(fut))
    }
}

impl DnsResolver for RuntimeHandle {
    /// Resolves a host name.
    #[track_caller]
    #[inline(always)]
    fn resolve(&self, host: Box<str>) -> Resolving {
        self.0.resolve(host)
    }
}

impl Timer for RuntimeHandle {
    /// Returns a sleep future for `duration`.
    #[inline]
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        self.0.sleep(duration)
    }

    /// Returns the runtime's current time.
    #[inline]
    fn now(&self) -> Instant {
        self.0.now()
    }

    /// Returns a sleep future that completes at `deadline`.
    #[inline]
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        self.0.sleep_until(deadline)
    }

    /// Resets an existing sleep future to `new_deadline`.
    #[inline]
    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        self.0.reset(sleep, new_deadline)
    }
}

impl Connector for RuntimeHandle {
    /// Connects the given TCP socket to `addr`.
    #[inline(always)]
    fn tcp_connect(&self, socket: TcpStream, addr: SocketAddr) -> Connecting {
        self.0.tcp_connect(socket, addr)
    }

    /// Connects to the Unix socket at `path`.
    #[cfg(unix)]
    #[inline(always)]
    fn unix_connect(&self, path: Arc<Path>) -> Connecting {
        self.0.unix_connect(path)
    }
}

impl Default for RuntimeHandle {
    #[inline]
    fn default() -> Self {
        if_tokio_rt!(block: {
            return RuntimeHandle(Arc::new(wreq_rt::tokio::TokioRuntime::new()))
        });

        if_compio_rt!(block: {
            return RuntimeHandle(Arc::new(wreq_rt::compio::CompioRuntime::new()))
        });

        if_all_rt!(block: {
            return RuntimeHandle(Arc::new(wreq_rt::tokio::TokioRuntime::new()))
        });

        if_no_rt!(block:{
            panic!(
                "no async runtime feature enabled; at least one of `tokio-rt` or `compio-rt` must be active"
            );
        });
    }
}
