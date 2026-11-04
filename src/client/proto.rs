//! Adapts established transports into protocol request senders.
//!
//! The HTTP/1 and optional HTTP/2 layers handshake established streams.
//! With the `http3` feature, the HTTP/3 connection service establishes
//! QUIC and performs its handshake. The pool composes these Tower services with reuse.
//!
//! A successful handshake starts the protocol driver and returns a sender with
//! the connection metadata needed by request preparation and pool health checks.

pub(super) mod http1;
#[cfg(feature = "http2")]
pub(super) mod http2;
#[cfg(feature = "http3")]
pub(super) mod http3;

#[cfg(any(feature = "http2", feature = "http3"))]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use http::Request;
use netty::conn::TrySendError;

use super::{
    error::{Error, ErrorKind},
    pool::ConnectionConfig,
};
#[cfg(feature = "http2")]
use crate::Protocol;
use crate::conn::Connected;
#[cfg(any(feature = "http2", feature = "http3"))]
use crate::sync::Mutex;

/// Physical transport and request-specific protocol configuration.
///
/// Connection making creates this value before protocol negotiation. The
/// selected handshake consumes it exactly once and transfers the transport to
/// the resulting protocol driver. Configuration stays shared until that
/// handshake applies the selected protocol's overrides.
pub(super) struct Established<T> {
    io: T,
    connected: Connected,
    #[cfg(feature = "http2")]
    protocol: Protocol,
    config: ConnectionConfig,
    #[cfg(feature = "http2")]
    idle_at: Instant,
}

/// Error returned while preparing or dispatching a protocol request.
///
/// Local failures, including HTTP/1 request preparation and sender readiness,
/// carry no request for retry. Protocol failures preserve netty's optional
/// unsent request so the outer client can retry only when encoding did not
/// begin.
#[derive(Debug)]
pub enum SendError<B> {
    Request(Error),
    Protocol(Box<TrySendError<Request<B>>>),
}

/// Shared checkout state for one HTTP/2 or HTTP/3 connection.
/// Accounting ends at response headers or checkout cancellation, not stream end.
/// Bodies and extended `CONNECT` upgrades do not hold this checkout state.
#[cfg(any(feature = "http2", feature = "http3"))]
struct ConnectionState {
    checkouts: AtomicUsize,
    idle_at: Mutex<Instant>,
}

// ===== impl ConnectionState =====

#[cfg(any(feature = "http2", feature = "http3"))]
impl ConnectionState {
    /// Creates idle checkout state for a newly established connection.
    pub(super) fn new(idle_at: Instant) -> Self {
        Self {
            checkouts: AtomicUsize::new(0),
            idle_at: Mutex::new(idle_at),
        }
    }

    /// Registers one sender checkout.
    pub(super) fn acquire(&self) {
        let _ = self
            .checkouts
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_add(1))
            });
    }

    /// Releases one checkout and records the final release time.
    pub(super) fn release(&self, now: Instant) -> bool {
        let mut checkouts = self.checkouts.load(Ordering::Acquire);

        loop {
            match checkouts {
                0 => return false,
                1 => {
                    let mut idle_at = self.idle_at.lock();
                    match self.checkouts.compare_exchange_weak(
                        1,
                        0,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            // Cleanup that observes zero must also observe this timestamp.
                            *idle_at = now;
                            return true;
                        }
                        Err(actual) => {
                            drop(idle_at);
                            checkouts = actual;
                        }
                    }
                }
                count => match self.checkouts.compare_exchange_weak(
                    count,
                    count - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return false,
                    Err(actual) => checkouts = actual,
                },
            }
        }
    }

    /// Returns whether no sender checkout is active.
    pub(super) fn is_idle(&self) -> bool {
        self.checkouts.load(Ordering::Acquire) == 0
    }

    /// Returns the last time the final checkout was released.
    pub(super) fn idle_at(&self) -> Instant {
        *self.idle_at.lock()
    }
}

// ===== impl Established =====

impl<T> Established<T> {
    /// Creates the protocol-neutral output of a physical connector.
    pub(super) fn new(
        io: T,
        connected: Connected,
        #[cfg(feature = "http2")] protocol: Protocol,
        config: ConnectionConfig,
        #[cfg(feature = "http2")] idle_at: Instant,
    ) -> Self {
        Self {
            io,
            connected,
            #[cfg(feature = "http2")]
            protocol,
            config,
            #[cfg(feature = "http2")]
            idle_at,
        }
    }

    /// Returns when this transport became available for protocol selection.
    #[cfg(feature = "http2")]
    pub(super) fn idle_at(&self) -> Instant {
        self.idle_at
    }

    /// Chooses HTTP/2 when requested explicitly or negotiated by the transport.
    #[cfg(feature = "http2")]
    pub(super) fn should_use_http2(&self) -> bool {
        self.protocol == Protocol::Http2
            || (self.protocol == Protocol::Auto && self.connected.is_negotiated_h2())
    }
}

// ===== impl SendError =====

impl<B> From<Error> for SendError<B> {
    fn from(error: Error) -> Self {
        Self::Request(error)
    }
}

impl<B> SendError<B> {
    /// Boxes a protocol failure that may carry the complete unsent request.
    pub(super) fn protocol(error: TrySendError<Request<B>>) -> Self {
        Self::Protocol(Box::new(error))
    }

    /// Returns whether the protocol rejected the request itself; such a failure repeats
    /// on the same connection, so the returned request must not be retried.
    pub fn is_user(&self) -> bool {
        matches!(self, Self::Protocol(error) if error.error().is_user())
    }

    /// Takes a request recovered before protocol encoding began.
    pub fn take_message(&mut self) -> Option<Request<B>> {
        match self {
            Self::Request(_) => None,
            Self::Protocol(error) => error.take_message(),
        }
    }

    /// Preserves local errors and assigns `kind` to protocol failures.
    pub fn into_client_error(self, kind: ErrorKind) -> Error {
        match self {
            Self::Request(error) => error,
            Self::Protocol(error) => Error::new(kind, (*error).into_error()),
        }
    }
}

/// Returns whether an idle timestamp exceeds the configured timeout.
fn is_expired(idle_at: Instant, now: Instant, timeout: Option<Duration>) -> bool {
    timeout.is_some_and(|timeout| now.saturating_duration_since(idle_at) > timeout)
}
