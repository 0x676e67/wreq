//! Adapts established transports into protocol request senders.
//!
//! The HTTP/1 and optional HTTP/2 layers handshake established streams.
//! With the `http3` feature, the HTTP/3 connection service establishes
//! QUIC and performs its handshake. The pool composes these Tower services with reuse.
//!
//! A successful handshake starts the protocol driver and returns a sender with
//! the connection metadata needed by request preparation and pool health checks.
//! HTTP/2 and HTTP/3 share one multiplexed sender type in `mux`.

pub(super) mod http1;
#[cfg(feature = "http2")]
pub(super) mod http2;
#[cfg(feature = "http3")]
pub(super) mod http3;
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) mod mux;

use std::time::{Duration, Instant};

use http::Request;
use netty::conn::TrySendError;

use super::error::{Error, ErrorKind};
use crate::{
    Body,
    conn::{Connected, Io},
};

/// Physical byte stream and its transport metadata.
///
/// Connection making creates this value before protocol negotiation. The
/// selected handshake consumes it exactly once and transfers the stream to
/// the resulting protocol driver.
pub(super) struct Established {
    io: Box<dyn Io>,
    connected: Connected,
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
pub enum SendError {
    Request(Error),
    Protocol(Box<TrySendError<Request<Body>>>),
}

// ===== impl Established =====

impl Established {
    /// Creates the protocol-neutral output of a physical connector.
    pub(super) fn new(
        io: Box<dyn Io>,
        connected: Connected,
        #[cfg(feature = "http2")] idle_at: Instant,
    ) -> Self {
        Self {
            io,
            connected,
            #[cfg(feature = "http2")]
            idle_at,
        }
    }

    /// Returns metadata for the transport, including its negotiated ALPN.
    #[cfg(feature = "http2")]
    pub(super) fn connected(&self) -> &Connected {
        &self.connected
    }

    /// Returns when this transport became available for protocol selection.
    #[cfg(feature = "http2")]
    pub(super) fn idle_at(&self) -> Instant {
        self.idle_at
    }
}

// ===== impl SendError =====

impl From<Error> for SendError {
    fn from(error: Error) -> Self {
        Self::Request(error)
    }
}

impl SendError {
    /// Boxes a protocol failure that may carry the complete unsent request.
    pub(super) fn protocol(error: TrySendError<Request<Body>>) -> Self {
        Self::Protocol(Box::new(error))
    }

    /// Returns whether the protocol rejected the request itself; such a failure repeats
    /// on the same connection, so the returned request must not be retried.
    pub fn is_user(&self) -> bool {
        matches!(self, Self::Protocol(error) if error.error().is_user())
    }

    /// Takes a request recovered before protocol encoding began.
    pub fn take_message(&mut self) -> Option<Request<Body>> {
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
pub(super) fn is_expired(idle_at: Instant, now: Instant, timeout: Option<Duration>) -> bool {
    timeout.is_some_and(|timeout| now.saturating_duration_since(idle_at) > timeout)
}
