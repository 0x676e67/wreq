//! Adapts established transports into protocol request senders.
//!
//! [`http1::Http1Layer`] and [`http2::Http2Layer`] place protocol handshakes
//! behind Tower services. The pool can therefore compose connection making,
//! protocol negotiation, and reuse without owning handshake state machines
//! itself.
//!
//! A successful handshake starts the protocol driver and returns a sender with
//! the connection metadata needed by request middleware and pool health checks.

pub(super) mod http1;
pub(super) mod http2;

use std::time::{Duration, Instant};

use http::Request;
use wreq_proto::{
    conn::{self, TrySendError},
    rt::Timer as _,
};

use super::{
    error::{Error, ErrorKind},
    pool::Ver,
};
use crate::{
    conn::Connected,
    rt::{Executor, Timer},
};

/// Physical transport and request-specific protocol configuration.
///
/// Connection making creates this value before protocol negotiation. The
/// selected handshake consumes it exactly once and transfers the transport to
/// the resulting protocol driver.
pub(super) struct Established<T> {
    /// Connected transport stream.
    io: T,

    /// Metadata supplied by the connector.
    connected: Connected,

    /// Requested protocol mode.
    version: Ver,

    /// HTTP/1 configuration supplied by this connection attempt.
    h1_builder: conn::http1::Builder,

    /// HTTP/2 configuration supplied by this connection attempt.
    h2_builder: conn::http2::Builder<Executor>,

    /// Time the transport became available for handshake.
    idle_at: Instant,
}

/// Error returned while preparing or dispatching a protocol request.
///
/// Preparation failures originate in the HTTP/1 request middleware and never
/// carry a request for retry. Protocol failures preserve wreq-proto's optional
/// unsent request so the outer client can retry only when encoding did not
/// begin.
#[derive(Debug)]
pub enum SendError<B> {
    /// Request middleware rejected the request before protocol dispatch.
    Request(Error),
    /// The protocol dispatcher failed and may return the unsent request.
    Protocol(Box<TrySendError<Request<B>>>),
}

// ===== impl Established =====

impl<T> Established<T> {
    /// Creates the protocol-neutral output of a physical connector.
    pub(super) fn new(
        io: T,
        connected: Connected,
        version: Ver,
        h1_builder: conn::http1::Builder,
        h2_builder: conn::http2::Builder<Executor>,
        idle_at: Instant,
    ) -> Self {
        Self {
            io,
            connected,
            version,
            h1_builder,
            h2_builder,
            idle_at,
        }
    }

    /// Returns when this transport became available for protocol selection.
    pub(super) fn idle_at(&self) -> Instant {
        self.idle_at
    }

    /// Chooses HTTP/2 when requested explicitly or negotiated by the transport.
    pub(super) fn should_use_http2(&self) -> bool {
        self.version == Ver::Http2
            || (self.version != Ver::Http1 && self.connected.is_negotiated_h2())
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
    fn protocol(error: TrySendError<Request<B>>) -> Self {
        Self::Protocol(Box::new(error))
    }

    /// Takes a request recovered before protocol encoding began.
    pub fn take_message(&mut self) -> Option<Request<B>> {
        match self {
            Self::Request(_) => None,
            Self::Protocol(error) => error.take_message(),
        }
    }

    /// Converts the failure into the requested client error category.
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

/// Reads the configured runtime clock, falling back to the system clock.
fn clock_now(timer: &Timer) -> Instant {
    if timer.is_empty() {
        Instant::now()
    } else {
        timer.now()
    }
}
