//! Connection observation for debugging and recording traffic.
//!
//! A [`ConnectionObserver`] set with
//! [`ClientBuilder::connection_observer`](crate::ClientBuilder::connection_observer) sees two
//! layers of every connection the client opens:
//!
//! - TLS records of each handshake as they appear on the transport, including the ClientHello that
//!   JA3/JA4 fingerprints are computed from.
//! - Plaintext above TLS and below the HTTP codec: HTTP/1 messages or HTTP/2 frames.
//!
//! CONNECT and SOCKS exchanges with a proxy are not reported.

use std::{
    fmt, io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::tls::TlsVersion;

/// Receives events from the connections of a client.
///
/// Callbacks run synchronously on the I/O task and must not block. A shared observer may receive
/// concurrent callbacks from different connections, while the events of one connection arrive in
/// transport order. Borrowed bytes and errors are valid only during the call. Events may contain
/// credentials and other secrets.
///
/// A panic from [`ConnectionEvent::Closed`] is caught and discarded because it may be reported
/// during unwinding; panics from other events propagate to the I/O task.
pub trait ConnectionObserver: Send + Sync {
    /// Observes one connection event.
    fn observe(&self, event: ConnectionEvent<'_>);
}

impl_into_shared!(
    /// Trait for converting types into a shared [`ConnectionObserver`].
    ///
    /// This allows accepting bare types, `Arc<T>`, or `Arc<dyn ConnectionObserver>`.
    pub trait IntoConnectionObserver => ConnectionObserver
);

/// Identifies one connection within this process.
///
/// Responses served over an observed connection carry its id in their extensions, linking a
/// response to the events of its connection. Pooled connections and HTTP/2 multiplexing let
/// several responses share one id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(u64);

/// One event of an observed connection.
///
/// A connection reports [`TlsHandshake`](Self::TlsHandshake) and the records of each TLS
/// handshake, then [`Connected`](Self::Connected) and its plaintext I/O, and finally
/// [`Closed`](Self::Closed). An attempt that fails before it becomes usable ends with `Closed`
/// and no `Connected`.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectionEvent<'a> {
    /// A TLS handshake is starting.
    ///
    /// Through an HTTPS proxy, an HTTPS origin connection performs two handshakes: first with the
    /// proxy, then with the origin inside the tunnel. The last handshake before `Connected`
    /// secures the plaintext that follows.
    #[non_exhaustive]
    TlsHandshake {
        /// Connection identifier.
        id: ConnectionId,
        /// Host the handshake is performed for.
        host: &'a str,
    },
    /// TLS records written during a handshake.
    #[non_exhaustive]
    TlsWrite {
        /// Connection identifier.
        id: ConnectionId,
        /// Record bytes as written to the transport.
        bytes: &'a [u8],
    },
    /// TLS records read during a handshake.
    #[non_exhaustive]
    TlsRead {
        /// Connection identifier.
        id: ConnectionId,
        /// Record bytes as read from the transport.
        bytes: &'a [u8],
    },
    /// The connection is ready, before any plaintext is transferred.
    #[non_exhaustive]
    Connected {
        /// Connection identifier.
        id: ConnectionId,
        /// Local socket address, when available.
        local_addr: Option<SocketAddr>,
        /// Remote socket address, when available; the proxy's when one is used.
        remote_addr: Option<SocketAddr>,
        /// Negotiated ALPN protocol, such as `b"h2"`.
        alpn: Option<&'a [u8]>,
        /// Negotiated TLS version; `None` for plaintext transports.
        tls_version: Option<TlsVersion>,
    },
    /// Plaintext read from the connection, excluding bytes already in the read buffer.
    #[non_exhaustive]
    Read {
        /// Connection identifier.
        id: ConnectionId,
        /// Plaintext bytes.
        bytes: &'a [u8],
    },
    /// Plaintext accepted by the connection, which does not imply delivery to the peer.
    #[non_exhaustive]
    Write {
        /// Connection identifier.
        id: ConnectionId,
        /// Plaintext bytes.
        bytes: &'a [u8],
    },
    /// A read with free buffer capacity returned no bytes.
    #[non_exhaustive]
    Eof {
        /// Connection identifier.
        id: ConnectionId,
    },
    /// A plaintext read failed.
    #[non_exhaustive]
    ReadError {
        /// Connection identifier.
        id: ConnectionId,
        /// The transport error.
        error: &'a io::Error,
    },
    /// A plaintext write failed.
    #[non_exhaustive]
    WriteError {
        /// Connection identifier.
        id: ConnectionId,
        /// The transport error.
        error: &'a io::Error,
    },
    /// Flushing the connection failed.
    #[non_exhaustive]
    FlushError {
        /// Connection identifier.
        id: ConnectionId,
        /// The transport error.
        error: &'a io::Error,
    },
    /// Shutting down the write side of the connection failed.
    #[non_exhaustive]
    ShutdownError {
        /// Connection identifier.
        id: ConnectionId,
        /// The transport error.
        error: &'a io::Error,
    },
    /// The connection or failed attempt was released; no further events follow.
    #[non_exhaustive]
    Closed {
        /// Connection identifier.
        id: ConnectionId,
    },
}

// ===== impl ConnectionId =====

impl ConnectionId {
    /// Allocates the next process-wide identifier.
    pub(crate) fn next() -> ConnectionId {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        ConnectionId(NEXT.fetch_add(1, Ordering::Relaxed))
    }

    /// Returns the numeric value of this identifier.
    #[inline]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// ===== impl ConnectionEvent =====

impl ConnectionEvent<'_> {
    /// Returns the connection this event belongs to.
    pub fn id(&self) -> ConnectionId {
        match *self {
            ConnectionEvent::TlsHandshake { id, .. }
            | ConnectionEvent::TlsWrite { id, .. }
            | ConnectionEvent::TlsRead { id, .. }
            | ConnectionEvent::Connected { id, .. }
            | ConnectionEvent::Read { id, .. }
            | ConnectionEvent::Write { id, .. }
            | ConnectionEvent::Eof { id }
            | ConnectionEvent::ReadError { id, .. }
            | ConnectionEvent::WriteError { id, .. }
            | ConnectionEvent::FlushError { id, .. }
            | ConnectionEvent::ShutdownError { id, .. }
            | ConnectionEvent::Closed { id } => id,
        }
    }
}
