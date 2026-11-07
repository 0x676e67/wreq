//! Shared sender and checkout state for multiplexed HTTP/2 and HTTP/3 connections.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures_util::{TryFutureExt, future::BoxFuture};
use http::{Request, Response};
use netty::{body::Incoming, conn};
use tower::Service;

use super::{SendError, is_expired};
use crate::{
    Body,
    client::error::Error,
    conn::Connected,
    rt::{DynRuntime, Timer as _},
    sync::Mutex,
};

/// Protocol request sender of one multiplexed connection.
#[derive(Clone)]
pub enum Sender {
    #[cfg(feature = "http2")]
    Http2(conn::http2::SendRequest<Body>),
    #[cfg(feature = "http3")]
    Http3(conn::http3::SendRequest<Body>),
}

/// Cloneable request-side handle for one HTTP/2 or HTTP/3 connection.
///
/// The pool singleton stores one instance and gives each checkout a sender
/// clone. Protocol stream availability remains owned by netty; the local
/// state records sender checkout only and is not an active-stream count.
#[derive(Clone)]
pub struct Connection {
    tx: Sender,
    state: Arc<ConnectionState>,
    connected: Connected,
    runtime: DynRuntime,
}

/// Checkout state shared by every clone of one [`Connection`].
/// Accounting ends at response headers or checkout cancellation, not stream end.
/// Bodies and extended `CONNECT` upgrades do not hold this checkout state.
struct ConnectionState {
    checkouts: AtomicUsize,
    idle_at: Mutex<Instant>,
}

// ===== impl Connection =====

impl Connection {
    /// Wraps a handshaken sender whose connection driver is already running.
    pub(super) fn new(tx: Sender, connected: Connected, runtime: DynRuntime) -> Self {
        Self {
            tx,
            state: Arc::new(ConnectionState::new(runtime.now())),
            connected,
            runtime,
        }
    }

    /// Returns metadata for the underlying transport.
    pub fn connected(&self) -> &Connected {
        &self.connected
    }

    /// Returns whether the protocol sender is immediately ready.
    pub fn is_ready(&self) -> bool {
        match &self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(tx) => tx.is_ready(),
            #[cfg(feature = "http3")]
            Sender::Http3(tx) => tx.is_ready(),
        }
    }

    /// Returns whether the protocol sender has closed.
    pub fn is_closed(&self) -> bool {
        match &self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(tx) => tx.is_closed(),
            #[cfg(feature = "http3")]
            Sender::Http3(tx) => tx.is_closed(),
        }
    }

    /// Returns whether the peer enabled extended CONNECT, or `None` before its SETTINGS.
    pub fn extended_connect(&self) -> Option<bool> {
        match &self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(tx) => tx.is_extended_connect_protocol_enabled(),
            #[cfg(feature = "http3")]
            Sender::Http3(tx) => tx.is_extended_connect_protocol_enabled(),
        }
    }

    /// Marks the shared sender checked out until response headers are returned.
    pub fn begin_checkout(&self) {
        self.state.acquire();
    }

    /// Ends response-header checkout and records when its count reaches zero.
    pub fn finish_checkout(&self) {
        let _ = self.state.release(self.runtime.now());
    }

    /// Returns whether the shared sender is healthy and reusable.
    pub fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        // TODO(task 9): Replace checkout-only idleness with a full-stream lease
        // after netty can observe both request and response endpoints,
        // including HTTP/2 extended CONNECT. Peer max-stream counts alone do
        // not expose local occupancy: https://github.com/hyperium/hyper/issues/3623
        !self.connected.poisoned()
            && !self.is_closed()
            && (!self.state.is_idle() || !is_expired(self.state.idle_at(), now, timeout))
    }
}

impl Service<Request<Body>> for Connection {
    type Response = Response<Incoming>;
    type Error = SendError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        let ready = match &mut self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(tx) => tx.poll_ready(cx),
            #[cfg(feature = "http3")]
            Sender::Http3(tx) => tx.poll_ready(cx),
        };
        if matches!(ready, Poll::Ready(Err(_))) {
            self.connected.poison();
        }
        ready.map_err(|error| SendError::Request(Error::closed(error)))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        match &mut self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(tx) => Box::pin(tx.try_send_request(req).map_err(SendError::protocol)),
            #[cfg(feature = "http3")]
            Sender::Http3(tx) => Box::pin(tx.try_send_request(req).map_err(SendError::protocol)),
        }
    }
}

// ===== impl ConnectionState =====

impl ConnectionState {
    /// Creates idle checkout state for a newly established connection.
    fn new(idle_at: Instant) -> Self {
        Self {
            checkouts: AtomicUsize::new(0),
            idle_at: Mutex::new(idle_at),
        }
    }

    /// Registers one sender checkout.
    fn acquire(&self) {
        let _ = self
            .checkouts
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_add(1))
            });
    }

    /// Releases one checkout and records the final release time.
    fn release(&self, now: Instant) -> bool {
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
    fn is_idle(&self) -> bool {
        self.checkouts.load(Ordering::Acquire) == 0
    }

    /// Returns the last time the final checkout was released.
    fn idle_at(&self) -> Instant {
        *self.idle_at.lock()
    }
}
