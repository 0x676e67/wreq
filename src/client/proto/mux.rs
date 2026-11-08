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
use http::{Request, Response, Version};
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
/// state counts sender checkouts, and netty reports which exchanges are live.
#[derive(Clone)]
pub struct Connection {
    tx: Sender,
    state: Arc<ConnectionState>,
    connected: Connected,
    runtime: DynRuntime,
}

/// Checkout state shared by every clone of one [`Connection`].
/// A checkout ends at response headers or cancellation; bodies and extended `CONNECT`
/// tunnels are tracked by netty instead. `idle_at` is when the connection was last in use.
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

    /// Returns the HTTP version spoken by the protocol sender.
    pub fn version(&self) -> Version {
        match &self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(_) => Version::HTTP_2,
            #[cfg(feature = "http3")]
            Sender::Http3(_) => Version::HTTP_3,
        }
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

    /// Returns whether netty reports no live exchange: no response awaited, body unread,
    /// request body sending or `CONNECT` tunnel open.
    pub fn is_idle(&self) -> bool {
        match &self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(tx) => tx.is_idle(),
            #[cfg(feature = "http3")]
            Sender::Http3(tx) => tx.is_idle(),
        }
    }

    /// Returns whether a checkout is active or netty reports a live exchange.
    pub fn is_in_use(&self) -> bool {
        self.state.has_checkouts() || !self.is_idle()
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
    ///
    /// A connection in use never idle-expires. With no busy-to-idle signal, seeing it in use
    /// moves `idle_at` to `now`, so idle time counts from when it was last seen in use.
    pub fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        if self.connected.poisoned() || self.is_closed() {
            return false;
        }
        if self.is_in_use() {
            self.state.touch(now);
            return true;
        }
        !is_expired(self.state.idle_at(), now, timeout)
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

    /// Returns whether a sender checkout is active.
    fn has_checkouts(&self) -> bool {
        self.checkouts.load(Ordering::Acquire) != 0
    }

    /// Moves the idle start to `now` for a connection seen in use, never backwards.
    fn touch(&self, now: Instant) {
        let mut idle_at = self.idle_at.lock();
        *idle_at = (*idle_at).max(now);
    }

    /// Returns when the connection was last released or seen in use.
    fn idle_at(&self) -> Instant {
        *self.idle_at.lock()
    }
}
