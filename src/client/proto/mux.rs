//! Shared sender and checkout state for multiplexed HTTP/2 and HTTP/3 connections.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
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
/// The pool singleton stores one instance and gives each checkout a sender clone.
/// Netty drives the protocol streams independently of the checkout.
#[derive(Clone)]
pub struct Connection {
    tx: Sender,
    state: Arc<ConnectionState>,
}

/// Connection metadata and checkout state shared by every sender clone.
///
/// `idle_at` records when the last checkout ended, even if streams remain open.
struct ConnectionState {
    connected: Connected,
    runtime: DynRuntime,
    checkouts: AtomicUsize,
    idle_at: Mutex<Instant>,
}

// ===== impl Connection =====

impl Connection {
    /// Wraps a handshaken sender whose connection driver is already running.
    pub(super) fn new(tx: Sender, connected: Connected, runtime: DynRuntime) -> Self {
        Self {
            tx,
            state: Arc::new(ConnectionState::new(connected, runtime)),
        }
    }

    /// Returns metadata for the underlying transport.
    #[must_use]
    pub fn connected(&self) -> &Connected {
        &self.state.connected
    }

    /// Returns the HTTP version spoken by the protocol sender.
    #[must_use]
    pub fn version(&self) -> Version {
        match &self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(_) => Version::HTTP_2,
            #[cfg(feature = "http3")]
            Sender::Http3(_) => Version::HTTP_3,
        }
    }

    /// Returns whether the protocol sender is immediately ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        match &self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(tx) => tx.is_ready(),
            #[cfg(feature = "http3")]
            Sender::Http3(tx) => tx.is_ready(),
        }
    }

    /// Returns whether the protocol sender has closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        match &self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(tx) => tx.is_closed(),
            #[cfg(feature = "http3")]
            Sender::Http3(tx) => tx.is_closed(),
        }
    }

    /// Returns whether the shared sender is open and unpoisoned.
    #[must_use]
    pub(in crate::client) fn is_open(&self) -> bool {
        !self.connected().poisoned() && !self.is_closed()
    }

    /// Returns whether the peer enabled extended CONNECT, or `None` before its SETTINGS.
    #[must_use]
    pub fn extended_connect(&self) -> Option<bool> {
        match &self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(tx) => tx.is_extended_connect_protocol_enabled(),
            #[cfg(feature = "http3")]
            Sender::Http3(tx) => tx.is_extended_connect_protocol_enabled(),
        }
    }

    /// Returns whether any checkout still holds the shared sender.
    #[must_use]
    fn has_checkouts(&self) -> bool {
        self.state.checkouts.load(Ordering::Acquire) != 0
    }

    /// Sets `pending` and returns `true` if a checkout is active.
    /// The final release shares the lock so it can observe the flag.
    #[must_use]
    pub(in crate::client) fn defer_until_idle(&self, pending: &AtomicBool) -> bool {
        if !self.has_checkouts() {
            return false;
        }

        // The last release may have finished before we acquired the lock.
        let _idle_at = self.state.idle_at.lock();
        let checked_out = self.has_checkouts();
        if checked_out {
            pending.store(true, Ordering::Release);
        }
        checked_out
    }

    /// Marks the shared sender checked out until response headers are returned.
    #[inline(always)]
    pub fn begin_checkout(&self) {
        self.state.acquire();
    }

    /// Ends a checkout, returning `true` and recording the idle time on the last release.
    #[must_use]
    #[inline(always)]
    pub fn finish_checkout(&self) -> bool {
        self.state.release(self.state.runtime.now())
    }

    /// Returns whether the shared sender is healthy and reusable.
    ///
    /// Idle expiry starts when the final checkout ends.
    #[must_use]
    pub fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        self.is_open() && (self.has_checkouts() || !is_expired(self.state.idle_at(), now, timeout))
    }
}

impl Service<Request<Body>> for Connection {
    type Response = Response<Incoming>;
    type Error = SendError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        let ready = match &mut self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(sender) => sender.poll_ready(cx),
            #[cfg(feature = "http3")]
            Sender::Http3(sender) => sender.poll_ready(cx),
        };

        if matches!(ready, Poll::Ready(Err(_))) {
            self.connected().poison();
        }

        ready.map_err(|error| SendError::Request(Error::closed(error)))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        match &mut self.tx {
            #[cfg(feature = "http2")]
            Sender::Http2(sender) => {
                Box::pin(sender.try_send_request(req).map_err(SendError::protocol))
            }
            #[cfg(feature = "http3")]
            Sender::Http3(sender) => {
                Box::pin(sender.try_send_request(req).map_err(SendError::protocol))
            }
        }
    }
}

// ===== impl ConnectionState =====

impl ConnectionState {
    /// Stores the metadata and initializes the checkout state for a new connection.
    #[must_use]
    fn new(connected: Connected, runtime: DynRuntime) -> Self {
        let idle_at = runtime.now();
        Self {
            connected,
            runtime,
            checkouts: AtomicUsize::new(0),
            idle_at: Mutex::new(idle_at),
        }
    }

    /// Registers one sender checkout.
    fn acquire(&self) {
        self.checkouts
            .update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.saturating_add(1)
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

    /// Returns when the last checkout ended.
    #[must_use]
    fn idle_at(&self) -> Instant {
        *self.idle_at.lock()
    }
}
