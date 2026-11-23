//! Shared sender and checkout state for multiplexed HTTP/2 and HTTP/3 connections.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures_util::TryFutureExt;
#[cfg(all(feature = "http2", feature = "http3"))]
use futures_util::future::Either;
use http::{Request, Response, Version};
use netty::{body::Incoming, conn};

use super::SendError;
use crate::{
    Body,
    client::error::Error,
    conn::Connected,
    rt::{DynRuntime, Timer as _},
};

/// Protocol request sender for a multiplexed HTTP/2 or HTTP/3 connection.
#[derive(Clone)]
pub enum Sender {
    #[cfg(feature = "http2")]
    Http2(conn::http2::SendRequest<Body>),
    #[cfg(feature = "http3")]
    Http3(conn::http3::SendRequest<Body>),
}

/// Cloneable request-side handle for a shared HTTP/2 or HTTP/3 connection.
///
/// The pool singleton stores one instance and gives each checkout a sender clone.
/// Netty drives the protocol streams independently of the checkout.
#[derive(Clone)]
pub struct Connection {
    /// Underlying HTTP/2 or HTTP/3 protocol sender.
    tx: Sender,
    /// Shared connection metadata, clock, and checkout accounting.
    state: Arc<ConnectionState>,
}

/// Connection metadata and checkout state shared by every sender clone.
///
/// Tracks active checkouts and the last return time in [`Leases`], even while streams
/// remain open after response headers arrive.
struct ConnectionState {
    /// Transport metadata and shared poison flag.
    connected: Connected,
    /// Runtime clock used to stamp idle time on final release.
    runtime: DynRuntime,
    /// Lock-free active checkout count and idle timestamp packed into one atomic word.
    leases: Leases,
}

/// Active checkout count and last-idle timestamp packed into a single atomic word.
///
/// The high bit distinguishes idle nanosecond offsets from active lease counts; bit 62
/// records deferred LRU tracking so `0 -> 1` and `1 -> 0` transitions remain lock-free.
struct Leases {
    /// Connection creation timestamp used as the zero origin for encoded idle times.
    epoch: Instant,
    /// Encodes either an idle nanosecond offset (`< ACTIVE`) or active count + flags.
    word: AtomicU64,
}

// ===== impl Connection =====

impl Connection {
    /// Wraps a handshaken sender whose connection driver is already running.
    #[must_use]
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

    /// Marks an active connection for deferred capacity tracking and returns `true`.
    ///
    /// Returns `false` if no checkout is active, allowing immediate eviction.
    #[must_use]
    pub(in crate::client) fn defer_until_idle(&self) -> bool {
        self.state.leases.defer_until_idle()
    }

    /// Checks health and idle expiry while acquiring the next checkout lease.
    ///
    /// Calls `defer_expiry` only when the connection is idle and past `expiry`, allowing
    /// callers to avoid reading pending-checkout counters on hot hits.
    #[must_use]
    pub(in crate::client) fn try_checkout(
        &self,
        expiry: Option<(Instant, Duration)>,
        defer_expiry: impl FnOnce() -> bool,
    ) -> bool {
        self.is_open() && self.state.leases.acquire(expiry, defer_expiry)
    }

    /// Marks the shared sender checked out until response headers are returned.
    #[inline(always)]
    pub fn begin_checkout(&self) {
        self.state.leases.register();
    }

    /// Ends a checkout, recording the idle time on the last release and returning
    /// whether deferred capacity tracking must run.
    #[must_use]
    #[inline(always)]
    pub fn finish_checkout(&self) -> bool {
        self.state.leases.release(|| self.state.runtime.now())
    }

    /// Returns whether the shared sender is healthy and reusable.
    ///
    /// Idle expiry starts when the final checkout ends.
    #[must_use]
    pub fn is_reusable(&self, expiry: Option<(Instant, Duration)>) -> bool {
        self.is_open() && self.state.leases.reusable(expiry)
    }

    /// Polls the multiplexed sender until it can accept a request, poisoning it on error.
    pub fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), SendError>> {
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

    /// Dispatches `req` over the shared HTTP/2 or HTTP/3 sender without boxing.
    pub fn send_request(
        &mut self,
        req: Request<Body>,
    ) -> impl Future<Output = Result<Response<Incoming>, SendError>> + use<> {
        cfg_select! {
            all(feature = "http2", feature = "http3") => match &mut self.tx {
                Sender::Http2(sender) => {
                    Either::Left(sender.try_send_request(req).map_err(SendError::protocol))
                }
                Sender::Http3(sender) => {
                    Either::Right(sender.try_send_request(req).map_err(SendError::protocol))
                }
            },
            feature = "http2" => match &mut self.tx {
                Sender::Http2(sender) => sender.try_send_request(req).map_err(SendError::protocol),
            },
            feature = "http3" => match &mut self.tx {
                Sender::Http3(sender) => sender.try_send_request(req).map_err(SendError::protocol),
            },
        }
    }
}

// ===== impl ConnectionState =====

impl ConnectionState {
    /// Stores the metadata and initializes the checkout state for a new connection.
    #[must_use]
    fn new(connected: Connected, runtime: DynRuntime) -> Self {
        let leases = Leases::new(runtime.now());
        Self {
            connected,
            runtime,
            leases,
        }
    }
}

// ===== impl Leases =====

impl Leases {
    // Unset high bit: idle time in nanoseconds since `epoch` (saturated to `MAX_IDLE`, ~292 years).
    // Set high bit: nonzero active lease count, with bit 62 reserved for deferred LRU tracking.
    const ACTIVE: u64 = 1 << 63;
    const DEFERRED: u64 = 1 << 62;
    const LAST: u64 = Self::ACTIVE | 1;
    const MAX_IDLE: u64 = Self::ACTIVE - 1;
    const MAX_COUNT: u64 = Self::DEFERRED - 1;

    /// Initializes an idle lease anchored at `epoch`.
    #[must_use]
    fn new(epoch: Instant) -> Self {
        Self {
            epoch,
            word: AtomicU64::new(0),
        }
    }

    /// Encodes `now` as saturated nanoseconds since `epoch` in the 63-bit idle range.
    #[inline]
    #[must_use]
    fn encode(&self, now: Instant) -> u64 {
        let nanos = now.saturating_duration_since(self.epoch).as_nanos();
        u64::try_from(nanos)
            .unwrap_or(Self::MAX_IDLE)
            .min(Self::MAX_IDLE)
    }

    /// Returns whether an encoded `idle` timestamp has exceeded `expiry`.
    #[inline]
    #[must_use]
    fn expired(&self, idle: u64, expiry: Option<(Instant, Duration)>) -> bool {
        expiry.is_some_and(|(now, timeout)| {
            now.saturating_duration_since(self.epoch)
                .checked_sub(timeout)
                .is_some_and(|cutoff| cutoff.as_nanos() > u128::from(idle))
        })
    }

    /// Reports whether the connection is active or has not exceeded `expiry`.
    #[must_use]
    fn reusable(&self, expiry: Option<(Instant, Duration)>) -> bool {
        let word = self.word.load(Ordering::Acquire);
        word >= Self::ACTIVE || !self.expired(word, expiry)
    }

    /// Checks idle expiry (calling `defer_expiry` only if expired) and registers one lease.
    #[must_use]
    fn acquire(
        &self,
        expiry: Option<(Instant, Duration)>,
        defer_expiry: impl FnOnce() -> bool,
    ) -> bool {
        let word = self.word.load(Ordering::Acquire);
        if word < Self::ACTIVE && self.expired(word, expiry) && !defer_expiry() {
            return false;
        }
        self.register();
        true
    }

    /// Registers a checked-out sender after the expiry snapshot has been accepted.
    fn register(&self) {
        self.word
            .update(Ordering::AcqRel, Ordering::Acquire, |word| {
                if word < Self::ACTIVE {
                    Self::LAST
                } else {
                    word + u64::from(word & Self::MAX_COUNT != Self::MAX_COUNT)
                }
            });
    }

    /// Marks an active lease with `DEFERRED` so the final release triggers capacity tracking.
    #[must_use]
    fn defer_until_idle(&self) -> bool {
        self.word
            .try_update(Ordering::AcqRel, Ordering::Acquire, |word| {
                (word >= Self::ACTIVE).then_some(word | Self::DEFERRED)
            })
            .is_ok()
    }

    /// Releases one checkout, sampling `now` only on the final release and returning
    /// whether that final release cleared a `DEFERRED` capacity-tracking mark.
    #[must_use]
    fn release(&self, mut now: impl FnMut() -> Instant) -> bool {
        let mut sampled = None;
        self.word
            .try_update(Ordering::AcqRel, Ordering::Acquire, |word| {
                if word < Self::ACTIVE {
                    None
                } else if word & !Self::DEFERRED == Self::LAST {
                    Some(self.encode(*sampled.get_or_insert_with(&mut now)))
                } else {
                    Some(word - 1)
                }
            })
            .is_ok_and(|prev| prev == (Self::LAST | Self::DEFERRED))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    use super::*;

    #[test]
    fn expiry_lazy_release_and_clock_clamping() {
        let epoch = Instant::now() + Duration::from_secs(1);
        let ns = Duration::from_nanos;
        let ttl = ns(20);
        let at = |now| Some((now, ttl));

        let leases = Leases::new(epoch);
        let deferred_calls = AtomicUsize::new(0);
        assert!(!leases.acquire(at(epoch + ns(21)), || {
            deferred_calls.fetch_add(1, Ordering::Relaxed);
            false
        }));
        assert_eq!(deferred_calls.load(Ordering::Relaxed), 1);

        // An unexpired idle connection must not evaluate `defer_expiry`.
        assert!(leases.acquire(at(epoch + ns(20)), || {
            deferred_calls.fetch_add(1, Ordering::Relaxed);
            false
        }));
        assert_eq!(deferred_calls.load(Ordering::Relaxed), 1);

        // Active checkouts skip expiry checks; non-final releases skip clock reads.
        assert!(leases.acquire(at(epoch + ns(32)), || {
            deferred_calls.fetch_add(1, Ordering::Relaxed);
            false
        }));
        assert_eq!(deferred_calls.load(Ordering::Relaxed), 1);

        let clock_reads = AtomicUsize::new(0);
        let release_at = epoch + ns(5);
        assert!(!leases.release(|| {
            clock_reads.fetch_add(1, Ordering::Relaxed);
            release_at
        }));
        assert_eq!(clock_reads.load(Ordering::Relaxed), 0);
        assert!(!leases.release(|| {
            clock_reads.fetch_add(1, Ordering::Relaxed);
            release_at
        }));
        assert_eq!(clock_reads.load(Ordering::Relaxed), 1);

        assert!(leases.reusable(at(release_at + ns(20))));
        assert!(!leases.reusable(at(release_at + ns(21))));
        assert!(!leases.acquire(at(release_at + ns(21)), || false));
        // `defer_expiry` rescues an expired idle connection.
        assert!(leases.acquire(at(release_at + ns(21)), || true));
        // A backwards clock clamps cleanly to `epoch` without setting `ACTIVE`.
        assert!(!leases.release(|| epoch - Duration::from_secs(1)));
        assert_eq!(leases.word.load(Ordering::Relaxed), 0);
        assert!(leases.reusable(at(epoch + ns(20))));
        assert!(!leases.reusable(at(epoch + ns(21))));

        // A concurrent final release after an accepted snapshot still registers cleanly.
        assert!(leases.acquire(at(epoch + ns(20)), || false));
        assert!(!leases.release(|| release_at));
        let after_expiry = release_at + ns(42);
        assert!(!leases.reusable(at(after_expiry)));
        leases.register();
        assert!(leases.reusable(at(after_expiry)));
        assert!(!leases.release(|| after_expiry));
    }

    #[test]
    fn deferred_eviction_is_visible_to_last_release() {
        let epoch = Instant::now() + Duration::from_secs(1);
        let now = epoch + Duration::from_nanos(1);
        let leases = Leases::new(epoch);
        for _ in 0..128 {
            assert!(leases.acquire(None, || false));
            let gate = Barrier::new(2);
            let (deferred, armed) = thread::scope(|scope| {
                let release = scope.spawn(|| {
                    gate.wait();
                    leases.release(|| now)
                });
                gate.wait();
                (leases.defer_until_idle(), release.join().unwrap())
            });
            assert_eq!(deferred, armed);
        }
    }
}
