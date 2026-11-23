//! Composable client connection pool, adapted from [hyper-util].
//!
//! [hyper-util]: https://docs.rs/hyper-util/latest/src/hyper_util/client/legacy/pool.rs.html
//!
//! The caller's key determines which connections can be reused. In `Auto` mode, existing or
//! in-flight HTTP/2 connections take priority before checking the HTTP/1 cache. New transports
//! negotiating `h2` run the HTTP/2 handshake; others fall back to HTTP/1 on the same stream.
//!
//! HTTP/1 hands out exclusive senders, while HTTP/2 and HTTP/3 multiplex over shared senders
//! (streams can finish even after their sender is evicted). The outer map lock only covers
//! entry lookup and bookkeeping; checkout polling and sender drops always happen unlocked.

mod cache;
mod entry;
mod expire;
mod map;
#[cfg(feature = "http2")]
mod negotiate;
#[cfg(any(feature = "http2", feature = "http3"))]
mod singleton;
#[cfg(test)]
mod tests;

use std::{
    fmt,
    future::Future,
    hash::Hash,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures_util::future::BoxFuture;
use http::{Response, Version};
use netty::body::Incoming;
use tower::{BoxError, Layer, Service, ServiceBuilder, ServiceExt, util::Oneshot};
#[cfg(feature = "http2")]
use {
    self::negotiate::{Negotiate, Negotiated},
    super::proto::is_expired,
    std::collections::VecDeque,
};
#[cfg(any(feature = "http2", feature = "http3"))]
use {
    self::singleton::{Singled, Singleton, SingletonError, SingletonFuture},
    super::proto::mux,
};

pub(super) use self::cache::Started;
use self::{
    cache::{Cache, Cached},
    entry::{Entry, EntryCleanupGuard, EntryUse},
    expire::{Expire, Retain},
    map::Map,
};
use super::proto::{Established, Handshakes, SendError, http1};
use crate::{
    Body,
    config::ConnectConfig,
    conn::{Conn, Connected, Request, Unnameable},
    protocol::Protocol,
    rt::{Executor, Timer},
    sync::{Mutex, MutexGuard},
};

/// Controls how long to wait for HTTP/1 reuse before opening a new connection.
///
/// Auto also uses this strategy while choosing a protocol. Requests join an existing
/// HTTP/2 or HTTP/3 connection attempt under either strategy.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "tokio-rt")] {
/// use std::time::Duration;
/// use wreq::{Client, PoolStrategy};
///
/// let _client = Client::builder_tokio()
///     .pool_strategy(PoolStrategy::ReuseFirst(Duration::from_millis(50)));
/// # }
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum PoolStrategy {
    /// Dials immediately on a reuse miss and races the dial against reuse. This is the default.
    #[default]
    Race,

    /// Lets an existing HTTP/1 checkout or connection attempt supply a sender before dialing.
    ///
    /// A group with no existing work dials immediately. A zero delay behaves
    /// like [`PoolStrategy::Race`].
    ReuseFirst(Duration),
}

/// Connection pool retention and checkout policy configured by
/// [`ClientBuilder`](crate::ClientBuilder).
///
/// Controls idle timeout, per-host HTTP/1 idle capacity, optional LRU group cap, and the
/// [`PoolStrategy`] applied before opening a new connection.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Maximum time an idle connection may stay pooled before expiration.
    pub(super) idle_timeout: Option<Duration>,
    /// Maximum unreserved idle HTTP/1 connections per group; `0` disables pooling.
    pub(super) max_idle_per_host: usize,
    /// Optional LRU cap on groups currently retaining reusable connections.
    pub(super) max_size: Option<NonZeroUsize>,
    /// Policy controlling whether HTTP/1 and `Auto` checkouts wait for reuse before dialing.
    pub(super) strategy: PoolStrategy,
}

/// Shared connection pool handle keyed by `K`.
///
/// The outer map lock is held only to look up or insert an entry; dialing and handshakes run
/// unlocked. Dropping the last handle stops the idle-cleanup task (checked-out senders hold
/// only weak references to the pool).
pub(super) struct Pool<K, C, R> {
    /// Shared pool state; dropping the last strong handle stops the expiration watcher.
    inner: Arc<PoolInner<K, C, R>>,
}

/// A sender checked out from a pool entry.
///
/// On drop, healthy HTTP/1 senders return to their cache, while HTTP/2 and HTTP/3 release
/// their checkout handle while letting the connection driver finish any open streams.
pub(super) struct Pooled {
    /// Checked-out HTTP/1 cache handle or shared HTTP/2 or HTTP/3 singleton handle.
    inner: PooledInner,
    /// Must drop after `inner` so maintenance sees the updated cache or singleton state.
    cleanup: EntryCleanupGuard,
}

/// Underlying protocol sender held by [`Pooled`].
enum PooledInner {
    /// Exclusive HTTP/1 sender.
    Http1(Cached<http1::Connection, EntryState>),
    /// Shared HTTP/2 or HTTP/3 sender.
    #[cfg(any(feature = "http2", feature = "http3"))]
    Mux(Singled<mux::Connection>),
}

/// Shared pool state and idle expiration coordinator.
///
/// `entries` is the only outer lock; each entry manages its own synchronization so no network
/// I/O runs while `entries` is locked. `expire` holds a weak reference to `self` so idle
/// cleanup stops promptly on drop.
// Keep the shared map at a fixed offset for hot checkouts across independent groups.
#[repr(C)]
struct PoolInner<K, C, R> {
    /// Outer map from reuse key `K` to its type-erased protocol entry.
    entries: Mutex<Map<K, SharedEntry>>,
    /// Whether checkouts may reuse and return connections (`max_idle_per_host > 0`).
    enabled: bool,
    /// Idle timeout applied during checkout pruning and periodic expiration sweeps.
    idle_timeout: Option<Duration>,
    /// Whether `entries` enforces a retained-group LRU cap (reused hits must refresh LRU).
    has_group_limit: bool,
    /// Single background watcher sweeping expired entries across the whole pool.
    expire: Expire<Self>,
    /// Factory composing the protocol service stack when a new map entry is created.
    targeter: PoolTargeter<C, R>,
}

/// Reference-counted type-erased pool entry stored in [`Map`].
type SharedEntry = Arc<
    dyn Entry<
            Request<ConnectConfig>,
            Sender = Pooled,
            Checkout = CheckoutFuture,
            Discarded = Discarded,
        >,
>;

/// Factory that builds the protocol service stack for each connection pool group.
///
/// Shares client-wide HTTP handshake builders and runtime handles; unpooled checkouts build
/// a temporary entry without inserting it into the map.
struct PoolTargeter<C, R> {
    /// Base transport connector cloned once per new map entry.
    connector: C,
    /// Per-entry HTTP/1 idle connection cap passed into [`Cache`].
    max_idle_per_host: usize,
    /// Non-zero reuse-first delay passed into [`StreamMaker`], if enabled.
    reuse_delay: Option<Duration>,
    /// Runtime driving pool timers and background tasks.
    runtime: R,
    /// Client-wide builders for the protocol handshake layers.
    handshakes: Handshakes,
}

/// Per-group connection reuse state shared under a single entry mutex.
///
/// The HTTP/1 cache and multiplexed state share this lock so an `Auto` entry can
/// inspect both together. Pending checkouts and maintenance are tracked by [`entry::EntryState`].
#[derive(Default)]
struct EntryState {
    /// Exclusive HTTP/1 idle connections, FIFO waiters, and active count.
    cache: cache::Shared<http1::Connection>,
    /// Queued ALPN-upgraded transports and multiplexed singleton state.
    #[cfg(feature = "http2")]
    mux: negotiate::Shared<Established, MuxHandshake, mux::Connection>,
    /// Shared HTTP/3 singleton state when HTTP/2 is disabled.
    #[cfg(all(feature = "http3", not(feature = "http2")))]
    mux: singleton::State<MuxHandshake, mux::Connection>,
}

/// Handshake future for an HTTP/2 or HTTP/3 connection.
#[cfg(any(feature = "http2", feature = "http3"))]
type MuxHandshake = BoxFuture<'static, Result<mux::Connection, BoxError>>;

/// Adapts a protocol service stack to the pool's [`Entry`] interface.
///
/// Pairs the protocol-specific pool service (`Cache`, `Singleton`, or `Negotiate`) with
/// the entry's shared checkout counter and identity-aware maintenance state.
struct ServiceEntry<S> {
    /// Protocol pool service handling checkouts and connection reuse.
    service: S,
    /// Checkout counter, capacity flags, and identity-checked maintenance callback.
    state: Arc<entry::EntryState>,
}

/// Owned connection input paired with whether the checkout may wait for reuse.
///
/// Passed into [`StreamMaker`] so dedicated or unpooled checkouts skip any reuse-first delay.
#[derive(Clone)]
struct Checkout<T> {
    /// Connection request forwarded to the underlying connector on a dial.
    target: T,
    /// Whether this checkout may wait out a reuse-first delay before dialing.
    wait_for_reuse: bool,
}

/// Deferred checkout future polled after the pool map lock is released.
///
/// Existing HTTP/2 and HTTP/3 generations avoid an extra box by holding their singleton
/// future directly, while cold dials and HTTP/1 races stay boxed. In both cases the entry
/// stays active until ownership transfers to [`Pooled`].
enum CheckoutFuture {
    /// Unboxed checkout joining an existing multiplexed generation.
    #[cfg(any(feature = "http2", feature = "http3"))]
    Mux {
        /// Singleton checkout future for the active or completed generation.
        future: SingletonFuture<MuxHandshake, mux::Connection, EntryState>,
        /// Dropped after `future` so cleanup observes the final singleton state.
        usage: Option<EntryUse>,
        /// Whether the checked-out sender participates in pool retention.
        pool_enabled: bool,
    },
    /// Boxed checkout for a cache race, cold dial, or protocol negotiation.
    Service(BoxFuture<'static, Result<Pooled, BoxError>>),
}

/// Connection state detached from an entry for drop after the map lock is released.
enum Discarded {
    /// Idle senders detached from the HTTP/1 cache.
    Http1 { _senders: Vec<http1::Connection> },
    /// Completed sender detached from a shared connection.
    #[cfg(any(feature = "http2", feature = "http3"))]
    Mux { _sender: mux::Connection },
    /// Queued transports and senders detached from a negotiated entry.
    #[cfg(feature = "http2")]
    Negotiated {
        _pending: VecDeque<Established>,
        _fallback: Vec<http1::Connection>,
        _upgrade: Option<mux::Connection>,
    },
}

/// Connector wrapper that defers dialing until its future is polled.
///
/// Optionally waits out a reuse-first window, then runs a cloned connector through `Oneshot`
/// so readiness and `call` happen on the same service instance.
#[derive(Clone)]
struct StreamMaker<C, T> {
    /// Underlying connector cloned for each dial attempt.
    connector: C,
    /// Reuse-first delay applied when `Checkout::wait_for_reuse` is set.
    reuse_delay: Option<Duration>,
    /// Timer for the reuse delay and connection establishment timestamp.
    timer: T,
}

/// Dial future that tracks whether physical connection work has started.
///
/// `started` flips to `true` right before awaiting the connector (after any reuse delay),
/// letting the HTTP/1 cache decide whether a lost race is worth finishing in the background.
struct MakeFuture<T> {
    /// Boxed async dial pipeline (optional delay followed by connector `Oneshot`).
    future: BoxFuture<'static, Result<T, BoxError>>,
    /// Shared flag set right after the reuse delay finishes and dialing begins.
    started: Option<Arc<AtomicBool>>,
    /// Tracks first poll when there is no reuse delay (`started` is `None`).
    polled: bool,
}

// ===== impl Config =====

impl Config {
    /// Returns whether connection pooling is enabled.
    #[must_use]
    pub(super) fn is_enabled(self) -> bool {
        self.max_idle_per_host > 0
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            idle_timeout: Some(Duration::from_secs(90)),
            max_idle_per_host: usize::MAX,
            max_size: None,
            strategy: PoolStrategy::default(),
        }
    }
}

// ===== impl Pool =====

impl<K, C, R> Pool<K, C, R>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    C: Service<Unnameable, Response = Conn, Error = BoxError, Future: Send + 'static>
        + Clone
        + Send
        + Sync
        + 'static,
    R: Executor + Timer + Clone + 'static,
{
    /// Creates a connection pool with the client's configured handshake builders.
    ///
    /// The idle-cleanup task stays dormant until an entry retains idle state.
    #[must_use]
    pub(super) fn new(connector: C, runtime: R, config: Config, handshakes: Handshakes) -> Self {
        let reuse_delay = match config.strategy {
            PoolStrategy::ReuseFirst(duration)
                if config.is_enabled() && duration != Duration::ZERO =>
            {
                Some(duration)
            }
            _ => None,
        };

        let inner = Arc::new_cyclic(|pool| {
            let targeter = PoolTargeter {
                connector,
                max_idle_per_host: config.max_idle_per_host,
                reuse_delay,
                runtime,
                handshakes,
            };

            PoolInner {
                enabled: config.is_enabled(),
                idle_timeout: config.idle_timeout,
                has_group_limit: config.max_size.is_some(),
                expire: Expire::new(pool.clone()),
                entries: Mutex::new(Map::new(config.max_size)),
                targeter,
            }
        });

        Self { inner }
    }

    /// Checks out a sender for `key`, creating a pool entry or dialing with `request` on a miss.
    ///
    /// Entry creation and cloning `request` may run under the map lock; the checkout future is
    /// polled after unlocking. When pooling is disabled or `key` is absent, uses a
    /// temporary entry whose sender never returns to the pool.
    pub(super) async fn checkout(
        &self,
        key: Option<&K>,
        request: &Request<ConnectConfig>,
    ) -> Result<Pooled, BoxError> {
        let Some(key) = key.filter(|_| self.inner.enabled) else {
            let (future, discarded) = self.inner.new_entry(None, request).checkout(request, false);
            drop(discarded);
            return future.await;
        };

        // The guard needs a lexical scope outside await for this future to remain Send.
        let future = {
            let now = self.inner.now();
            let mut entries = self.inner.entries.lock();
            // Bounded pools keep lookup and LRU reconciliation together.
            if !self.inner.has_group_limit
                && let Some(entry) = entries.get_mut(key).cloned()
            {
                drop(entries);
                if let Some(pooled) = entry.checkout_ready(now, self.inner.idle_timeout) {
                    if !self.inner.expire.is_running() {
                        self.inner.schedule_expiration();
                    }
                    return Ok(pooled);
                }
                drop(entry);
                entries = self.inner.entries.lock();
            }
            // Prune only this group on checkout. A global retained-group scan
            // would add O(group count) work and nested locking to every pool hit.
            let entry =
                entries.get_or_insert_with(key, || self.inner.new_entry(Some(key), request));
            let discarded = entry.prune(now, self.inner.idle_timeout);
            let (future, redundant) = entry.checkout(request, true);
            drop(entries);
            drop(discarded);
            drop(redundant);
            future
        };

        future.await
    }

    /// Checks out an established HTTP/2 or HTTP/3 sender whose peer enabled extended CONNECT.
    ///
    /// Probes completed senders only. A miss leaves pool entries intact.
    #[must_use]
    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    pub(super) fn checkout_extended_connect(&self, key: &K) -> Option<Pooled> {
        if !self.inner.enabled {
            return None;
        }
        let now = self.inner.now();
        let pooled = {
            let mut entries = self.inner.entries.lock();
            entries
                .get_mut(key)?
                .checkout_extended_connect(now, self.inner.idle_timeout)?
        };
        // Retained-group maintenance may lock the map again.
        pooled.cleanup.maintain(true);
        Some(pooled)
    }
}

impl<K, C, R> Clone for Pool<K, C, R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<K, C, R: Executor> Executor for Pool<K, C, R> {
    #[track_caller]
    fn execute(&self, future: BoxFuture<'static, ()>) {
        self.inner.targeter.runtime.execute(future);
    }
}

// ===== impl Pooled =====

impl Pooled {
    /// Wraps a checked-out sender and transfers pending entry tracking from `usage`.
    #[must_use]
    fn new(inner: PooledInner, pool_enabled: bool, usage: EntryUse) -> Self {
        // Register the sender before releasing the pending entry lease.
        #[cfg(any(feature = "http2", feature = "http3"))]
        if let PooledInner::Mux(service) = &inner {
            service.inner().begin_checkout();
        }
        let pooled = Self {
            inner,
            cleanup: usage.into_cleanup(pool_enabled),
        };
        if pool_enabled {
            pooled.cleanup.maintain(pooled.is_reused());
        }
        pooled
    }

    /// Wraps an HTTP/1 sender, maintaining its entry when pooling is enabled.
    #[must_use]
    fn new_http1(
        service: Cached<http1::Connection, EntryState>,
        pool_enabled: bool,
        usage: EntryUse,
    ) -> Self {
        Self::new(PooledInner::Http1(service), pool_enabled, usage)
    }

    /// Wraps an HTTP/2 or HTTP/3 sender, maintaining its entry when pooling is enabled.
    #[must_use]
    #[cfg(any(feature = "http2", feature = "http3"))]
    fn new_mux(service: Singled<mux::Connection>, pool_enabled: bool, usage: EntryUse) -> Self {
        Self::new(PooledInner::Mux(service), pool_enabled, usage)
    }

    /// Wraps a ready sender whose checkout was registered under the group lock.
    #[must_use]
    fn reuse(inner: PooledInner, state: Arc<entry::EntryState>) -> Self {
        Self {
            inner,
            cleanup: EntryCleanupGuard::new(Some(state)),
        }
    }

    /// Returns the HTTP version of this connection (HTTP/1 reports HTTP/1.1).
    #[must_use]
    pub(super) fn version(&self) -> Version {
        match &self.inner {
            PooledInner::Http1(_) => Version::HTTP_11,
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.inner().version(),
        }
    }

    /// Returns whether the peer enabled extended CONNECT, or `None` before its SETTINGS arrive.
    ///
    /// Always returns `Some(false)` for HTTP/1.
    #[must_use]
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) fn extended_connect(&self) -> Option<bool> {
        match &self.inner {
            PooledInner::Http1(_) => Some(false),
            PooledInner::Mux(service) => service.inner().extended_connect(),
        }
    }

    /// Returns whether the sender came from an existing pooled connection.
    #[must_use]
    pub(super) fn is_reused(&self) -> bool {
        match &self.inner {
            PooledInner::Http1(service) => service.is_reused(),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.is_reused(),
        }
    }

    /// Returns whether completed senders may be retained for reuse.
    #[must_use]
    pub(super) fn is_pool_enabled(&self) -> bool {
        self.cleanup.is_mapped()
    }

    /// Returns whether the protocol sender can accept a request immediately.
    #[must_use]
    pub(super) fn is_ready(&self) -> bool {
        match &self.inner {
            PooledInner::Http1(service) => service.inner().is_ready(),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.inner().is_ready(),
        }
    }

    /// Returns metadata for the underlying physical connection.
    #[must_use]
    pub(super) fn connected(&self) -> &Connected {
        match &self.inner {
            PooledInner::Http1(service) => service.inner().connected(),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.inner().connected(),
        }
    }
}

impl Service<http::Request<Body>> for Pooled {
    type Response = Response<Incoming>;
    type Error = SendError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        match &mut self.inner {
            PooledInner::Http1(service) => service.poll_ready(cx),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.inner_mut().poll_ready(cx).map_err(|error| {
                self.cleanup.discard(service.generation());
                error
            }),
        }
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        match &mut self.inner {
            PooledInner::Http1(service) => service.call(req),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.inner_mut().call(req),
        }
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        match &mut self.inner {
            PooledInner::Http1(service) => {
                if service.inner().is_open() {
                    service.inner_mut().mark_idle();
                } else {
                    service.discard_on_drop();
                }
                let returned = service.return_to_cache();
                if self.is_pool_enabled() {
                    if returned {
                        self.cleanup.maintain(true);
                    } else {
                        self.cleanup.arm();
                    }
                }
            }
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => {
                let connection = service.inner();
                let needs_tracking = connection.finish_checkout();
                let discard = !connection.is_open();
                if discard {
                    self.cleanup.discard(service.generation());
                }
                if self.is_pool_enabled() && (discard || needs_tracking) {
                    self.cleanup.arm();
                }
            }
        }
    }
}

impl fmt::Debug for Pooled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pooled")
            .field("version", &self.version())
            .field("reused", &self.is_reused())
            .finish()
    }
}

// ===== impl PoolInner =====

impl<K, C, R> PoolInner<K, C, R>
where
    K: Eq + Hash + Clone + Send + 'static,
    C: Send + Sync + 'static,
    R: Executor + Timer + Clone + 'static,
{
    /// Builds an entry for `request`, binding it to the pool only when given a `key`.
    #[must_use]
    fn new_entry(self: &Arc<Self>, key: Option<&K>, request: &Request<ConnectConfig>) -> SharedEntry
    where
        K: Sync,
        C: Service<Unnameable, Response = Conn, Error = BoxError> + Clone,
        C::Future: Send + 'static,
    {
        let shared = Arc::new(Mutex::new(EntryState::default()));
        let state = Arc::new(entry::EntryState {
            uses: AtomicUsize::new(0),
            has_group_limit: self.has_group_limit,
            idle_watch_running: key
                .and(self.expiration_interval(true))
                .map(|_| self.expire.running_flag()),
            maintain: match key {
                Some(key) => {
                    let pool = Arc::downgrade(self);
                    let key = key.clone();
                    // Keep a weak handle to the group mutex for direct mux generation
                    // discard without locking the outer map; HTTP/1 never uses it.
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    let group = if request.protocol() == Protocol::Http1 {
                        std::sync::Weak::new()
                    } else {
                        Arc::downgrade(&shared)
                    };
                    Box::new(move |state, action| match action {
                        #[cfg(any(feature = "http2", feature = "http3"))]
                        entry::Maintenance::Discard(generation) => {
                            singleton::discard_generation(&group, generation);
                        }
                        entry::Maintenance::Touch | entry::Maintenance::Reconcile => {
                            if let Some(pool) = pool.upgrade() {
                                pool.update_entry(
                                    &key,
                                    state,
                                    matches!(action, entry::Maintenance::Touch),
                                );
                            }
                        }
                    })
                }
                None => Box::new(|_, _| {}),
            },
        });
        self.targeter.service(request, state, shared)
    }

    /// Reads the configured runtime clock.
    #[must_use]
    fn now(&self) -> Instant {
        self.targeter.runtime.now()
    }

    /// Returns the proactive idle-check interval when retained state exists.
    #[must_use]
    fn expiration_interval(&self, has_retained: bool) -> Option<Duration> {
        self.idle_timeout
            .filter(|timeout| self.enabled && has_retained && *timeout != Duration::ZERO)
            .map(|timeout| timeout.max(Duration::from_millis(90)))
    }

    /// Schedules idle cleanup with the same runtime used for checkout timestamps.
    fn schedule_expiration(&self) {
        self.expire
            .schedule(self.expiration_interval(true), &self.targeter.runtime);
    }

    /// Mutates `entries` under the lock, then drops `detached` after releasing it.
    ///
    /// The field order of `detached` controls the drop order.
    fn with_entries<T, D>(
        guard: MutexGuard<'_, Map<K, SharedEntry>>,
        mut detached: D,
        clean: impl FnOnce(&mut Map<K, SharedEntry>, &mut D) -> T,
    ) -> T {
        let result = {
            let mut guard = guard;
            clean(&mut guard, &mut detached)
        };
        drop(detached);
        result
    }

    /// Removes an empty entry or reconciles its idle-group capacity tracking.
    fn update_entry(self: &Arc<Self>, key: &K, state: &Arc<entry::EntryState>, promote: bool) {
        let mut entries = self.entries.lock();
        let Some((empty, retained)) = entries
            .get_mut(key)
            .filter(|entry| entry.has_state(state))
            .map(|entry| (entry.is_empty(), entry.has_retained()))
        else {
            return;
        };

        if empty {
            Self::with_entries(entries, None, |entries, removed| {
                *removed = entries.remove_if(key, |_| true);
            });
            return;
        }

        if !retained {
            entries.unmark_retained(key);
            return;
        }

        // Check other entries only when making room for this retained group.
        let (pruned, evicted) =
            entries.mark_retained(key, promote, |entry| entry.prepare_eviction());

        if pruned.is_empty() && evicted.is_none() {
            drop(entries);
        } else {
            // Drop removed entries before detached connections. Capacity can
            // evict a single group after any number of stale markers are pruned.
            Self::with_entries(
                entries,
                (Vec::new(), None, Vec::new(), None),
                move |entries, (removed, evicted_entry, discarded, evicted_state)| {
                    // Busy senders stay pooled and resume tracking when idle.
                    if !pruned.is_empty() {
                        let now = self.now();
                        for key in &pruned {
                            removed.extend(entries.remove_if(key, |entry| {
                                discarded.extend(entry.prune(now, self.idle_timeout));
                                entry.is_empty()
                            }));
                        }
                    }

                    *evicted_entry = evicted.and_then(|key| {
                        entries.remove_if(&key, |entry| {
                            *evicted_state = entry.evict();
                            entry.is_empty()
                        })
                    });
                },
            );
        }

        self.schedule_expiration();
    }
}

impl<K, C, R> Retain for PoolInner<K, C, R>
where
    K: Eq + Hash + Clone + Send + 'static,
    C: Send + Sync + 'static,
    R: Executor + Timer + Clone + 'static,
{
    fn retain(&self, now: Instant) -> Option<Duration> {
        let has_retained = Self::with_entries(
            self.entries.lock(),
            (Vec::new(), Vec::new()),
            |entries, (removed, discarded)| {
                let mut has_retained = false;
                *removed = entries.retain(|_, entry| {
                    discarded.extend(entry.prune(now, self.idle_timeout));
                    let keep = !entry.is_empty();
                    has_retained |= keep && entry.has_retained();
                    keep
                });
                let _ = entries.prune_retained(|entry| entry.has_retained());
                has_retained
            },
        );
        self.expiration_interval(has_retained)
    }

    fn next(&self) -> Option<Duration> {
        let has_retained = self
            .entries
            .lock()
            .iter_mut()
            .any(|(_, entry)| entry.has_retained());

        self.expiration_interval(has_retained)
    }
}

// ===== impl PoolTargeter =====

impl<C, R: Executor + Timer + Clone + 'static> PoolTargeter<C, R> {
    /// Wraps the HTTP/1 handshake layer in an idle connection cache.
    #[must_use]
    fn http1_pool<'layer, S>(
        &'layer self,
        state: &'layer Arc<entry::EntryState>,
        shared: &'layer Arc<Mutex<EntryState>>,
        config: &'layer ConnectConfig,
    ) -> impl Layer<
        S,
        Service = Cache<
            http1::Connect<S>,
            Checkout<Request<ConnectConfig>>,
            cache::events::WithRuntime<R>,
            EntryState,
        >,
    > + use<'layer, C, R, S>
    where
        S: Service<Checkout<Request<ConnectConfig>>, Response = Established, Error = BoxError>
            + Clone,
        S::Future: Started + Unpin,
    {
        ServiceBuilder::new()
            .layer_fn(move |service| {
                let state = state.clone();
                cache::builder()
                    .runtime(self.runtime.clone())
                    .on_background_complete(move || {
                        (state.maintain)(&state, entry::Maintenance::Touch);
                    })
                    .max_idle(self.max_idle_per_host)
                    .build_in(service, shared.clone())
            })
            .layer(self.handshakes.http1(config))
            .into_inner()
    }

    /// Builds the entry service stack for `request`'s protocol mode and HTTP option overrides.
    #[must_use]
    fn service(
        &self,
        request: &Request<ConnectConfig>,
        state: Arc<entry::EntryState>,
        shared: Arc<Mutex<EntryState>>,
    ) -> SharedEntry
    where
        C: Service<Unnameable, Response = Conn, Error = BoxError> + Clone + Send + Sync + 'static,
        C::Future: Send + 'static,
    {
        let connector = || self.connector.clone().map_request(Unnameable::from);
        let connect = || StreamMaker {
            timer: self.runtime.clone(),
            connector: connector(),
            reuse_delay: self.reuse_delay,
        };
        let config = request.body();

        // Fixed protocol modes use smaller service graphs; only Auto needs both
        // pools and negotiation: https://github.com/hyperium/hyper/issues/3948
        match request.protocol() {
            Protocol::Http1 => {
                let service = self.http1_pool(&state, &shared, config).layer(connect());
                Arc::new(ServiceEntry { service, state })
            }
            #[cfg(feature = "http2")]
            Protocol::Http2 => Arc::new(ServiceEntry {
                service: ServiceBuilder::new()
                    .layer_fn(|maker| Singleton::new(maker, shared.clone()))
                    .layer(self.handshakes.http2(config))
                    .service(connect()),
                state,
            }),
            #[cfg(feature = "http3")]
            Protocol::Http3 => Arc::new(ServiceEntry {
                service: ServiceBuilder::new()
                    .layer_fn(|maker| Singleton::new(maker, shared.clone()))
                    .layer(self.handshakes.http3(config))
                    .service(connector()),
                state,
            }),
            Protocol::Auto => cfg_select! {
                feature = "http2" => Arc::new({
                    let inspect: fn(&Established) -> bool =
                        |established| established.connected().is_negotiated_h2();
                    let upgrade = ServiceBuilder::new()
                        .layer_fn(|maker| Singleton::new(maker, shared.clone()))
                        .layer(self.handshakes.http2(config));
                    let service = Negotiate::new(
                        connect(),
                        inspect,
                        self.http1_pool(&state, &shared, config),
                        upgrade,
                    );

                    ServiceEntry { service, state }
                }),
                _ => Arc::new({
                    let service = self.http1_pool(&state, &shared, config).layer(connect());
                    ServiceEntry { service, state }
                }),
            },
        }
    }
}

// ===== impl EntryState =====

impl AsMut<cache::Shared<http1::Connection>> for EntryState {
    fn as_mut(&mut self) -> &mut cache::Shared<http1::Connection> {
        &mut self.cache
    }
}

#[cfg(feature = "http2")]
impl AsRef<negotiate::Shared<Established, MuxHandshake, mux::Connection>> for EntryState {
    fn as_ref(&self) -> &negotiate::Shared<Established, MuxHandshake, mux::Connection> {
        &self.mux
    }
}

#[cfg(feature = "http2")]
impl AsMut<negotiate::Shared<Established, MuxHandshake, mux::Connection>> for EntryState {
    fn as_mut(&mut self) -> &mut negotiate::Shared<Established, MuxHandshake, mux::Connection> {
        &mut self.mux
    }
}

#[cfg(feature = "http2")]
impl AsMut<VecDeque<Established>> for EntryState {
    fn as_mut(&mut self) -> &mut VecDeque<Established> {
        self.mux.as_mut()
    }
}

#[cfg(any(feature = "http2", feature = "http3"))]
impl AsMut<singleton::State<MuxHandshake, mux::Connection>> for EntryState {
    fn as_mut(&mut self) -> &mut singleton::State<MuxHandshake, mux::Connection> {
        cfg_select! {
            feature = "http2" => self.mux.as_mut(),
            _ => &mut self.mux,
        }
    }
}

#[cfg(feature = "http2")]
impl EntryState {
    /// Prunes both sides of an Auto entry under the same group lock.
    #[must_use]
    fn prune(
        &mut self,
        now: Instant,
        timeout: Option<Duration>,
        in_use: bool,
    ) -> Option<Discarded> {
        let upgrade: &mut singleton::State<_, _> = self.mux.as_mut();
        // Queued transports are redundant once the upgrade is established.
        let pending = if upgrade.service().is_some() {
            self.mux.drain_pending()
        } else if !in_use {
            self.mux
                .retain_pending(|connection| !is_expired(connection.idle_at(), now, timeout))
        } else {
            Default::default()
        };
        let fallback = self
            .cache
            .retain_idle(|connection| connection.is_reusable(now, timeout));
        // In-flight checkouts defer expiry, not health checks.
        let timeout = timeout.filter(|_| !in_use);
        let upgrade: &mut singleton::State<_, _> = self.mux.as_mut();
        let upgrade = upgrade.retain(|connection| connection.is_reusable(now, timeout));
        Discarded::negotiated(pending, fallback, upgrade)
    }

    /// Checks retained state and optionally marks active multiplexed connections for deferred LRU.
    #[must_use]
    fn retained(&mut self, defer_busy: bool) -> bool {
        let queued = self.mux.has_pending() || self.cache.has_idle();
        let upgrade: &mut singleton::State<_, _> = self.mux.as_mut();
        let connection = upgrade.service();
        (queued || connection.is_some_and(mux::Connection::is_open))
            && !(defer_busy && connection.is_some_and(mux::Connection::defer_until_idle))
    }

    /// Detaches retained Auto connections for drop outside the pool locks.
    #[must_use]
    fn evict(&mut self) -> Option<Discarded> {
        let pending = self.mux.drain_pending();
        let fallback = self.cache.drain_idle();
        let upgrade: &mut singleton::State<_, _> = self.mux.as_mut();
        Discarded::negotiated(pending, fallback, upgrade.take())
    }
}

// ===== impl ServiceEntry =====

impl<M, T, Ev> Entry<T> for ServiceEntry<Cache<M, Checkout<T>, Ev, EntryState>>
where
    T: Clone + Send + 'static,
    M: Service<Checkout<T>, Response = http1::Connection>,
    Cache<M, Checkout<T>, Ev, EntryState>: Service<
            Checkout<T>,
            Response = Cached<http1::Connection, EntryState>,
            Error = BoxError,
            Future: Send,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    type Sender = Pooled;
    type Checkout = CheckoutFuture;
    type Discarded = Discarded;

    fn checkout_ready(&self, now: Instant, timeout: Option<Duration>) -> Option<Pooled> {
        let service = self
            .service
            .checkout_idle(&mut self.service.shared().lock().cache, |connection| {
                connection.is_reusable(now, timeout)
            })?;
        Some(Pooled::reuse(
            PooledInner::Http1(service),
            self.state.clone(),
        ))
    }

    fn checkout(&self, target: &T, pool_enabled: bool) -> (CheckoutFuture, Option<Discarded>) {
        // Only enable reuse-first delay when existing work may yield a sender.
        let checkout = Checkout::new(target.clone(), pool_enabled && !Entry::<T>::is_empty(self));
        let service = self.service.clone();
        let usage = EntryUse::new(self.state.clone());
        (
            CheckoutFuture::Service(Box::pin(async move {
                Oneshot::new(service, checkout)
                    .await
                    .map(|service| Pooled::new_http1(service, pool_enabled, usage))
            })),
            None,
        )
    }

    fn prune(&self, now: Instant, timeout: Option<Duration>) -> Option<Discarded> {
        Discarded::http1(
            self.service
                .retain_idle(|connection| connection.is_reusable(now, timeout)),
        )
    }

    fn has_retained(&self) -> bool {
        self.service.has_idle()
    }

    fn evict(&self) -> Option<Discarded> {
        Discarded::http1(self.service.drain_idle())
    }

    fn has_state(&self, state: &Arc<entry::EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    fn is_empty(&self) -> bool {
        self.state.uses.load(Ordering::Acquire) == 0 && self.service.is_empty()
    }
}

#[cfg(any(feature = "http2", feature = "http3"))]
impl<M, T> Entry<T> for ServiceEntry<Singleton<M, Checkout<T>, EntryState>>
where
    T: Clone + Send + 'static,
    M: Service<Checkout<T>, Response = mux::Connection, Error = BoxError, Future = MuxHandshake>
        + Clone
        + Send
        + Sync
        + 'static,
{
    type Sender = Pooled;
    type Checkout = CheckoutFuture;
    type Discarded = Discarded;

    fn checkout_ready(&self, now: Instant, timeout: Option<Duration>) -> Option<Pooled> {
        self.service
            .checkout_ready(None, |connection| {
                connection.try_checkout(now, timeout, || {
                    self.state.uses.load(Ordering::Acquire) != 0
                })
            })
            .into_made()
            .map(|service| Pooled::reuse(PooledInner::Mux(service), self.state.clone()))
    }

    #[cfg(feature = "ws")]
    fn checkout_extended_connect(&self, now: Instant, timeout: Option<Duration>) -> Option<Pooled> {
        checkout_extended_connect(&self.service, &self.state, now, timeout)
    }

    fn checkout(&self, target: &T, pool_enabled: bool) -> (CheckoutFuture, Option<Discarded>) {
        let usage = EntryUse::new(self.state.clone());
        if let Some(future) = self.service.checkout(None) {
            return (
                CheckoutFuture::Mux {
                    future,
                    usage: Some(usage),
                    pool_enabled,
                },
                None,
            );
        }
        let checkout = Checkout::new(target.clone(), false);
        let service = self.service.clone();
        (
            CheckoutFuture::Service(Box::pin(async move {
                let service = Oneshot::new(service, checkout).await?;
                Ok(Pooled::new_mux(service, pool_enabled, usage))
            })),
            None,
        )
    }

    fn prune(&self, now: Instant, timeout: Option<Duration>) -> Option<Discarded> {
        // A checkout waiting on the singleton may not hold a sender yet.
        let timeout = timeout.filter(|_| self.state.uses.load(Ordering::Acquire) == 0);
        self.service
            .with_state(|state| state.retain(|connection| connection.is_reusable(now, timeout)))
            .map(|sender| Discarded::Mux { _sender: sender })
    }

    fn has_retained(&self) -> bool {
        // Check health because a peer may close an idle connection between sweeps.
        self.service
            .with_state(|state| state.service().is_some_and(mux::Connection::is_open))
    }

    fn prepare_eviction(&self) -> bool {
        self.service.with_state(|state| {
            state
                .service()
                .is_some_and(|connection| connection.is_open() && !connection.defer_until_idle())
        })
    }

    fn evict(&self) -> Option<Discarded> {
        self.service
            .with_state(singleton::State::take)
            .map(|sender| Discarded::Mux { _sender: sender })
    }

    fn has_state(&self, state: &Arc<entry::EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    fn is_empty(&self) -> bool {
        self.state.uses.load(Ordering::Acquire) == 0
            && self
                .service
                .with_state(|state| matches!(state, singleton::State::Empty))
    }
}

#[cfg(feature = "http2")]
impl<M, U, T, Ev> Entry<T>
    for ServiceEntry<
        Negotiate<
            Cache<M, Checkout<T>, Ev, EntryState>,
            Singleton<U, Established, EntryState>,
            Established,
        >,
    >
where
    T: Clone + Send + 'static,
    M: Service<Checkout<T>, Response = http1::Connection>,
    Cache<M, Checkout<T>, Ev, EntryState>: Service<
            Checkout<T>,
            Response = Cached<http1::Connection, EntryState>,
            Error = BoxError,
            Future: Send,
        > + Clone
        + Send
        + Sync
        + 'static,
    U: Service<Established, Response = mux::Connection, Error = BoxError, Future = MuxHandshake>
        + Clone
        + Send
        + Sync
        + 'static,
{
    type Sender = Pooled;
    type Checkout = CheckoutFuture;
    type Discarded = Discarded;

    fn checkout_ready(&self, now: Instant, timeout: Option<Duration>) -> Option<Pooled> {
        self.service.checkout_ready(
            |connection, state| {
                // The regular path prunes any remaining HTTP/1 idle state.
                !state.cache.has_idle()
                    && connection.try_checkout(now, timeout, || {
                        self.state.uses.load(Ordering::Acquire) != 0
                    })
            },
            |fallback, state| {
                fallback.checkout_idle(&mut state.cache, |connection| {
                    connection.is_reusable(now, timeout)
                })
            },
            |service| Pooled::reuse(PooledInner::Mux(service), self.state.clone()),
            |service| Pooled::reuse(PooledInner::Http1(service), self.state.clone()),
        )
    }

    fn checkout(&self, target: &T, pool_enabled: bool) -> (CheckoutFuture, Option<Discarded>) {
        let wait_for_reuse = pool_enabled && !Entry::<T>::is_empty(self);
        let usage = EntryUse::new(self.state.clone());
        if let Some((future, pending)) = self.service.checkout_existing() {
            return (
                CheckoutFuture::Mux {
                    future,
                    usage: Some(usage),
                    pool_enabled,
                },
                Discarded::negotiated(pending, Vec::new(), None),
            );
        }
        let checkout = Checkout::new(target.clone(), wait_for_reuse);
        let service = self.service.clone();
        (
            CheckoutFuture::Service(Box::pin(async move {
                Oneshot::new(service, checkout)
                    .await
                    .map(|service| match service {
                        Negotiated::Left(service) => {
                            Pooled::new_http1(service, pool_enabled, usage)
                        }
                        Negotiated::Right(service) => Pooled::new_mux(service, pool_enabled, usage),
                    })
            })),
            None,
        )
    }

    #[cfg(feature = "ws")]
    fn checkout_extended_connect(&self, now: Instant, timeout: Option<Duration>) -> Option<Pooled> {
        checkout_extended_connect(self.service.upgrade(), &self.state, now, timeout)
    }

    fn prune(&self, now: Instant, timeout: Option<Duration>) -> Option<Discarded> {
        let in_use = self.state.uses.load(Ordering::Acquire) != 0;
        self.service
            .upgrade()
            .shared()
            .lock()
            .prune(now, timeout, in_use)
    }

    fn has_retained(&self) -> bool {
        self.service.upgrade().shared().lock().retained(false)
    }

    fn prepare_eviction(&self) -> bool {
        self.service.upgrade().shared().lock().retained(true)
    }

    fn evict(&self) -> Option<Discarded> {
        self.service.upgrade().shared().lock().evict()
    }

    fn has_state(&self, state: &Arc<entry::EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    fn is_empty(&self) -> bool {
        self.state.uses.load(Ordering::Acquire) == 0
            && self.service.is_empty(|group| group.cache.is_empty())
    }
}

/// Probes `singleton` for an established, reusable sender whose peer enabled extended CONNECT.
#[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
fn checkout_extended_connect<M, T>(
    singleton: &Singleton<M, T, EntryState>,
    state: &Arc<entry::EntryState>,
    now: Instant,
    timeout: Option<Duration>,
) -> Option<Pooled>
where
    M: Service<T, Response = mux::Connection, Future = MuxHandshake>,
{
    singleton
        .checkout_ready(None, |sender| {
            sender.extended_connect() == Some(true) && sender.try_checkout(now, timeout, || false)
        })
        .into_made()
        .map(|service| Pooled::reuse(PooledInner::Mux(service), state.clone()))
}

// ===== impl Checkout =====

impl<T> Checkout<T> {
    #[must_use]
    fn new(target: T, wait_for_reuse: bool) -> Self {
        Self {
            target,
            wait_for_reuse,
        }
    }
}

impl From<Checkout<Request<ConnectConfig>>> for Unnameable {
    fn from(checkout: Checkout<Request<ConnectConfig>>) -> Self {
        Self(checkout.target)
    }
}

// ===== impl CheckoutFuture =====

impl Future for CheckoutFuture {
    type Output = Result<Pooled, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            #[cfg(any(feature = "http2", feature = "http3"))]
            Self::Mux {
                future,
                usage,
                pool_enabled,
            } => {
                let result = std::task::ready!(Pin::new(&mut *future).poll(cx));
                let Some(usage) = usage.take() else {
                    return Poll::Pending;
                };
                // Pooled::new_mux starts checkout accounting before releasing EntryUse and
                // may run map maintenance, so it must execute outside the lock.
                Poll::Ready(
                    result
                        .map(|service| Pooled::new_mux(service, *pool_enabled, usage))
                        .map_err(Into::into),
                )
            }
            Self::Service(future) => future.as_mut().poll(cx),
        }
    }
}

// ===== impl Discarded =====

impl Discarded {
    /// Returns a batch when the HTTP/1 cache detached at least one sender.
    #[must_use]
    fn http1(senders: Vec<http1::Connection>) -> Option<Self> {
        (!senders.is_empty()).then_some(Self::Http1 { _senders: senders })
    }

    /// Groups resources detached from either side of negotiation into one batch.
    #[cfg(feature = "http2")]
    #[must_use]
    fn negotiated(
        pending: VecDeque<Established>,
        fallback: Vec<http1::Connection>,
        upgrade: Option<mux::Connection>,
    ) -> Option<Self> {
        (!pending.is_empty() || !fallback.is_empty() || upgrade.is_some()).then_some(
            Self::Negotiated {
                _pending: pending,
                _fallback: fallback,
                _upgrade: upgrade,
            },
        )
    }
}

// ===== impl StreamMaker =====

impl<C, R, T> Service<Checkout<T>> for StreamMaker<C, R>
where
    C: Service<Checkout<T>, Response = Conn, Error = BoxError, Future: Send + 'static>
        + Clone
        + Send
        + 'static,
    R: Timer + Clone + 'static,
    T: Send + 'static,
{
    type Response = Established;
    type Error = BoxError;
    type Future = MakeFuture<Self::Response>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, checkout: Checkout<T>) -> Self::Future {
        let reuse_delay = if checkout.wait_for_reuse {
            self.reuse_delay
        } else {
            None
        };
        let started = reuse_delay
            .is_some()
            .then(|| Arc::new(AtomicBool::new(false)));
        let start_signal = started.clone();
        let connector = self.connector.clone();
        let timer = self.timer.clone();

        let future = Box::pin(async move {
            if let Some(duration) = reuse_delay {
                timer.sleep(duration).await;
            }
            if let Some(started) = &start_signal {
                started.store(true, Ordering::Release);
            }

            let Conn {
                transport,
                connected,
            } = Oneshot::new(connector, checkout).await?;

            Ok(Established::new(
                transport.into_stream()?,
                connected,
                #[cfg(feature = "http2")]
                timer.now(),
            ))
        });

        MakeFuture {
            future,
            polled: false,
            started,
        }
    }
}

// ===== impl MakeFuture =====

impl<T> Future for MakeFuture<T> {
    type Output = Result<T, BoxError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.polled = true;
        self.future.as_mut().poll(cx)
    }
}

impl<T> Started for MakeFuture<T> {
    fn started(&self) -> bool {
        self.started
            .as_ref()
            .map_or(self.polled, |started| started.load(Ordering::Acquire))
    }
}

/// Returns whether an internal singleton batch asks the client to retry.
#[must_use]
pub(super) fn is_canceled(error: &(dyn std::error::Error + 'static)) -> bool {
    cfg_select! {
        any(feature = "http2", feature = "http3") => SingletonError::is_canceled(error),
        _ => {
            let _ = error;
            false
        }
    }
}
