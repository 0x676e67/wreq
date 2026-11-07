//! Composable client connection pooling, adapted from [hyper-util].
//! Connections are isolated by configuration and managed by acquisition and idle policies.
//!
//! [hyper-util]: https://github.com/hyperium/hyper-util/blob/master/src/client/pool/mod.rs
//!
//! [`Map`] groups connections by [`ConnectionKey`], including request-local
//! configuration and an optional [`crate::Group`] partition. Fixed modes use
//! an HTTP/1 [`Cache`] or an HTTP/2 or HTTP/3 [`Singleton`]. Auto negotiates
//! between HTTP/1 and HTTP/2 through [`Negotiate`].
//!
//! HTTP/1 senders are exclusive and return only when ready. HTTP/2 and HTTP/3
//! senders are shared; checkout accounting ends at response headers, not at stream completion.
//!
//! # Checkout flow
//!
//! 1. Find or create the entry for the connection key.
//! 2. Check the fixed protocol pool, or try HTTP/2 then HTTP/1 reuse in Auto mode before allowing a
//!    new connection.
//! 3. Handshake using the request's protocol configuration.
//! 4. Transfer cleanup to [`Pooled`] on success; on cancellation, remove the same entry only when
//!    no shared work remains.
//!
//! Locks protect routing and bookkeeping. Sender destruction, user service
//! polling, and task wakeups run after releasing them.

pub(super) mod cache;
pub(super) mod expire;
pub(super) mod map;
#[cfg(feature = "http2")]
pub(super) mod negotiate;
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) mod singleton;

use std::{
    fmt,
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures_util::future::BoxFuture;
#[cfg(feature = "http3")]
use futures_util::future::Either;
use http::{Request, Response};
use netty::{body::Incoming, conn};
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Layer, Service, ServiceBuilder, util::Oneshot};

#[cfg(feature = "http2")]
use self::negotiate::{Existing, Negotiate, Negotiated};
#[cfg(any(feature = "http2", feature = "http3"))]
use self::singleton::{Singled, Singleton, SingletonError, SingletonFuture};
use self::{
    cache::{BackgroundConnect, Cache, Cached, Started},
    expire::{Expire, Inspect},
    map::{Map, Target},
};
#[cfg(feature = "http3")]
use super::proto::http3;
use super::proto::{Established, SendError, http1};
#[cfg(feature = "http2")]
use super::proto::{http2, is_expired};
use crate::{
    Body, Protocol,
    conn::{
        AsyncConn, Conn, Connected,
        request::{ConnectRequest, ConnectionKey},
    },
    rt::{DynRuntime, Timer as _},
    sync::Mutex,
};

/// Returns whether an internal singleton batch asks the client to retry.
pub(super) fn is_canceled(error: &(dyn std::error::Error + 'static)) -> bool {
    cfg_select! {
        any(feature = "http2", feature = "http3") => SingletonError::is_canceled(error),
        _ => {
            let _ = error;
            false
        }
    }
}

/// Selects when the pool starts a new connection while reuse is unavailable.
///
/// This changes acquisition timing only. Idle timeouts and retention limits are
/// configured separately on [`ClientBuilder`](crate::ClientBuilder).
/// Existing HTTP/2 or HTTP/3 creation is shared under either strategy, without a competing
/// connection attempt; the reuse delay does not limit that wait.
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
    /// Starts a new connection as soon as no reusable connection is ready.
    ///
    /// Existing work can still win the resulting race. This is the default and
    /// favors low latency.
    #[default]
    Race,

    /// Gives existing pool state this long to become reusable before connecting.
    ///
    /// A cold compatibility group connects immediately. The delay applies only
    /// when idle, checked-out, or connecting state may become reusable. A zero
    /// duration behaves like [`PoolStrategy::Race`].
    ReuseFirst(Duration),
}

/// Immutable retention and acquisition policy for one connection pool.
///
/// The client builder assembles this value once. Every mapped entry inherits the
/// same idle policy and acquisition strategy; request-specific handshake inputs
/// remain in [`PoolTarget`].
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Maximum time an unused connection remains reusable.
    pub(super) idle_timeout: Option<Duration>,

    /// Maximum HTTP/1 connections retained per compatibility group.
    pub(super) max_idle_per_host: usize,

    /// Maximum number of compatibility groups allowed to retain idle state.
    pub(super) max_size: Option<NonZeroUsize>,

    /// Delay policy applied before starting a new connection.
    pub(super) strategy: PoolStrategy,

    /// Deadline of the HTTP/3 connect and handshake, which the transport timeout alone does not
    /// cover.
    #[cfg(feature = "http3")]
    pub(super) http3_connect_timeout: Option<Duration>,
}

// ===== impl Config =====

impl Config {
    /// Returns whether mapped pooling and sender retention are enabled.
    pub(super) fn is_enabled(self) -> bool {
        self.max_idle_per_host > 0
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            idle_timeout: None,
            max_idle_per_host: usize::MAX,
            max_size: None,
            strategy: PoolStrategy::default(),
            #[cfg(feature = "http3")]
            http3_connect_timeout: None,
        }
    }
}

/// Transport connector cloned into each pool connection attempt.
///
/// Names the bounds shared by the client stack, the pool and the HTTP/3 connect
/// service; every connector service with these bounds implements it.
pub trait TransportConnector:
    Service<ConnectRequest, Response = Conn, Error = BoxError, Future: Send + 'static>
    + Clone
    + Send
    + Sync
    + 'static
{
}

impl<C> TransportConnector for C where
    C: Service<ConnectRequest, Response = Conn, Error = BoxError, Future: Send + 'static>
        + Clone
        + Send
        + Sync
        + 'static
{
}

/// Cloneable connection-pool handle used by the HTTP client.
///
/// Cloning this type shares every mapped entry and cleanup task. A checkout
/// locks the outer map only long enough to locate or create one
/// entry; connection acquisition and protocol handshakes run after that lock is
/// released.
///
/// The final handle drop closes the idle-cleanup signal. Checked-out protocol
/// senders can outlive the handle, but their weak pool references prevent them
/// from keeping the routing map alive.
pub(super) struct Pool<C> {
    inner: Arc<PoolInner<C>>,
}

/// Shared coordinator for mapped pool services and idle maintenance.
///
/// `services` is the only outer routing lock. Entry services contain their own
/// finer-grained synchronization, so no network future is polled while this lock
/// is held. The coordinator also owns the weak back-reference used by failed
/// checkout cleanup.
///
/// Its [`Expire`] component owns the single weakly referenced maintenance task,
/// allowing long idle timers to stop immediately when this coordinator drops.
struct PoolInner<C> {
    /// Whether completed connections may return to pool entries.
    enabled: bool,

    /// Maximum idle duration applied during cleanup and checkout.
    idle_timeout: Option<Duration>,

    /// Schedules the single outer expiration watcher.
    expire: Expire<Self>,

    /// Factory used when pooling is disabled or a map entry is missing.
    targeter: PoolTargeter<C>,

    /// Services keyed by complete connection compatibility.
    services: Mutex<Map<ConnectionKey, Box<dyn Entry>>>,
}

/// Destination and protocol configuration for one pool checkout.
///
/// The key fixes the origin and relevant configuration before checkout.
/// Client builders and request overrides travel together so each new connection
/// uses its initiating request's settings.
/// `wait_for_reuse` is computed by the existing entry, keeping cold starts free
/// of the reuse-first delay.
#[derive(Clone)]
pub(super) struct PoolTarget {
    /// Immutable configuration shared with retries and negotiation.
    pub(super) config: ConnectionConfig,

    /// Requested protocol selection mode.
    protocol: Protocol,

    /// Whether this checkout can wait for existing pool state to become reusable.
    wait_for_reuse: bool,
}

/// Connection inputs carried by one request's checkout and retries.
/// Clones share the frozen configuration and client builders without an outer allocation.
/// Only the selected handshake prepares a builder with request-local options.
#[derive(Clone)]
pub(super) struct ConnectionConfig {
    pub(super) req: ConnectRequest,
    pub(super) proto: Arc<ProtocolBuilders>,
    /// Whether checkout always connects and never returns the sender to the pool.
    pub(super) dedicated: bool,
}

/// Handshake builders shared by all requests from one client.
pub(super) struct ProtocolBuilders {
    pub(super) http1: conn::http1::Builder,
    #[cfg(feature = "http2")]
    pub(super) http2: conn::http2::Builder<DynRuntime>,
    #[cfg(feature = "http3")]
    pub(super) http3: conn::http3::Builder<DynRuntime>,
}

/// Factory that creates one protocol-specific service graph per destination group.
///
/// [`Map`] calls this factory on a key miss. Fixed protocol targets receive their
/// matching pool; Auto combines HTTP/1 and HTTP/2 through [`Negotiate`]. Unpooled
/// checkouts create a temporary entry. Entries hold only a weak reference to [`PoolInner`].
struct PoolTargeter<C> {
    /// Physical connection service.
    connector: C,

    /// HTTP/1 idle capacity configured for each entry.
    max_idle_per_host: usize,

    /// Optional delay before a cache miss starts connecting.
    reuse_delay: Option<Duration>,

    /// Pool coordinator used for identity-aware entry cleanup.
    pool: Weak<PoolInner<C>>,

    /// Runtime used by cache races and protocol drivers.
    runtime: DynRuntime,

    /// Whether HTTP/1 should generate a missing `Host` field.
    set_host: bool,

    /// Deadline of each HTTP/3 connect and handshake.
    #[cfg(feature = "http3")]
    http3_connect_timeout: Option<Duration>,
}

/// Type-erased operations required from one mapped pool entry.
///
/// The outer map stores different protocol pools through this trait object,
/// preserving static dispatch inside each entry. Maintenance methods return
/// removed connection state for destruction after the map lock is released.
trait Entry: Send {
    /// Selects a checkout without polling service code under the map lock.
    /// Poll or drop the checkout and unused configuration only after unlocking.
    fn checkout(
        &mut self,
        target: PoolTarget,
        pool_enabled: bool,
    ) -> (Checkout, Option<ConnectionConfig>);

    /// Clones an established HTTP/2 sender without creating, joining, or draining
    /// work. Other protocols and generations still being made return `None`.
    #[cfg(feature = "http2")]
    fn checkout_made(&self) -> Option<(H2Pooled, Arc<EntryState>)>;

    /// Removes expired or closed idle connections for unlocked destruction.
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Option<DeferredDrop>;

    /// Returns whether this entry retains reusable connection state.
    fn is_retained(&self) -> bool;

    /// Removes reusable state selected by the global idle-group LRU.
    fn evict_retained(&mut self) -> Option<DeferredDrop>;

    /// Returns whether this is the entry identified by `state`.
    fn matches_identity(&self, state: &Arc<EntryState>) -> bool;

    /// Returns whether the entry has no active, pending, or idle work.
    fn is_empty(&self) -> bool;

    /// Returns the protocol topology constructed for this entry.
    #[cfg(test)]
    fn protocol(&self) -> Protocol;
}

/// Fixed HTTP/1 entry owning the cache and its checkout-cleanup identity.
/// Each checkout takes an exclusive sender from the cache or a new handshake.
/// Ready senders return to the cache; pending uses keep the entry from removal.
struct Http1Entry<L> {
    /// Exclusive HTTP/1 sender cache.
    service: L,
    /// Checkout count and identity-aware cleanup for this entry.
    state: Arc<EntryState>,
}

/// Fixed HTTP/2 entry sharing one connection generation across cold checkouts.
/// Once established, the sender is cloned for concurrent requests.
/// Pending uses keep the entry alive; `state` identifies it during cleanup.
#[cfg(feature = "http2")]
struct Http2Entry<R> {
    /// Shared HTTP/2 sender singleton.
    service: R,
    /// Checkout count and identity-aware cleanup for this entry.
    state: Arc<EntryState>,
}

/// Fixed HTTP/3 entry sharing one connection generation across checkouts.
#[cfg(feature = "http3")]
struct Http3Entry<M>
where
    M: Service<PoolTarget>,
{
    service: Singleton<M, PoolTarget>,
    state: Arc<EntryState>,
}

/// Entry that selects HTTP/1 or HTTP/2 after transport negotiation.
///
/// `service` combines the HTTP/1 cache and HTTP/2 singleton for one compatibility
/// group. `state` counts checkout futures and carries the identity-aware cleanup
/// operation used when the final unsuccessful checkout leaves an empty entry.
#[cfg(feature = "http2")]
struct NegotiatedEntry<L, R, S> {
    /// Fallback and upgraded pool composition.
    service: Negotiate<L, R, S>,
    /// Checkout count and failed-checkout cleanup for this entry.
    state: Arc<EntryState>,
}

/// HTTP/1 cache maintenance used by entries without naming the maker type.
trait Http1Pool:
    Service<PoolTarget, Response = Cached<http1::Connection>, Error = BoxError> + Clone + Send + 'static
{
    /// Removes closed or expired idle HTTP/1 senders.
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) -> Vec<http1::Connection>;

    /// Removes all unreserved idle HTTP/1 senders.
    fn drain_idle(&mut self) -> Vec<http1::Connection>;

    /// Returns whether at least one unreserved idle HTTP/1 sender exists.
    fn has_idle(&self) -> bool;

    /// Returns whether the HTTP/1 cache owns no services.
    fn is_empty(&self) -> bool;
}

/// Idle-management operations required from the HTTP/2 singleton.
///
/// The entry needs to inspect and remove a completed sender without starting
/// another maker. In-progress handshakes are retained because canceling them
/// would also cancel participating checkouts.
#[cfg(feature = "http2")]
trait Http2Pool: Clone + Send + 'static {
    /// Removes a closed or expired idle HTTP/2 sender.
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>)
    -> Option<http2::Connection>;

    /// Removes the completed shared HTTP/2 sender without canceling its maker.
    fn take_idle(&mut self) -> Option<http2::Connection>;

    /// Returns whether the HTTP/2 singleton is empty.
    fn is_empty(&self) -> bool;

    /// Returns whether the singleton has completed its shared sender.
    fn has_service(&self) -> bool;
}

#[cfg(feature = "http2")]
type H2MakeFuture = BoxFuture<'static, Result<http2::Connection, BoxError>>;
#[cfg(feature = "http2")]
type H2Pooled = Singled<H2MakeFuture, http2::Connection>;
#[cfg(feature = "http2")]
type H2Checkout = SingletonFuture<H2MakeFuture, http2::Connection>;

#[cfg(feature = "http3")]
type H3MakeFuture = BoxFuture<'static, Result<http3::Connection, BoxError>>;
#[cfg(feature = "http3")]
type H3Pooled = Singled<H3MakeFuture, http3::Connection>;
#[cfg(feature = "http3")]
type H3Checkout = SingletonFuture<H3MakeFuture, http3::Connection>;

/// Defers checkout completion and resource destruction until the map is unlocked.
///
/// Existing HTTP/2 and HTTP/3 generations retain their concrete singleton future. Cold
/// creation and HTTP/1 races keep the composed service future boxed. In either
/// case, the entry remains active until it is transferred to the sender.
enum Checkout {
    /// Existing singleton work, without another box around its future.
    #[cfg(feature = "http2")]
    Http2 {
        /// Owns the sender clone or pending-generation participation.
        future: H2Checkout,
        /// Redundant negotiated transports released on the first poll or drop.
        discarded: Option<DeferredDrop>,
        /// Drops after the singleton participant so cleanup sees its final state.
        usage: Option<EntryUse>,
        /// Whether the resulting sender belongs to a shared pool.
        pool_enabled: bool,
    },
    #[cfg(feature = "http3")]
    Http3 {
        future: H3Checkout,
        usage: Option<EntryUse>,
        pool_enabled: bool,
    },
    /// Composed cache or negotiation work, retaining its own scheduling state.
    Service(BoxFuture<'static, Result<Pooled, BoxError>>),
}

/// HTTP sender selected for one pool checkout.
enum PooledInner {
    Http1(Cached<http1::Connection>),
    #[cfg(feature = "http2")]
    Http2(H2Pooled),
    #[cfg(feature = "http3")]
    Http3(H3Pooled),
}

/// Type-erased connection state held until the outer map lock is released.
///
/// One value may aggregate several concrete senders from the same entry. This
/// keeps cleanup type-erased without allocating one box per removed connection.
type DeferredDrop = Box<dyn Send>;

/// Identity-aware maintenance operation for one mapped entry.
type EntryMaintenance = Box<dyn Fn(&Arc<EntryState>) + Send + Sync>;

/// Protocol-agnostic sender checked out from one pool entry.
///
/// HTTP/1 owns an exclusive [`Cached`] sender that returns to its cache on drop.
/// HTTP/2 and HTTP/3 own a [`Singled`] clone and count checkouts until response
/// headers. The wrapper presents one request interface to the client and
/// records whether a healthy sender may be retained after dispatch.
///
/// Dropping this value marks HTTP/1 idle or ends the HTTP/2 or HTTP/3 checkout.
/// Poisoned or closed senders are removed instead of being reused.
pub(super) struct Pooled {
    /// HTTP/1 cache checkout or HTTP/2 or HTTP/3 singleton checkout.
    inner: PooledInner,

    /// Whether healthy senders should return to their pool.
    pool_enabled: bool,

    /// Runs after `inner` is dropped when this checkout discarded its sender.
    cleanup: EntryCleanupGuard,
}

/// Lazily creates physical connections under the configured reuse policy.
///
/// The maker defers every expensive step until its future is polled. It may wait
/// for a reuse-first window, then runs a cloned connector through `Oneshot` so
/// readiness and `call` use the same service instance.
#[derive(Clone)]
struct ConnectionMaker<C> {
    /// Physical transport connector.
    connector: C,

    /// Optional delay giving connection reuse time to win.
    reuse_delay: Option<Duration>,

    /// Clock shared by reuse waits and transport timestamps.
    runtime: DynRuntime,
}

/// Connection-maker future with explicit started-work tracking.
///
/// `polled` distinguishes a never-started checkout from one that has entered
/// policy work. When `started` is present, it becomes true immediately before
/// the physical connector is awaited. The HTTP/1 cache uses this distinction to
/// decide whether a lost reuse race is worth completing in the background.
struct ConnectFuture<T> {
    /// Deferred delay and physical connect work.
    future: BoxFuture<'static, Result<T, BoxError>>,

    /// Records whether the future has ever been polled.
    polled: bool,

    /// Separates waiting for policy from useful connection work.
    started: Option<Arc<AtomicBool>>,
}

/// RAII count keeping a mapped entry alive while checkout is pending.
///
/// Every entry checkout creates one guard. Success disarms cleanup but still
/// decrements the use count. Failure or cancellation lets the final guard invoke
/// the entry's identity-aware cleanup operation, removing only the same empty
/// entry that created it.
struct EntryUse {
    /// Shared state of the map entry being used.
    state: Option<Arc<EntryState>>,
    /// Whether cancellation or failure should remove an empty entry.
    cleanup_on_drop: bool,
}

/// Deferred cleanup for a successful checkout that later discards its sender.
///
/// This field is declared after [`Pooled::inner`], so Rust drops the negotiated
/// sender and updates cache checkout accounting before this guard inspects the
/// mapped entry. A disarmed guard takes no lock on drop; successful return paths
/// perform their own maintenance before this guard is dropped.
struct EntryCleanupGuard {
    /// Entry identity and cleanup operation transferred from [`EntryUse`].
    state: Option<Arc<EntryState>>,
    /// Whether sender disposal may have left the mapped entry empty.
    armed: bool,
}

/// Shared checkout count and cleanup operation for one mapped entry.
///
/// The cleanup closure owns the map key and a weak pool reference once per
/// entry, rather than cloning both for every request. It also compares this
/// state's `Arc` identity before removal, so an old checkout cannot delete a new
/// entry inserted under the same key after LRU eviction.
struct EntryState {
    /// Number of checkout futures keeping the entry active.
    uses: AtomicUsize,
    /// Reconciles this exact entry with cleanup and idle-group limits.
    maintain: EntryMaintenance,
}

/// Type-erases one aggregate resource for destruction after unlocking.
fn defer_drop<T>(value: T) -> DeferredDrop
where
    T: Send + 'static,
{
    Box::new(value)
}

/// Defers a vector only when it owns at least one resource.
fn defer_drop_vec<T>(value: Vec<T>) -> Option<DeferredDrop>
where
    T: Send + 'static,
{
    (!value.is_empty()).then(|| defer_drop(value))
}

// ===== impl Pool =====

impl<C> Pool<C>
where
    C: TransportConnector,
{
    /// Builds the shared map and protocol-specific entry factory.
    ///
    /// Idle maintenance remains dormant until an entry retains reusable state.
    pub(super) fn new(config: Config, connector: C, runtime: DynRuntime, set_host: bool) -> Self {
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
                pool: pool.clone(),
                runtime: runtime.clone(),
                set_host,
                #[cfg(feature = "http3")]
                http3_connect_timeout: config.http3_connect_timeout,
            };

            PoolInner {
                enabled: config.is_enabled(),
                idle_timeout: config.idle_timeout,
                expire: Expire::new(pool.clone(), runtime),
                services: Mutex::new(Map::new(config.max_size)),
                targeter,
            }
        });

        Self { inner }
    }

    /// Checks out a sender compatible with the destination and handshake builders.
    ///
    /// The map lock is released before the returned future is polled. When
    /// pooling is disabled or the connection is dedicated, the call creates a
    /// temporary entry for this request.
    pub(super) async fn checkout(
        &self,
        config: ConnectionConfig,
        protocol: Protocol,
    ) -> Result<Pooled, BoxError> {
        let target = PoolTarget {
            config,
            protocol,
            wait_for_reuse: false,
        };

        if !self.inner.enabled || target.config.dedicated {
            return self
                .inner
                .targeter
                .service(&target)
                .checkout(target, false)
                .0
                .await;
        }

        // The guard needs a lexical scope outside await for this future to remain Send.
        let future = {
            let now = self.inner.now();
            let mut services = self.inner.services.lock();
            // Inspect only this group on checkout. A global retained-group scan
            // would add O(group count) work and nested locking to every pool hit.
            let ((future, unused), discarded) =
                services.with_service(&self.inner.targeter, target, |service, target| {
                    let discarded = service.retain(now, self.inner.idle_timeout);
                    (service.checkout(target, true), discarded)
                });
            drop(services);
            drop(unused);
            drop(discarded);
            future
        };

        future.await
    }

    /// Checks out an established HTTP/2 sender whose peer enabled extended CONNECT.
    ///
    /// Never creates entries or connections, joins pending handshakes, or touches
    /// HTTP/1 state, so a miss costs one map lookup.
    #[cfg(feature = "http2")]
    pub(super) fn checkout_extended_connect(&self, key: &ConnectionKey) -> Option<Pooled> {
        if !self.inner.enabled {
            return None;
        }
        let (service, state) = self.inner.services.lock().get_mut(key)?.checkout_made()?;
        // Pooled::new runs map maintenance, so it must stay outside the map lock.
        let connection = service.inner();
        let usable = connection.extended_connect() == Some(true)
            && connection.is_reusable(self.inner.now(), self.inner.idle_timeout);
        usable.then(|| Pooled::new_h2(service, true, EntryUse::new(state)))
    }
}

impl<C> Clone for Pool<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

// ===== impl PoolInner =====

impl<C> PoolInner<C>
where
    C: TransportConnector,
{
    /// Reads the configured runtime clock.
    fn now(&self) -> Instant {
        self.expire.now()
    }

    /// Returns the proactive idle-check interval when retained state exists.
    fn expiration_interval(&self, has_retained: bool) -> Option<Duration> {
        self.idle_timeout
            .filter(|timeout| self.enabled && has_retained && *timeout != Duration::ZERO)
            .map(|timeout| timeout.max(Duration::from_millis(90)))
    }

    /// Reconciles one entry with empty cleanup and the global idle-group LRU.
    fn maintain_entry(self: &Arc<Self>, key: &ConnectionKey, identity: &Arc<EntryState>) {
        let mut services = self.services.lock();
        // Keep per-entry maintenance independent of the retained-group count.
        // mark_retained checks other markers only before capacity eviction;
        // periodic expiration still performs the global sweep.
        let state = services.get_mut(key).and_then(|entry| {
            entry
                .matches_identity(identity)
                .then(|| (entry.is_empty(), entry.is_retained()))
        });
        let mut removed = Vec::new();
        let mut discarded = Vec::new();
        let mut schedule_expiration = false;

        match state {
            Some((true, _)) => removed.extend(services.remove_if(key, |_| true)),
            Some((false, true)) => {
                schedule_expiration = true;
                let (pruned, evicted) = services.mark_retained(key, |entry| entry.is_retained());
                // Pruned groups lost reusable state between sweeps, such as a closed
                // QUIC connection. Idle sweeps may be disabled, so clean them up here.
                if !pruned.is_empty() {
                    let now = self.now();
                    for key in &pruned {
                        let empty = services.get_mut(key).is_some_and(|entry| {
                            discarded.extend(entry.retain(now, self.idle_timeout));
                            entry.is_empty()
                        });
                        if empty {
                            removed.extend(services.remove_if(key, |_| true));
                        }
                    }
                }
                if let Some(evicted) = evicted {
                    let empty = services.get_mut(&evicted).is_some_and(|entry| {
                        discarded.extend(entry.evict_retained());
                        entry.is_empty()
                    });
                    if empty {
                        removed.extend(services.remove_if(&evicted, |_| true));
                    }
                }
            }
            Some((false, false)) => services.unmark_retained(key),
            None => {}
        }

        drop(services);
        drop(removed);
        drop(discarded);

        self.expire
            .schedule(self.expiration_interval(schedule_expiration));
    }
}

impl<C> Inspect for PoolInner<C>
where
    C: TransportConnector,
{
    fn retain(&self, now: Instant) -> Option<Duration> {
        let mut services = self.services.lock();
        let mut discarded = Vec::new();
        let mut has_retained = false;
        let removed = services.retain(|_, entry| {
            discarded.extend(entry.retain(now, self.idle_timeout));
            let keep = !entry.is_empty();
            has_retained |= keep && entry.is_retained();
            keep
        });
        services.prune_retained(|entry| entry.is_retained());
        drop(services);
        drop(removed);
        drop(discarded);
        self.expiration_interval(has_retained)
    }

    fn next(&self) -> Option<Duration> {
        let has_retained = self
            .services
            .lock()
            .iter_mut()
            .any(|(_, entry)| entry.is_retained());

        self.expiration_interval(has_retained)
    }
}

// ===== impl PoolTargeter =====

impl<C> PoolTargeter<C> {
    /// Composes an HTTP/1 cache around protocol handshaking.
    /// Only the cache's background-completion callback owns an entry-state clone.
    fn http1_layer<S, T>(
        &self,
        state: &Arc<EntryState>,
    ) -> impl Layer<S, Service = Cache<http1::Connect<S>, PoolTarget, cache::events::WithRuntime>>
    where
        S: Service<PoolTarget, Response = Established<T>, Error = BoxError> + Clone,
        S::Future: Started + Unpin,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        ServiceBuilder::new()
            .layer_fn(move |service| {
                let state = state.clone();
                cache::builder()
                    .runtime(self.runtime.clone())
                    .on_background_complete(move || (state.maintain)(&state))
                    .max_idle(self.max_idle_per_host)
                    .build(service)
            })
            .layer(http1::ConnectLayer::new(
                self.runtime.clone(),
                self.set_host,
            ))
            .into_inner()
    }
}

impl<C> Target<PoolTarget> for PoolTargeter<C>
where
    C: TransportConnector,
{
    type Key = ConnectionKey;
    type Service = Box<dyn Entry>;

    fn key(&self, target: &PoolTarget) -> Self::Key {
        target.config.req.key()
    }

    /// Builds only the pool components required by the target's protocol mode.
    fn service(&self, target: &PoolTarget) -> Self::Service {
        let pool = self.pool.clone();
        let key = target.config.req.key();
        let state = Arc::new(EntryState {
            uses: AtomicUsize::new(0),
            maintain: Box::new(move |identity| {
                let Some(pool) = pool.upgrade() else {
                    return;
                };
                pool.maintain_entry(&key, identity);
            }),
        });

        let connect = ConnectionMaker {
            connector: self.connector.clone(),
            reuse_delay: self.reuse_delay,
            runtime: self.runtime.clone(),
        };

        // Fixed protocol modes use smaller service graphs; only Auto needs both
        // pools and negotiation: https://github.com/hyperium/hyper/issues/3948
        match target.protocol {
            Protocol::Http1 => {
                let service = self.http1_layer(&state).layer(connect);
                Box::new(Http1Entry { service, state })
            }
            // QUIC dials directly, so take the maker's connector instead of cloning again.
            #[cfg(feature = "http3")]
            Protocol::Http3 => Box::new(Http3Entry {
                service: Singleton::new(http3::Connect::new(
                    connect.connector,
                    connect.runtime,
                    self.http3_connect_timeout,
                )),
                state,
            }),
            #[cfg(feature = "http2")]
            Protocol::Http2 => Box::new(Http2Entry {
                service: ServiceBuilder::new()
                    .layer_fn(Singleton::new)
                    .layer(http2::ConnectLayer::new(self.runtime.clone()))
                    .service(connect),
                state,
            }),
            #[cfg(not(feature = "http2"))]
            Protocol::Auto => {
                let service = self.http1_layer(&state).layer(connect);
                Box::new(Http1Entry { service, state })
            }
            #[cfg(feature = "http2")]
            Protocol::Auto => {
                let inspect: fn(&Established<Box<dyn AsyncConn>>) -> bool =
                    Established::should_use_http2;
                let upgrade = ServiceBuilder::new()
                    .layer_fn(Singleton::new)
                    .layer(http2::ConnectLayer::new(self.runtime.clone()));
                let service = negotiate::builder()
                    .connect(connect)
                    .inspect(inspect)
                    .fallback(self.http1_layer(&state))
                    .upgrade(upgrade)
                    .build::<PoolTarget>();

                Box::new(NegotiatedEntry { service, state })
            }
        }
    }
}

// ===== impl Http1Entry =====

impl<L> Entry for Http1Entry<L>
where
    L: Http1Pool,
    L::Future: Send,
{
    /// Checks out one exclusive HTTP/1 sender from this entry.
    ///
    /// A reuse-first delay is enabled only when the entry already contains work
    /// that may yield a sender. [`EntryUse`] keeps the map entry alive until the
    /// checkout either fails or transfers ownership to [`Pooled`].
    fn checkout(
        &mut self,
        mut target: PoolTarget,
        pool_enabled: bool,
    ) -> (Checkout, Option<ConnectionConfig>) {
        target.wait_for_reuse = pool_enabled && !self.is_empty();
        let service = self.service.clone();
        let usage = EntryUse::new(self.state.clone());
        let future = Checkout::Service(Box::pin(async move {
            Oneshot::new(service, target)
                .await
                .map(|service| Pooled::new_h1(service, pool_enabled, usage))
        }));
        (future, None)
    }

    #[cfg(feature = "http2")]
    fn checkout_made(&self) -> Option<(H2Pooled, Arc<EntryState>)> {
        None
    }

    /// Removes closed or expired idle senders for unlocked destruction.
    ///
    /// Active checkouts and FIFO waiters remain owned by the cache.
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Option<DeferredDrop> {
        defer_drop_vec(self.service.retain_idle(now, timeout))
    }

    /// Returns whether this entry contributes an idle sender to the global LRU.
    fn is_retained(&self) -> bool {
        self.service.has_idle()
    }

    /// Drains idle senders selected by the global retained-group LRU.
    ///
    /// Checked-out senders remain valid and can finish their requests.
    fn evict_retained(&mut self) -> Option<DeferredDrop> {
        defer_drop_vec(self.service.drain_idle())
    }

    /// Compares cleanup state with this exact mapped entry.
    fn matches_identity(&self, state: &Arc<EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    /// Returns whether no checkout, waiter, reservation, or sender remains.
    fn is_empty(&self) -> bool {
        self.state.uses.load(Ordering::Acquire) == 0 && self.service.is_empty()
    }

    /// Identifies the fixed HTTP/1 topology in tests.
    #[cfg(test)]
    fn protocol(&self) -> Protocol {
        Protocol::Http1
    }
}

// ===== impl Http2Entry =====

#[cfg(feature = "http2")]
impl<M> Entry for Http2Entry<Singleton<M, PoolTarget>>
where
    M: Service<PoolTarget, Response = http2::Connection, Error = BoxError, Future = H2MakeFuture>
        + Clone
        + Send
        + 'static,
{
    /// Joins the current HTTP/2 generation or starts one when the entry is empty.
    ///
    /// A fixed HTTP/2 cold start never waits for HTTP/1-style reuse. Every
    /// participant still carries [`EntryUse`] until singleton checkout finishes.
    fn checkout(
        &mut self,
        mut target: PoolTarget,
        pool_enabled: bool,
    ) -> (Checkout, Option<ConnectionConfig>) {
        target.wait_for_reuse = false;
        let usage = EntryUse::new(self.state.clone());
        if let Some(future) = self.service.checkout() {
            return (
                Checkout::Http2 {
                    future,
                    discarded: None,
                    usage: Some(usage),
                    pool_enabled,
                },
                Some(target.config),
            );
        }
        let service = self.service.clone();
        let future = Checkout::Service(Box::pin(async move {
            let service = Oneshot::new(service, target).await?;
            Ok(Pooled::new_h2(service, pool_enabled, usage))
        }));
        (future, None)
    }

    fn checkout_made(&self) -> Option<(H2Pooled, Arc<EntryState>)> {
        Some((self.service.checkout_made()?, self.state.clone()))
    }

    /// Removes a completed HTTP/2 sender when poisoned, closed, or expired idle.
    ///
    /// Pending singleton creation is left untouched. Active sender checkouts are
    /// kept by [`http2::Connection::is_reusable`].
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Option<DeferredDrop> {
        // Pending checkouts defer idle expiry, never poison or closure checks.
        let timeout = timeout.filter(|_| self.state.uses.load(Ordering::Acquire) == 0);
        self.service
            .retain(|connection| connection.is_reusable(now, timeout))
            .map(defer_drop)
    }

    /// Returns whether the singleton owns a completed reusable sender.
    fn is_retained(&self) -> bool {
        self.service.has_service()
    }

    /// Detaches the completed sender selected by the global retained-group LRU.
    ///
    /// Existing sender clones remain valid, while later checkouts create or join
    /// a new singleton generation.
    fn evict_retained(&mut self) -> Option<DeferredDrop> {
        self.service.take().map(defer_drop)
    }

    /// Compares cleanup state with this exact mapped entry.
    fn matches_identity(&self, state: &Arc<EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    /// Returns whether no checkout or singleton generation remains.
    fn is_empty(&self) -> bool {
        self.state.uses.load(Ordering::Acquire) == 0 && self.service.is_empty()
    }

    /// Identifies the fixed HTTP/2 topology in tests.
    #[cfg(test)]
    fn protocol(&self) -> Protocol {
        Protocol::Http2
    }
}

// ===== impl Http3Entry =====

#[cfg(feature = "http3")]
impl<M> Entry for Http3Entry<M>
where
    M: Service<PoolTarget, Response = http3::Connection, Error = BoxError, Future = H3MakeFuture>
        + Clone
        + Send
        + 'static,
{
    fn checkout(
        &mut self,
        mut target: PoolTarget,
        pool_enabled: bool,
    ) -> (Checkout, Option<ConnectionConfig>) {
        target.wait_for_reuse = false;
        let usage = EntryUse::new(self.state.clone());
        if let Some(future) = self.service.checkout() {
            return (
                Checkout::Http3 {
                    future,
                    usage: Some(usage),
                    pool_enabled,
                },
                Some(target.config),
            );
        }
        let service = self.service.clone();
        let future = Checkout::Service(Box::pin(async move {
            let service = Oneshot::new(service, target).await?;
            Ok(Pooled::new_h3(service, pool_enabled, usage))
        }));
        (future, None)
    }

    #[cfg(feature = "http2")]
    fn checkout_made(&self) -> Option<(H2Pooled, Arc<EntryState>)> {
        None
    }

    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Option<DeferredDrop> {
        let timeout = timeout.filter(|_| self.state.uses.load(Ordering::Acquire) == 0);
        self.service
            .retain(|connection| connection.is_reusable(now, timeout))
            .map(defer_drop)
    }

    /// Returns whether the singleton owns an open, unpoisoned sender.
    ///
    /// QUIC can close an idle connection before the next sweep; a dead sender
    /// must not keep its idle-group LRU slot and displace live groups.
    fn is_retained(&self) -> bool {
        self.service.has_service_and(|connection| {
            !connection.connected().poisoned() && !connection.is_closed()
        })
    }

    fn evict_retained(&mut self) -> Option<DeferredDrop> {
        self.service.take().map(defer_drop)
    }

    fn matches_identity(&self, state: &Arc<EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    fn is_empty(&self) -> bool {
        self.state.uses.load(Ordering::Acquire) == 0 && self.service.is_empty()
    }

    #[cfg(test)]
    fn protocol(&self) -> Protocol {
        Protocol::Http3
    }
}

// ===== impl NegotiatedEntry =====

#[cfg(feature = "http2")]
impl<L, R, T> Entry for NegotiatedEntry<L, R, Established<T>>
where
    L: Http1Pool,
    L::Future: Send,
    R: Http2Pool + Existing<Established<T>, Response = H2Pooled, Future = H2Checkout>,
    R::Error: Into<BoxError>,
    R::Future: Send,
    T: Send + 'static,
{
    /// Joins existing upgraded work or checks out through the composed service.
    fn checkout(
        &mut self,
        mut target: PoolTarget,
        pool_enabled: bool,
    ) -> (Checkout, Option<ConnectionConfig>) {
        target.wait_for_reuse = pool_enabled && !self.is_empty();
        let usage = EntryUse::new(self.state.clone());
        if let Some((future, discarded)) = self.service.checkout_existing() {
            return (
                Checkout::Http2 {
                    future,
                    discarded: (!discarded.is_empty()).then(|| defer_drop(discarded)),
                    usage: Some(usage),
                    pool_enabled,
                },
                Some(target.config),
            );
        }
        let service = self.service.clone();
        let future = Checkout::Service(Box::pin(async move {
            Oneshot::new(service, target)
                .await
                .map(|service| match service {
                    Negotiated::Left(service) => Pooled::new_h1(service, pool_enabled, usage),
                    Negotiated::Right(service) => Pooled::new_h2(service, pool_enabled, usage),
                })
        }));
        (future, None)
    }

    /// Uses only the upgraded side; HTTP/1 fallback and pending transports stay untouched.
    fn checkout_made(&self) -> Option<(H2Pooled, Arc<EntryState>)> {
        Some((self.service.upgrade().checkout_made()?, self.state.clone()))
    }

    /// Cleans pending negotiation results and both protocol pools.
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Option<DeferredDrop> {
        let entry_in_use = self.state.uses.load(Ordering::Acquire) != 0;
        let pending = if self.service.upgrade().has_service() {
            self.service.drain_pending()
        } else if !entry_in_use {
            self.service
                .retain_pending(|connection| !is_expired(connection.idle_at(), now, timeout))
        } else {
            Default::default()
        };
        let fallback = self.service.fallback_mut().retain_idle(now, timeout);
        // Keep health checks active while another checkout protects against idle expiry.
        let upgrade = self
            .service
            .upgrade_mut()
            .retain_idle(now, timeout.filter(|_| !entry_in_use));

        (!pending.is_empty() || !fallback.is_empty() || upgrade.is_some())
            .then(|| defer_drop((pending, fallback, upgrade)))
    }

    /// Reports reusable connections owned by any negotiated path.
    fn is_retained(&self) -> bool {
        !self.service.pending_is_empty()
            || self.service.fallback().has_idle()
            || self.service.upgrade().has_service()
    }

    /// Drains every reusable connection while preserving active HTTP/1 work.
    fn evict_retained(&mut self) -> Option<DeferredDrop> {
        let pending = self.service.drain_pending();
        let fallback = self.service.fallback_mut().drain_idle();
        let upgrade = self.service.upgrade_mut().take_idle();

        (!pending.is_empty() || !fallback.is_empty() || upgrade.is_some())
            .then(|| defer_drop((pending, fallback, upgrade)))
    }

    /// Compares shared checkout state with this exact entry instance.
    fn matches_identity(&self, state: &Arc<EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    /// Returns whether no checkout or protocol pool state remains.
    fn is_empty(&self) -> bool {
        self.state.uses.load(Ordering::Acquire) == 0
            && self.service.pending_is_empty()
            && self.service.fallback().is_empty()
            && self.service.upgrade().is_empty()
    }

    /// Identifies the negotiated HTTP/1-or-HTTP/2 topology in tests.
    #[cfg(test)]
    fn protocol(&self) -> Protocol {
        Protocol::Auto
    }
}

// ===== impl Checkout =====

impl Future for Checkout {
    type Output = Result<Pooled, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            #[cfg(feature = "http2")]
            Self::Http2 {
                future,
                discarded,
                usage,
                pool_enabled,
                ..
            } => {
                drop(discarded.take());
                let result = std::task::ready!(Pin::new(future).poll(cx));
                let Some(usage) = usage.take() else {
                    return Poll::Pending;
                };
                // Pooled::new starts H2 accounting before releasing EntryUse and
                // may run map maintenance, so it must execute outside the lock.
                Poll::Ready(
                    result
                        .map(|service| Pooled::new_h2(service, *pool_enabled, usage))
                        .map_err(Into::into),
                )
            }
            #[cfg(feature = "http3")]
            Self::Http3 {
                future,
                usage,
                pool_enabled,
            } => {
                let result = std::task::ready!(Pin::new(future).poll(cx));
                let Some(usage) = usage.take() else {
                    return Poll::Pending;
                };
                Poll::Ready(
                    result
                        .map(|service| Pooled::new_h3(service, *pool_enabled, usage))
                        .map_err(Into::into),
                )
            }
            Self::Service(future) => future.as_mut().poll(cx),
        }
    }
}

// ===== impl Cache =====

impl<M, Ev> Http1Pool for Cache<M, PoolTarget, Ev>
where
    M: Service<PoolTarget, Response = http1::Connection, Error = BoxError> + Clone + Send + 'static,
    M::Future: Unpin + Send,
    M::Response: Unpin,
    Ev: cache::events::Events<BackgroundConnect<M::Future, M::Response>>
        + Clone
        + Send
        + Unpin
        + 'static,
{
    /// Retains reusable HTTP/1 senders.
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) -> Vec<http1::Connection> {
        self.retain(|connection| connection.is_reusable(now, timeout))
    }

    /// Drains unreserved idle HTTP/1 senders.
    fn drain_idle(&mut self) -> Vec<http1::Connection> {
        Cache::drain_idle(self)
    }

    /// Reports whether an unreserved HTTP/1 sender is idle.
    fn has_idle(&self) -> bool {
        Cache::has_idle(self)
    }

    /// Returns whether the cache owns no ready, idle, or active sender.
    fn is_empty(&self) -> bool {
        Cache::is_empty(self)
    }
}

// ===== impl Singleton =====

#[cfg(feature = "http2")]
impl<M, Dst> Http2Pool for Singleton<M, Dst>
where
    M: Service<Dst, Response = http2::Connection> + Clone + Send + 'static,
    M::Future: Send + 'static,
    Dst: Send + 'static,
{
    /// Removes a completed sender only when the pool's health policy rejects it.
    ///
    /// A maker generation still in progress is never canceled by maintenance.
    fn retain_idle(
        &mut self,
        now: Instant,
        timeout: Option<Duration>,
    ) -> Option<http2::Connection> {
        self.retain(|connection| connection.is_reusable(now, timeout))
    }

    /// Detaches the completed sender without interrupting an active maker.
    fn take_idle(&mut self) -> Option<http2::Connection> {
        self.take()
    }

    /// Returns whether neither a completed sender nor a maker generation exists.
    fn is_empty(&self) -> bool {
        Singleton::is_empty(self)
    }

    /// Returns whether singleton creation has produced a shared sender.
    fn has_service(&self) -> bool {
        self.has_service()
    }
}

#[cfg(feature = "http2")]
impl<M, S> Existing<S> for Singleton<M, S>
where
    M: Service<S>,
    M::Response: Clone,
    M::Error: Into<BoxError>,
{
    /// Joins only existing or in-progress singleton state.
    fn checkout(&self) -> Option<Self::Future> {
        Singleton::checkout(self)
    }

    fn checkout_made(&self) -> Option<Self::Response> {
        Singleton::checkout_made(self)
    }
}

// ===== impl ConnectionMaker =====

impl<C> Service<PoolTarget> for ConnectionMaker<C>
where
    C: TransportConnector,
{
    type Response = Established<Box<dyn AsyncConn>>;
    type Error = BoxError;
    type Future = ConnectFuture<Self::Response>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: PoolTarget) -> Self::Future {
        let PoolTarget {
            config,
            protocol,
            wait_for_reuse,
        } = target;
        #[cfg(not(feature = "http2"))]
        let _ = protocol;
        let reuse_delay = if wait_for_reuse {
            self.reuse_delay
        } else {
            None
        };
        let started = reuse_delay
            .is_some()
            .then(|| Arc::new(AtomicBool::new(false)));
        let start_signal = started.clone();
        let connector = self.connector.clone();
        let runtime = self.runtime.clone();

        let future = Box::pin(async move {
            if let Some(duration) = reuse_delay {
                runtime.sleep(duration).await;
            }

            if let Some(started) = &start_signal {
                started.store(true, Ordering::Release);
            }

            let Conn {
                inner: io,
                connected,
            } = Oneshot::new(connector, config.req.clone()).await?;
            #[cfg(feature = "http3")]
            let Either::Left(io) = io else {
                return Err("stream connection returned QUIC".into());
            };

            Ok(Established::new(
                io,
                connected,
                #[cfg(feature = "http2")]
                protocol,
                config,
                #[cfg(feature = "http2")]
                runtime.now(),
            ))
        });

        ConnectFuture {
            future,
            polled: false,
            started,
        }
    }
}

// ===== impl ConnectFuture =====

impl<T> Future for ConnectFuture<T> {
    type Output = Result<T, BoxError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.polled = true;
        self.future.as_mut().poll(cx)
    }
}

impl<T> Started for ConnectFuture<T> {
    fn started(&self) -> bool {
        self.started
            .as_ref()
            .map_or(self.polled, |started| started.load(Ordering::Acquire))
    }
}

// ===== impl Pooled =====

impl Pooled {
    /// Wraps a negotiated sender and registers an HTTP/2 or HTTP/3 checkout when needed.
    fn new(inner: PooledInner, pool_enabled: bool, usage: EntryUse) -> Self {
        match &inner {
            PooledInner::Http1(_) => {}
            #[cfg(feature = "http2")]
            PooledInner::Http2(service) => service.inner().begin_checkout(),
            #[cfg(feature = "http3")]
            PooledInner::Http3(service) => service.inner().begin_checkout(),
        }
        let cleanup = usage.into_cleanup();
        if pool_enabled {
            cleanup.maintain();
        }
        Self {
            inner,
            pool_enabled,
            cleanup,
        }
    }

    fn new_h1(service: Cached<http1::Connection>, pool_enabled: bool, usage: EntryUse) -> Self {
        Self::new(PooledInner::Http1(service), pool_enabled, usage)
    }

    #[cfg(feature = "http2")]
    fn new_h2(service: H2Pooled, pool_enabled: bool, usage: EntryUse) -> Self {
        Self::new(PooledInner::Http2(service), pool_enabled, usage)
    }

    #[cfg(feature = "http3")]
    fn new_h3(service: H3Pooled, pool_enabled: bool, usage: EntryUse) -> Self {
        Self::new(PooledInner::Http3(service), pool_enabled, usage)
    }

    #[cfg(feature = "http3")]
    pub(super) fn is_http3(&self) -> bool {
        matches!(self.inner, PooledInner::Http3(_))
    }

    /// Returns whether this checkout uses HTTP/1.
    pub(super) fn is_http1(&self) -> bool {
        matches!(self.inner, PooledInner::Http1(_))
    }

    /// Returns whether this checkout uses HTTP/2.
    pub(super) fn is_http2(&self) -> bool {
        match self.inner {
            PooledInner::Http1(_) => false,
            #[cfg(feature = "http3")]
            PooledInner::Http3(_) => false,
            #[cfg(feature = "http2")]
            PooledInner::Http2(_) => true,
        }
    }

    /// Returns whether the peer enabled extended CONNECT, or `None` before its SETTINGS.
    /// HTTP/1 never supports it.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) fn extended_connect(&self) -> Option<bool> {
        match &self.inner {
            PooledInner::Http1(_) => Some(false),
            #[cfg(feature = "http2")]
            PooledInner::Http2(service) => service.inner().extended_connect(),
            #[cfg(feature = "http3")]
            PooledInner::Http3(service) => service.inner().extended_connect(),
        }
    }

    /// Returns whether the sender came from an existing pooled connection.
    pub(super) fn is_reused(&self) -> bool {
        match &self.inner {
            PooledInner::Http1(service) => service.is_reused(),
            #[cfg(feature = "http2")]
            PooledInner::Http2(service) => service.is_reused(),
            #[cfg(feature = "http3")]
            PooledInner::Http3(service) => service.is_reused(),
        }
    }

    /// Returns whether completed senders may be retained for reuse.
    pub(super) fn is_pool_enabled(&self) -> bool {
        self.pool_enabled
    }

    /// Returns whether the protocol sender can accept a request immediately.
    pub(super) fn is_ready(&self) -> bool {
        match &self.inner {
            PooledInner::Http1(service) => service.inner().is_ready(),
            #[cfg(feature = "http2")]
            PooledInner::Http2(service) => service.inner().is_ready(),
            #[cfg(feature = "http3")]
            PooledInner::Http3(service) => service.inner().is_ready(),
        }
    }

    /// Returns metadata for the underlying physical connection.
    pub(super) fn connected(&self) -> &Connected {
        match &self.inner {
            PooledInner::Http1(service) => service.inner().connected(),
            #[cfg(feature = "http2")]
            PooledInner::Http2(service) => service.inner().connected(),
            #[cfg(feature = "http3")]
            PooledInner::Http3(service) => service.inner().connected(),
        }
    }
}

impl Service<Request<Body>> for Pooled {
    type Response = Response<Incoming>;
    type Error = SendError;
    cfg_select! {
        all(feature = "http2", feature = "http3") => {
            type Future = futures_util::future::Either<
                futures_util::future::Either<
                    <http1::Connection as Service<Request<Body>>>::Future,
                    <http2::Connection as Service<Request<Body>>>::Future,
                >,
                <http3::Connection as Service<Request<Body>>>::Future,
            >;
        }
        feature = "http2" => {
            type Future = futures_util::future::Either<
                <http1::Connection as Service<Request<Body>>>::Future,
                <http2::Connection as Service<Request<Body>>>::Future,
            >;
        }
        feature = "http3" => {
            type Future = futures_util::future::Either<
                <http1::Connection as Service<Request<Body>>>::Future,
                <http3::Connection as Service<Request<Body>>>::Future,
            >;
        }
        _ => {
            type Future = <http1::Connection as Service<Request<Body>>>::Future;
        }
    }

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        match &mut self.inner {
            PooledInner::Http1(service) => service.poll_ready(cx),
            #[cfg(feature = "http2")]
            PooledInner::Http2(service) => service.poll_ready(cx),
            #[cfg(feature = "http3")]
            PooledInner::Http3(service) => service.poll_ready(cx),
        }
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        match &mut self.inner {
            PooledInner::Http1(service) => {
                let future = service.call(req);
                #[cfg(feature = "http2")]
                let future = futures_util::future::Either::Left(future);
                #[cfg(feature = "http3")]
                let future = futures_util::future::Either::Left(future);
                future
            }
            #[cfg(feature = "http2")]
            PooledInner::Http2(service) => {
                let future = futures_util::future::Either::Right(service.call(req));
                #[cfg(feature = "http3")]
                let future = futures_util::future::Either::Left(future);
                future
            }
            #[cfg(feature = "http3")]
            PooledInner::Http3(service) => futures_util::future::Either::Right(service.call(req)),
        }
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        match &mut self.inner {
            PooledInner::Http1(service) => {
                service.inner_mut().mark_idle();
                if !service.inner().is_open() {
                    service.discard_on_drop();
                }
                let returned = service.return_to_cache();
                if self.pool_enabled {
                    if returned {
                        self.cleanup.maintain();
                    } else {
                        self.cleanup.arm();
                    }
                }
            }
            #[cfg(feature = "http2")]
            PooledInner::Http2(service) => {
                let discard = {
                    let connection = service.inner();
                    connection.finish_checkout();
                    connection.connected().poisoned() || connection.is_closed()
                };
                if discard {
                    service.discard_shared();
                }
                if self.pool_enabled && discard {
                    self.cleanup.arm();
                }
            }
            #[cfg(feature = "http3")]
            PooledInner::Http3(service) => {
                let discard = {
                    let connection = service.inner();
                    connection.finish_checkout();
                    connection.connected().poisoned() || connection.is_closed()
                };
                if discard {
                    service.discard_shared();
                }
                if self.pool_enabled && discard {
                    self.cleanup.arm();
                }
            }
        }
    }
}

impl fmt::Debug for Pooled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let version = match self.inner {
            PooledInner::Http1(_) => http::Version::HTTP_11,
            #[cfg(feature = "http2")]
            PooledInner::Http2(_) => http::Version::HTTP_2,
            #[cfg(feature = "http3")]
            PooledInner::Http3(_) => http::Version::HTTP_3,
        };
        f.debug_struct("Pooled")
            .field("version", &version)
            .field("reused", &self.is_reused())
            .finish()
    }
}

// ===== impl EntryUse =====

impl EntryUse {
    /// Registers one checkout against a mapped pool entry.
    fn new(state: Arc<EntryState>) -> Self {
        let _ = state
            .uses
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_add(1))
            });
        Self {
            state: Some(state),
            cleanup_on_drop: true,
        }
    }

    /// Transfers successful-checkout cleanup to the returned pooled sender.
    fn into_cleanup(mut self) -> EntryCleanupGuard {
        self.cleanup_on_drop = false;
        let state = self.state.take();
        if let Some(state) = &state {
            let _ = state
                .uses
                .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    Some(count.saturating_sub(1))
                });
        }
        EntryCleanupGuard {
            state,
            armed: false,
        }
    }
}

impl Drop for EntryUse {
    fn drop(&mut self) {
        let Some(state) = &self.state else {
            return;
        };
        let previous = state
            .uses
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            });
        if self.cleanup_on_drop && previous == Ok(1) {
            (state.maintain)(state);
        }
    }
}

// ===== impl EntryCleanupGuard =====

impl EntryCleanupGuard {
    /// Reconciles retained state immediately after a successful transition.
    fn maintain(&self) {
        if let Some(state) = &self.state {
            (state.maintain)(state);
        }
    }

    /// Requests one identity-aware empty-entry check after sender destruction.
    fn arm(&mut self) {
        self.armed = true;
    }
}

impl Drop for EntryCleanupGuard {
    fn drop(&mut self) {
        if self.armed
            && let Some(state) = &self.state
        {
            (state.maintain)(state);
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "http2")]
    use std::hash::{Hash, Hasher};
    use std::io;
    #[cfg(feature = "http3")]
    use std::net::{Ipv4Addr, SocketAddr};

    #[cfg(feature = "http3")]
    use ::quic::crypto::rustls::QuicClientConfig;
    #[cfg(feature = "http2")]
    use bytes::Bytes;
    #[cfg(feature = "http2")]
    use http_body_util::Empty;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    #[cfg(feature = "http2")]
    use crate::conn::config::{ConfigScope, ConnectConfig};
    #[cfg(feature = "http3")]
    use crate::conn::transport::test_server_config;
    use crate::{conn::config::ConfigSet, group::Group};

    /// Connector behavior used to exercise unsuccessful checkout cleanup.
    #[derive(Clone)]
    enum TestConnector {
        /// Fails the connection attempt immediately.
        Fails,
        /// Keeps the connection attempt pending until cancellation.
        Pending,
        /// Completes one request and then closes the transport.
        ClosesAfterResponse,
        /// Keeps the transport reusable until the client drops its sender.
        KeepsAlive,
        /// Accepts a request without producing response headers.
        StallsAfterRequest(Arc<tokio::sync::Notify>),
        /// Counts HTTP/2 connection attempts and gates transport creation.
        #[cfg(feature = "http2")]
        Http2(Arc<AtomicUsize>, Arc<tokio::sync::Semaphore>),
        /// Opens a fresh QUIC connection to the local server at this address.
        #[cfg(feature = "http3")]
        Http3(SocketAddr, ::quic::ClientConfig),
    }

    impl Service<ConnectRequest> for TestConnector {
        type Response = Conn;
        type Error = BoxError;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ConnectRequest) -> Self::Future {
            match self {
                Self::Fails => Box::pin(std::future::ready(Err(io::Error::from(
                    io::ErrorKind::ConnectionRefused,
                )
                .into()))),
                Self::Pending => Box::pin(std::future::pending()),
                #[cfg(feature = "http3")]
                Self::Http3(server, config) => {
                    let (server, config) = (*server, config.clone());
                    Box::pin(async move {
                        let endpoint = ::quic::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
                        let connection =
                            endpoint.connect_with(config, server, "localhost")?.await?;
                        Ok(Conn {
                            inner: Either::Right((connection, endpoint)),
                            connected: Connected::new(),
                        })
                    })
                }
                #[cfg(feature = "http2")]
                Self::Http2(calls, gate) => {
                    calls.fetch_add(1, Ordering::Relaxed);
                    let gate = gate.clone();
                    Box::pin(async move {
                        gate.acquire().await.unwrap().forget();
                        let (client, server) = tokio::io::duplex(4096);
                        tokio::spawn(async move {
                            let service = hyper::service::service_fn(|_| async {
                                Ok::<_, io::Error>(Response::new(Empty::<Bytes>::new()))
                            });
                            let _ = hyper::server::conn::http2::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            )
                            .enable_connect_protocol()
                            .serve_connection(hyper_util::rt::TokioIo::new(server), service)
                            .await;
                        });
                        Ok(Conn::test(client))
                    })
                }
                Self::ClosesAfterResponse => Box::pin(async {
                    let (client, mut server) = tokio::io::duplex(1024);
                    tokio::spawn(async move {
                        let mut request = [0; 1024];
                        let read = server.read(&mut request).await.expect("read request");
                        assert!(read > 0);
                        server
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                            )
                            .await
                            .expect("write response");
                    });
                    Ok(Conn::test(client))
                }),
                Self::KeepsAlive => Box::pin(async {
                    let (client, mut server) = tokio::io::duplex(1024);
                    tokio::spawn(async move {
                        let mut request = [0; 1024];
                        let read = server.read(&mut request).await.expect("read request");
                        if read == 0 {
                            return;
                        }
                        server
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .expect("write response");
                        while server.read(&mut request).await.unwrap_or_default() != 0 {}
                    });
                    Ok(Conn::test(client))
                }),
                Self::StallsAfterRequest(request_read) => {
                    let request_read = request_read.clone();
                    Box::pin(async move {
                        let (client, mut server) = tokio::io::duplex(1024);
                        tokio::spawn(async move {
                            let mut request = [0; 1024];
                            let read = server.read(&mut request).await.expect("read request");
                            assert!(read > 0);
                            request_read.notify_one();
                            std::future::pending::<()>().await;
                        });
                        Ok(Conn::test(client))
                    })
                }
            }
        }
    }

    /// Creates connection inputs for a local test origin.
    fn connect_request() -> ConnectRequest {
        grouped_request(Group::new("test"))
    }

    /// Supplies default protocol configuration for a test connection.
    fn connection_config(req: ConnectRequest) -> ConnectionConfig {
        ConnectionConfig {
            req,
            proto: Arc::new(ProtocolBuilders {
                http1: conn::http1::Builder::default(),
                #[cfg(feature = "http2")]
                http2: conn::http2::Builder::new(DynRuntime::new(crate::rt::tokio::TokioRuntime)),
                #[cfg(feature = "http3")]
                http3: conn::http3::Builder::new(DynRuntime::new(crate::rt::tokio::TokioRuntime)),
            }),
            dedicated: false,
        }
    }

    /// Creates connection inputs with an explicit compatibility group.
    fn grouped_request(group: Group) -> ConnectRequest {
        let mut config_set = ConfigSet::default();
        config_set.insert(group);
        ConnectRequest::test(
            http::Uri::from_static("http://localhost/"),
            None,
            config_set,
        )
    }

    /// Creates a pool without periodic cleanup so empty-entry removal is explicit.
    fn test_pool(connector: TestConnector) -> Pool<TestConnector> {
        Pool::new(
            Config {
                idle_timeout: None,
                ..Config::default()
            },
            connector,
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
            true,
        )
    }

    /// Starts a local QUIC server and returns a connector trusting its certificate.
    /// The server keeps every accepted connection open until the test runtime ends.
    #[cfg(feature = "http3")]
    fn http3_connector() -> TestConnector {
        let (config, cert) = test_server_config();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.into()).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];

        let server = ::quic::Endpoint::server(config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let address = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut peers = Vec::new();
            while let Some(incoming) = server.accept().await {
                peers.extend(incoming.await);
            }
        });
        TestConnector::Http3(
            address,
            ::quic::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap())),
        )
    }

    #[test]
    fn protocol_modes_build_specialized_entries() {
        /// Counts connector copies made while composing protocol entries.
        /// Shares the counter between clones without creating a transport.
        /// Captured by the connector closure to observe service graph construction.
        struct CloneCounter(Arc<AtomicUsize>);

        impl Clone for CloneCounter {
            fn clone(&self) -> Self {
                self.0.fetch_add(1, Ordering::Relaxed);
                Self(self.0.clone())
            }
        }

        let clones = Arc::new(AtomicUsize::new(0));
        let counter = CloneCounter(clones.clone());
        let connector = tower::service_fn(move |_: ConnectRequest| {
            let _counter = &counter;
            std::future::pending::<Result<Conn, BoxError>>()
        });
        let pool = Pool::new(
            Config::default(),
            connector,
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
            true,
        );
        assert_eq!(clones.load(Ordering::Relaxed), 0);

        for (index, protocol) in [
            Protocol::Http1,
            #[cfg(feature = "http2")]
            Protocol::Http2,
            #[cfg(feature = "http3")]
            Protocol::Http3,
            Protocol::Auto,
        ]
        .into_iter()
        .enumerate()
        {
            let target = PoolTarget {
                config: connection_config(connect_request()),
                protocol,
                wait_for_reuse: false,
            };
            let entry = pool.inner.targeter.service(&target);

            let expected = match protocol {
                #[cfg(not(feature = "http2"))]
                Protocol::Auto => Protocol::Http1,
                protocol => protocol,
            };
            assert_eq!(entry.protocol(), expected);
            assert_eq!(clones.load(Ordering::Relaxed), index + 1);
        }
    }

    #[tokio::test]
    #[cfg(feature = "http2")]
    async fn http2_checkouts_preserve_generation_and_cancellation() {
        /// Records when one checkout's configuration is finally released.
        /// Its QUIC scope keeps it out of the HTTP/2 and Auto pool identities.
        #[derive(Clone)]
        struct Released(Arc<AtomicBool>);

        impl PartialEq for Released {
            fn eq(&self, _other: &Self) -> bool {
                true
            }
        }

        impl Eq for Released {}

        impl Hash for Released {
            fn hash<H: Hasher>(&self, state: &mut H) {
                state.write_u8(0);
            }
        }

        impl ConnectConfig for Released {
            const SCOPE: ConfigScope = ConfigScope::QUIC;
        }

        impl Drop for Released {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        for protocol in [Protocol::Http2, Protocol::Auto] {
            let calls = Arc::new(AtomicUsize::new(0));
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let pool = test_pool(TestConnector::Http2(calls.clone(), gate.clone()));
            let checkout = || {
                let released = Arc::new(AtomicBool::new(false));
                let req = connect_request();
                let mut config_set = req.config_set().clone();
                config_set.insert(Released(released.clone()));
                let target = PoolTarget {
                    config: connection_config(ConnectRequest::test(
                        req.uri().clone(),
                        req.protocol(),
                        config_set,
                    )),
                    protocol,
                    wait_for_reuse: false,
                };
                let (future, unused) = pool.inner.services.lock().with_service(
                    &pool.inner.targeter,
                    target,
                    |entry, mut target| {
                        assert_eq!(entry.protocol(), protocol);
                        // Exercise the Auto graph without TLS by selecting H2 at
                        // the transport stage, where ALPN would normally choose it.
                        target.protocol = Protocol::Http2;
                        let checkout = entry.checkout(target, true);
                        assert!(!released.load(Ordering::Relaxed));
                        checkout
                    },
                );
                let reused = unused.is_some();
                drop(unused);
                assert_eq!(released.load(Ordering::Relaxed), reused);
                future
            };

            let mut driver = tokio_test::task::spawn(checkout());
            assert!(driver.poll().is_pending());
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            let held = if protocol == Protocol::Http2 {
                let waiter = checkout();
                assert!(matches!(waiter, Checkout::Http2 { .. }));
                let mut waiter = tokio_test::task::spawn(waiter);
                assert!(waiter.poll().is_pending());
                drop(driver);
                assert!(waiter.is_woken());
                gate.add_permits(1);
                let held = tokio::time::timeout(Duration::from_secs(1), waiter)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(held.is_reused());
                held
            } else {
                // Auto has no singleton generation until transport negotiation.
                gate.add_permits(1);
                tokio::time::timeout(Duration::from_secs(1), driver)
                    .await
                    .unwrap()
                    .unwrap()
            };

            let mut checkouts = Vec::new();
            for i in 0..100 {
                let future = checkout();
                assert!(matches!(future, Checkout::Http2 { .. }));
                if i % 2 == 0 {
                    checkouts.push(future);
                }
            }
            for pooled in futures_util::future::join_all(checkouts).await {
                assert!(pooled.unwrap().is_reused());
            }
            assert_eq!(calls.load(Ordering::Relaxed), 1);

            let pending = checkout();
            let completed = checkout().await.unwrap();
            let connected = completed.connected().clone();
            drop(completed);
            // Response::forbid_recycle poisons after dispatch releases its checkout.
            // Another unpolled checkout must not suppress this health check.
            connected.poison();
            let discarded = pool
                .inner
                .services
                .lock()
                .get_mut(&connect_request().key())
                .unwrap()
                .retain(pool.inner.now(), None);
            assert!(
                discarded.is_some(),
                "{protocol:?}: poisoned sender was retained"
            );
            drop(discarded);
            gate.add_permits(1);
            let mut replacement = tokio::time::timeout(Duration::from_secs(1), checkout())
                .await
                .unwrap()
                .unwrap();
            assert!(!replacement.is_reused());
            drop(pending);
            drop(held);
            assert!(checkout().await.unwrap().is_reused());
            assert_eq!(calls.load(Ordering::Relaxed), 2);
            assert_eq!(pool.inner.services.lock().iter_mut().count(), 1);

            let response = Oneshot::new(
                &mut replacement,
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(response.version(), http::Version::HTTP_2);
            replacement.connected().poison();
            drop(replacement);
            assert!(pool.inner.services.lock().is_empty());

            let mut driver = tokio_test::task::spawn(checkout());
            assert!(driver.poll().is_pending());
            let waiter = checkout();
            drop(driver);
            drop(waiter);
            assert!(pool.inner.services.lock().is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_task_tracks_reusable_state() {
        let pool = Pool::new(
            Config {
                idle_timeout: Some(Duration::from_millis(10)),
                ..Config::default()
            },
            TestConnector::KeepsAlive,
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
            true,
        );
        let pooled = pool
            .checkout(connection_config(connect_request()), Protocol::Http1)
            .await
            .expect("successful checkout");

        assert!(!pool.inner.expire.is_running());
        drop(pooled);
        tokio::task::yield_now().await;
        assert!(pool.inner.expire.is_running());

        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;

        assert!(pool.inner.services.lock().is_empty());
        assert!(!pool.inner.expire.is_running());

        let pool = Pool::new(
            Config {
                idle_timeout: Some(Duration::ZERO),
                ..Config::default()
            },
            TestConnector::KeepsAlive,
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
            true,
        );
        let pooled = pool
            .checkout(connection_config(connect_request()), Protocol::Http1)
            .await
            .expect("successful checkout");

        drop(pooled);
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;

        assert!(!pool.inner.services.lock().is_empty());
        assert!(!pool.inner.expire.is_running());
    }

    #[tokio::test]
    async fn idle_task_waits_for_a_runtime_after_off_runtime_drop() {
        let pool = Pool::new(
            Config {
                idle_timeout: Some(Duration::from_secs(60)),
                ..Config::default()
            },
            TestConnector::KeepsAlive,
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
            true,
        );
        let checkout = || pool.checkout(connection_config(connect_request()), Protocol::Http1);

        // Returning a connection on a thread without a runtime keeps it pooled but
        // cannot start the watcher.
        let pooled = checkout().await.expect("successful checkout");
        std::thread::spawn(move || drop(pooled))
            .join()
            .expect("drop without a runtime");
        tokio::task::yield_now().await;
        assert!(!pool.inner.expire.is_running());

        // The next return on the runtime starts it.
        let pooled = checkout().await.expect("reused checkout");
        assert!(pooled.is_reused());
        drop(pooled);
        tokio::task::yield_now().await;
        assert!(pool.inner.expire.is_running());
    }

    #[tokio::test]
    #[cfg(feature = "http2")]
    async fn extended_connect_checkout_only_clones_established_senders() {
        for protocol in [Protocol::Http2, Protocol::Auto] {
            let calls = Arc::new(AtomicUsize::new(0));
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let pool = test_pool(TestConnector::Http2(calls.clone(), gate.clone()));
            let key = connect_request().key();
            let checkout = || {
                let target = PoolTarget {
                    config: connection_config(connect_request()),
                    protocol,
                    wait_for_reuse: false,
                };
                let (future, _) = pool.inner.services.lock().with_service(
                    &pool.inner.targeter,
                    target,
                    |entry, mut target| {
                        // Auto selects H2 where ALPN would, as in the generation test.
                        target.protocol = Protocol::Http2;
                        entry.checkout(target, true)
                    },
                );
                future
            };

            // A miss neither connects nor leaves an entry behind.
            assert!(pool.checkout_extended_connect(&key).is_none());
            assert!(pool.inner.services.lock().get_mut(&key).is_none());

            // A generation still being made is not joined.
            let mut making = tokio_test::task::spawn(checkout());
            assert!(making.poll().is_pending());
            assert!(pool.checkout_extended_connect(&key).is_none());
            gate.add_permits(1);
            let mut pooled = making.await.unwrap();
            // Support is unknown until the peer's SETTINGS; the probe must not guess.
            assert_eq!(pooled.extended_connect(), None);
            assert!(pool.checkout_extended_connect(&key).is_none());

            // A response proves the peer's SETTINGS were applied.
            let request = Request::get("http://localhost/")
                .body(crate::Body::default())
                .unwrap();
            pooled.call(request).await.unwrap();
            drop(pooled);
            let probed = pool.checkout_extended_connect(&key).unwrap();
            assert!(probed.is_http2() && probed.is_reused());
            assert_eq!(probed.extended_connect(), Some(true));
            assert_eq!(calls.load(Ordering::Relaxed), 1);

            // Unusable senders are skipped without the probe evicting them.
            probed.connected().poison();
            assert!(pool.checkout_extended_connect(&key).is_none());
            assert!(pool.inner.services.lock().get_mut(&key).is_some());
            // A probed checkout discards its sender like any other.
            drop(probed);
            assert!(pool.inner.services.lock().get_mut(&key).is_none());
        }
    }

    #[tokio::test]
    async fn checkouts_remove_empty_map_entries() {
        for protocol in [
            Protocol::Http1,
            #[cfg(feature = "http2")]
            Protocol::Http2,
            #[cfg(feature = "http3")]
            Protocol::Http3,
            Protocol::Auto,
        ] {
            let pool = test_pool(TestConnector::Fails);
            let result = pool
                .checkout(connection_config(connect_request()), protocol)
                .await;
            assert!(result.is_err());
            assert!(pool.inner.services.lock().is_empty());
            assert!(!pool.inner.expire.is_running());

            let pool = test_pool(TestConnector::Pending);
            let mut first = tokio_test::task::spawn(
                pool.checkout(connection_config(connect_request()), protocol),
            );
            let mut second = tokio_test::task::spawn(
                pool.checkout(connection_config(connect_request()), protocol),
            );
            assert!(first.poll().is_pending());
            assert!(second.poll().is_pending());
            drop(first);
            assert!(!pool.inner.services.lock().is_empty());
            drop(second);
            assert!(pool.inner.services.lock().is_empty());
            assert!(!pool.inner.expire.is_running());
        }

        let pool = test_pool(TestConnector::ClosesAfterResponse);
        let mut pooled = pool
            .checkout(connection_config(connect_request()), Protocol::Http1)
            .await
            .expect("successful checkout");
        std::future::poll_fn(|cx| pooled.poll_ready(cx))
            .await
            .expect("ready sender");
        let response = pooled
            .call(
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            )
            .await
            .expect("successful request");
        assert_eq!(response.status(), http::StatusCode::OK);
        assert!(
            std::future::poll_fn(|cx| pooled.poll_ready(cx))
                .await
                .is_err()
        );
        drop(pooled);

        assert!(pool.inner.services.lock().is_empty());
        assert!(!pool.inner.expire.is_running());

        let request_read = Arc::new(tokio::sync::Notify::new());
        let pool = test_pool(TestConnector::StallsAfterRequest(request_read.clone()));
        let mut pooled = pool
            .checkout(connection_config(connect_request()), Protocol::Http1)
            .await
            .expect("successful checkout");
        std::future::poll_fn(|cx| pooled.poll_ready(cx))
            .await
            .expect("ready sender");
        let mut response = tokio_test::task::spawn(
            pooled.call(
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            ),
        );
        assert!(response.poll().is_pending());
        tokio::time::timeout(Duration::from_secs(1), request_read.notified())
            .await
            .expect("request should reach server");
        drop(response);
        drop(pooled);

        assert!(pool.inner.services.lock().is_empty());
        assert!(!pool.inner.expire.is_running());

        let pool = test_pool(TestConnector::KeepsAlive);
        let req = grouped_request(Group::new("active"));
        let mut first = pool
            .checkout(connection_config(req.clone()), Protocol::Http1)
            .await
            .expect("first checkout");
        std::future::poll_fn(|cx| first.poll_ready(cx))
            .await
            .expect("ready sender");
        first
            .call(
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            )
            .await
            .expect("successful request");

        // An in-flight HTTP/1 sender can disappear from its idle cache while
        // still needing that cache for its return. This regression was found in:
        // https://github.com/smithy-lang/smithy-rs/commit/998e5fb9254bf972aa9c6f6e82e521afd627613e
        let (removed, discarded) = {
            let mut services = pool.inner.services.lock();
            let mut discarded = Vec::new();
            let removed = services.retain(|_, entry| {
                discarded.extend(entry.retain(pool.inner.now(), Some(Duration::ZERO)));
                !entry.is_empty()
            });
            (removed, discarded)
        };
        assert!(removed.is_empty());
        assert!(discarded.is_empty());
        assert_eq!(pool.inner.services.lock().iter_mut().count(), 1);

        std::future::poll_fn(|cx| first.poll_ready(cx))
            .await
            .expect("reusable sender");
        drop(first);

        let second = pool
            .checkout(connection_config(req), Protocol::Http1)
            .await
            .expect("second checkout");

        assert!(second.is_reused());
        assert_eq!(pool.inner.services.lock().iter_mut().count(), 1);
        drop(second);
    }

    #[tokio::test]
    async fn pool_max_size_evicts_only_idle_groups() {
        async fn send(client: &mut Pooled) {
            std::future::poll_fn(|cx| client.poll_ready(cx))
                .await
                .expect("ready sender");
            client
                .call(
                    Request::builder()
                        .uri("http://localhost/")
                        .body(crate::Body::default())
                        .unwrap(),
                )
                .await
                .expect("successful request");
        }

        let pool = Pool::new(
            Config {
                max_size: NonZeroUsize::new(1),
                ..Config::default()
            },
            TestConnector::KeepsAlive,
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
            true,
        );
        let first_req = grouped_request(Group::new("first"));
        let second_req = grouped_request(Group::new("second"));
        let first_key = first_req.key();
        let second_key = second_req.key();

        let mut first = pool
            .checkout(connection_config(first_req), Protocol::Http1)
            .await
            .expect("first checkout");
        send(&mut first).await;

        let mut second = pool
            .checkout(connection_config(second_req), Protocol::Http1)
            .await
            .expect("second checkout");
        send(&mut second).await;
        drop(second);

        assert_eq!(pool.inner.services.lock().iter_mut().count(), 2);

        drop(first);

        let mut services = pool.inner.services.lock();
        assert!(services.get_mut(&first_key).is_some());
        assert!(services.get_mut(&second_key).is_none());
    }

    #[tokio::test]
    #[cfg(feature = "http3")]
    async fn pool_max_size_skips_dead_http3_groups() {
        let pool = Pool::new(
            Config {
                idle_timeout: None,
                max_size: NonZeroUsize::new(2),
                ..Config::default()
            },
            http3_connector(),
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
            true,
        );
        let [live, dead, next] =
            ["live", "dead", "next"].map(|name| grouped_request(Group::new(name)));
        let (live_key, dead_key, next_key) = (live.key(), dead.key(), next.key());
        let checkout = |req| pool.checkout(connection_config(req), Protocol::Http3);

        // Established HTTP/3 senders stay retained after their checkouts end.
        drop(checkout(live).await.expect("live checkout"));
        let pooled = checkout(dead).await.expect("dead checkout");
        let connected = pooled.connected().clone();
        drop(pooled);
        // Kill the idle MRU sender without a checkout, as a QUIC idle close would.
        connected.poison();

        // The full LRU removes the dead group instead of evicting the live one,
        // even though idle sweeps are disabled.
        drop(checkout(next).await.expect("next checkout"));
        let mut services = pool.inner.services.lock();
        for key in [&live_key, &next_key] {
            assert!(
                services
                    .get_mut(key)
                    .is_some_and(|entry| entry.is_retained())
            );
        }
        assert!(services.get_mut(&dead_key).is_none());
        assert_eq!(services.iter_mut().count(), 2);
    }
}
