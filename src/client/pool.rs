//! Composes the client connection pool from small service components.
//!
//! [`Map`] owns one entry per [`ConnectionKey`]. Fixed
//! protocol entries build only an HTTP/1 [`cache::Cache`] or an HTTP/2
//! [`singleton::Singleton`]. Automatic entries use [`Negotiate`] to route an
//! established connection between both pools.
//! Request-local TLS and protocol overrides still require [`crate::Group`]
//! partitioning; this refactor preserves the existing connection identity.
//!
//! ```text
//! Pool
//!  `- Map<connection group>
//!      |- HTTP/1 -> Cache<sender>
//!      |- HTTP/2 -> Singleton<sender>
//!      `- Auto   -> Negotiate<Cache, Singleton>
//! ```
//!
//! HTTP/1 checkouts own an exclusive sender through dispatch and return it only
//! after the protocol reports readiness. HTTP/2 checkouts clone a shared sender;
//! their current accounting ends at response headers and does not yet represent
//! the full stream lifetime.
//!
//! # Checkout flow
//!
//! 1. The map finds or creates the complete connection-compatibility group.
//! 2. Fixed entries check only their protocol pool. Automatic entries first try reusable HTTP/2
//!    state, then HTTP/1 reuse, and only then allow the connection maker to dial.
//! 3. The established transport carries the request's shared protocol configuration into the
//!    selected handshake.
//! 4. A successful checkout transfers entry cleanup into [`Pooled`]. Cancellation instead removes
//!    the same map entry when no shared work remains.
//!
//! Pool locks protect routing and bookkeeping only. Any operation that can
//! destroy a sender, poll user-provided service code, or wake a task first moves
//! the affected value out of the lock.

use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{self, Poll, ready},
    time::{Duration, Instant},
};

use futures_util::future::BoxFuture;
use http::{Request, Response};
use http_body::Body;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Layer, Service, ServiceBuilder, util::Oneshot};
use wreq_proto::{body::Incoming, conn, rt::Timer as _};

pub(super) use self::cache::Started;
use self::{
    cache::Cached,
    expire::{Expire, Inspect},
    map::{Map, Target},
    negotiate::{Negotiate, Negotiated},
    singleton::Singled,
};
use super::proto::{Established, SendError, http1, http2};
use crate::{
    HttpVersion,
    conn::{ConnectContext, Connected, Connection, ConnectionKey},
    rt::{Executor, Timer},
    sync::Mutex,
};

mod cache;
mod expire;
mod map;
mod negotiate;
mod singleton;

/// Returns whether an internal singleton batch asks the client to retry.
pub(super) fn is_canceled(error: &(dyn std::error::Error + 'static)) -> bool {
    singleton::SingletonError::is_canceled(error)
}

/// Selects when the pool starts a new connection while reuse is unavailable.
///
/// This changes acquisition timing only. Idle timeouts and retention limits are
/// configured separately on [`ClientBuilder`](crate::ClientBuilder).
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use wreq::{Client, PoolStrategy};
///
/// let _client = Client::builder()
///     .pool_strategy(PoolStrategy::ReuseFirst(Duration::from_millis(50)));
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
    pub(super) max_pool_size: Option<NonZeroUsize>,

    /// Delay policy applied before starting a new connection.
    pub(super) strategy: PoolStrategy,
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
            max_pool_size: None,
            strategy: PoolStrategy::default(),
        }
    }
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
pub(super) struct Pool<C, B>
where
    C: Service<ConnectContext> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Shared map, timers, and service factory.
    inner: Arc<PoolInner<C, B>>,
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
struct PoolInner<C, B>
where
    C: Service<ConnectContext> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Whether completed connections may return to pool entries.
    enabled: bool,

    /// Maximum idle duration applied during cleanup and checkout.
    idle_timeout: Option<Duration>,

    /// Schedules the single outer expiration watcher.
    expire: Expire<Self>,

    /// Factory used when pooling is disabled or a map entry is missing.
    targeter: PoolTargeter<C, B>,

    /// Services keyed by complete connection compatibility.
    services: Mutex<Map<PoolTargeter<C, B>, PoolTarget>>,
}

/// Destination and protocol configuration for one pool checkout.
///
/// The key freezes the origin and all connection overrides before checkout.
/// Shared base builders and request-local overrides
/// travel together so each new connection uses its initiating request's settings.
/// `wait_for_reuse` is computed by the existing entry, keeping cold starts free
/// of the reuse-first delay.
#[derive(Clone)]
pub(super) struct PoolTarget {
    /// Immutable configuration shared with retries and negotiation.
    connection: Arc<ConnectionConfig>,

    /// Requested protocol selection mode.
    version: HttpVersion,

    /// Whether this checkout can wait for existing pool state to become reusable.
    wait_for_reuse: bool,
}

/// Immutable connection inputs shared by one request's checkout and retries.
///
/// Pool hits only clone the shared handle. A connection attempt clones the
/// context after the reuse wait; the selected handshake alone prepares its
/// builder, so retries and negotiation do not copy unused protocol options.
pub(super) struct ConnectionConfig {
    /// Frozen origin and complete request-local connection configuration.
    pub(super) ctx: ConnectContext,

    /// Base handshake builders shared with the client configuration layer.
    pub(super) proto: Arc<(conn::http1::Builder, conn::http2::Builder<Executor>)>,
}

/// Factory that creates one protocol-specific service graph per destination group.
///
/// [`Map`] calls this targeter only on a key miss. Fixed HTTP/1 and HTTP/2
/// targets receive only their matching pool. Automatic targets combine both
/// paths with [`Negotiate`]. Every entry holds only a weak reference back to
/// [`PoolInner`].
struct PoolTargeter<C, B>
where
    C: Service<ConnectContext> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Physical connection service.
    connector: C,

    /// HTTP/1 idle capacity configured for each entry.
    max_idle_per_host: usize,

    /// Optional delay before a cache miss starts connecting.
    reuse_delay: Option<Duration>,

    /// Pool coordinator used for identity-aware entry cleanup.
    pool: Weak<PoolInner<C, B>>,

    /// Runtime used by cache races and protocol drivers.
    exec: Executor,

    /// Clock used for idle timestamps.
    timer: Timer,

    /// Whether HTTP/1 should generate a missing `Host` field.
    set_host: bool,

    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// Type-erased operations required from one mapped pool entry.
///
/// HTTP/1 and HTTP/2 service composition produces large concrete generic types.
/// The outer map stores this trait object to keep [`PoolInner`] nameable while
/// preserving static dispatch inside each entry. Maintenance methods return
/// removed connection state for destruction after the map lock is released.
trait Entry<B>: Send
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Selects a checkout without polling service code under the map lock.
    /// Polling or dropping the checkout may trigger identity-aware cleanup;
    /// both must happen after the caller releases that lock.
    fn checkout(&mut self, target: PoolTarget, enabled: bool) -> Checkout<B>;

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
    fn protocol(&self) -> HttpVersion;
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
struct Http2Entry<R> {
    /// Shared HTTP/2 sender singleton.
    service: R,

    /// Checkout count and identity-aware cleanup for this entry.
    state: Arc<EntryState>,
}

/// Entry that selects HTTP/1 or HTTP/2 after transport negotiation.
///
/// `service` combines the HTTP/1 cache and HTTP/2 singleton for one compatibility
/// group. `state` counts checkout futures and carries the identity-aware cleanup
/// operation used when the final unsuccessful checkout leaves an empty entry.
struct NegotiatedEntry<L, R, S> {
    /// Fallback and upgraded pool composition.
    service: Negotiate<L, R, S>,

    /// Checkout count and failed-checkout cleanup for this entry.
    state: Arc<EntryState>,
}

/// HTTP/1 cache maintenance used by entries without naming the maker type.
trait Http1Pool<B>:
    Service<PoolTarget, Response = Cached<http1::Connection<B>>, Error = BoxError>
    + Clone
    + Send
    + 'static
{
    /// Removes closed or expired idle HTTP/1 senders.
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>)
    -> Vec<http1::Connection<B>>;

    /// Removes all unreserved idle HTTP/1 senders.
    fn drain_idle(&mut self) -> Vec<http1::Connection<B>>;

    /// Returns whether at least one unreserved idle HTTP/1 sender exists.
    fn has_idle(&self) -> bool;

    /// Returns whether the HTTP/1 cache owns no services.
    fn idle_is_empty(&self) -> bool;
}

/// Idle-management operations required from the HTTP/2 singleton.
///
/// The entry needs to inspect and remove a completed sender without starting
/// another maker. In-progress handshakes are retained because canceling them
/// would also cancel participating checkouts.
trait Http2Pool<B>: Clone + Send + 'static {
    /// Removes a closed or expired idle HTTP/2 sender.
    fn retain_idle(
        &mut self,
        now: Instant,
        timeout: Option<Duration>,
    ) -> Option<http2::Connection<B>>;

    /// Removes the completed shared HTTP/2 sender without canceling its maker.
    fn take_idle(&mut self) -> Option<http2::Connection<B>>;

    /// Returns whether the HTTP/2 singleton is empty.
    fn idle_is_empty(&self) -> bool;

    /// Returns whether the singleton has completed its shared sender.
    fn has_service(&self) -> bool;
}

/// Boxed future that establishes the singleton HTTP/2 sender.
type H2MakeFuture<B> = BoxFuture<'static, Result<http2::Connection<B>, BoxError>>;

/// Generation-aware checkout of the shared HTTP/2 sender.
type H2Pooled<B> = Singled<H2MakeFuture<B>, http2::Connection<B>>;

/// Future joining an existing HTTP/2 singleton generation.
type H2Checkout<B> = singleton::SingletonFuture<H2MakeFuture<B>, http2::Connection<B>>;

/// Defers checkout completion and resource destruction until the map is unlocked.
///
/// Existing HTTP/2 generations retain their concrete singleton future. Cold
/// creation and HTTP/1 races keep the composed service future boxed. In either
/// case, the entry remains active until it is transferred to the sender.
enum Checkout<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Existing singleton work, without another box around its future.
    Http2 {
        /// Owns the sender clone or pending-generation participation.
        future: H2Checkout<B>,
        /// Redundant negotiated transports released on the first poll or drop.
        discarded: Option<DeferredDrop>,
        /// Keeps request metadata alive until outside the outer map lock.
        _connection: Arc<ConnectionConfig>,
        /// Drops after the singleton participant so cleanup sees its final state.
        usage: Option<EntryUse>,
        /// Whether the resulting sender belongs to a shared pool.
        enabled: bool,
    },
    /// Composed cache or negotiation work, retaining its own scheduling state.
    Service(BoxFuture<'static, Result<Pooled<B>, BoxError>>),
}

/// HTTP sender selected for one pool checkout.
type PooledInner<B> = Negotiated<Cached<http1::Connection<B>>, H2Pooled<B>>;

/// Type-erased connection state held until the outer map lock is released.
///
/// One value may aggregate several concrete senders from the same entry. This
/// keeps cleanup type-erased without allocating one box per removed connection.
type DeferredDrop = Box<dyn Send>;

/// Identity-aware maintenance operation for one mapped entry.
type EntryMaintenance = dyn Fn(&Arc<EntryState>) + Send + Sync;

/// Protocol-agnostic sender checked out from one pool entry.
///
/// HTTP/1 owns an exclusive [`Cached`] sender that returns to its cache on drop.
/// HTTP/2 owns a [`Singled`] clone and increments shared response-header
/// checkout state. The wrapper presents one request interface to the client and
/// records whether a healthy sender may be retained after dispatch.
///
/// Dropping this value marks HTTP/1 idle or ends the HTTP/2 checkout. A poisoned,
/// closed sender is removed instead of being reused.
pub(super) struct Pooled<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// HTTP/1 cache checkout or HTTP/2 singleton checkout.
    inner: PooledInner<B>,

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
struct ConnectionMaker<C>
where
    C: Service<ConnectContext> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
{
    /// Physical transport connector.
    connector: C,

    /// Optional delay giving connection reuse time to win.
    reuse_delay: Option<Duration>,

    /// Clock shared by reuse waits and transport timestamps.
    timer: Timer,
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
    maintain: Box<EntryMaintenance>,
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

impl<C, B> Pool<C, B>
where
    C: Service<ConnectContext> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Builds the shared map and protocol-specific entry factory.
    ///
    /// Idle maintenance remains dormant until an entry retains reusable state.
    pub(super) fn new(
        config: Config,
        connector: C,
        exec: Executor,
        timer: Timer,
        set_host: bool,
    ) -> Self {
        let reuse_delay = match config.strategy {
            PoolStrategy::ReuseFirst(duration)
                if config.is_enabled() && duration != Duration::ZERO && !timer.is_empty() =>
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
                exec: exec.clone(),
                timer: timer.clone(),
                set_host,
                _body: PhantomData,
            };

            PoolInner {
                enabled: config.is_enabled(),
                idle_timeout: config.idle_timeout,
                expire: Expire::new(pool.clone(), exec, timer),
                services: Mutex::new(Map::new(config.max_pool_size)),
                targeter,
            }
        });

        Self { inner }
    }

    /// Checks out a sender compatible with the destination and handshake builders.
    ///
    /// The map lock is released before the returned future is polled. When
    /// pooling is disabled, the call creates a temporary entry for this request.
    pub(super) async fn checkout(
        &self,
        connection: Arc<ConnectionConfig>,
        version: HttpVersion,
    ) -> Result<Pooled<B>, BoxError> {
        let target = PoolTarget {
            connection,
            version,
            wait_for_reuse: false,
        };

        let (future, discarded) = if self.inner.enabled {
            let now = self.inner.now();
            let mut services = self.inner.services.lock();
            // Inspect only this group on checkout. A global retained-group scan
            // would add O(group count) work and nested locking to every pool hit.
            services.with_service(&self.inner.targeter, target, |service, target| {
                let discarded = service.retain(now, self.inner.idle_timeout);
                let future = service.checkout(target, true);
                (future, discarded)
            })
        } else {
            (
                self.inner.targeter.service(&target).checkout(target, false),
                None,
            )
        };
        drop(discarded);

        future.await
    }
}

impl<C, B> Clone for Pool<C, B>
where
    C: Service<ConnectContext> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

// ===== impl PoolInner =====

impl<C, B> PoolInner<C, B>
where
    C: Service<ConnectContext> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Reads the configured clock, falling back to `Instant::now`.
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
        let (removed, discarded, schedule_expiration) = {
            let mut services = self.services.lock();
            // Keep per-entry maintenance independent of the retained-group count.
            // mark_retained checks other markers only before capacity eviction;
            // periodic expiration still performs the global sweep.
            let state = services.get_mut(key).and_then(|entry| {
                entry
                    .matches_identity(identity)
                    .then(|| (entry.is_empty(), entry.is_retained()))
            });
            let mut removed = None;
            let mut discarded = None;
            let mut schedule_expiration = false;

            match state {
                Some((true, _)) => {
                    removed = services.remove_if(key, |_| true);
                }
                Some((false, true)) => {
                    schedule_expiration = true;
                    if let Some(evicted) = services.mark_retained(key, |entry| entry.is_retained())
                    {
                        let empty = services.get_mut(&evicted).is_some_and(|entry| {
                            discarded = entry.evict_retained();
                            entry.is_empty()
                        });
                        if empty {
                            removed = services.remove_if(&evicted, |_| true);
                        }
                    }
                }
                Some((false, false)) => services.unmark_retained(key),
                None => {}
            }

            (removed, discarded, schedule_expiration)
        };
        drop(removed);
        drop(discarded);

        self.expire
            .schedule(self.expiration_interval(schedule_expiration));
    }
}

impl<C, B> Inspect for PoolInner<C, B>
where
    C: Service<ConnectContext> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    fn retain(&self, now: Instant) -> Option<Duration> {
        let (has_retained, removed, discarded) = {
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
            (has_retained, removed, discarded)
        };
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

impl<C, B> PoolTargeter<C, B>
where
    C: Service<ConnectContext> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Composes an HTTP/1 cache around protocol handshaking.
    /// Only the cache's background-completion callback owns an entry-state clone.
    fn http1_layer<S, T>(
        &self,
        state: &Arc<EntryState>,
    ) -> impl Layer<
        S,
        Service = cache::Cache<
            http1::Connect<S, B>,
            PoolTarget,
            cache::events::WithExecutor<Executor>,
        >,
    >
    where
        S: Service<PoolTarget, Response = Established<T>, Error = BoxError> + Clone,
        S::Future: Started + Unpin,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        ServiceBuilder::new()
            .layer_fn(move |service| {
                let state = state.clone();
                cache::builder()
                    .executor(self.exec.clone())
                    .on_background_complete(move || (state.maintain)(&state))
                    .max_idle(self.max_idle_per_host)
                    .build(service)
            })
            .layer(http1::ConnectLayer::new(
                self.exec.clone(),
                self.timer.clone(),
                self.set_host,
            ))
            .into_inner()
    }
}

impl<C, B> Target<PoolTarget> for PoolTargeter<C, B>
where
    C: Service<ConnectContext> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Key = ConnectionKey;
    type Service = Box<dyn Entry<B>>;

    fn key(&self, target: &PoolTarget) -> Self::Key {
        target.connection.ctx.key()
    }

    /// Builds only the pool components required by the target's protocol mode.
    fn service(&self, target: &PoolTarget) -> Self::Service {
        let pool = self.pool.clone();
        let key = target.connection.ctx.key();
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
            timer: self.timer.clone(),
        };

        // Fixed protocol modes use smaller service graphs; only Auto needs both
        // pools and negotiation: https://github.com/hyperium/hyper/issues/3948
        match target.version {
            HttpVersion::Http1 => {
                let service = self.http1_layer(&state).layer(connect);
                Box::new(Http1Entry { service, state })
            }
            HttpVersion::Http2 => Box::new(Http2Entry {
                service: ServiceBuilder::new()
                    .layer_fn(singleton::Singleton::new)
                    .layer(http2::ConnectLayer::new(
                        self.exec.clone(),
                        self.timer.clone(),
                    ))
                    .service(connect),
                state,
            }),
            HttpVersion::Auto => {
                let inspect: fn(&Established<C::Response>) -> bool = Established::should_use_http2;
                let service = negotiate::builder()
                    .connect(connect)
                    .inspect(inspect)
                    .fallback(self.http1_layer(&state))
                    .upgrade(
                        ServiceBuilder::new()
                            .layer_fn(singleton::Singleton::new)
                            .layer(http2::ConnectLayer::new(
                                self.exec.clone(),
                                self.timer.clone(),
                            )),
                    )
                    .build::<PoolTarget>();

                Box::new(NegotiatedEntry { service, state })
            }
        }
    }
}

// ===== impl Http1Entry =====

impl<L, B> Entry<B> for Http1Entry<L>
where
    L: Http1Pool<B>,
    L::Future: Send,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Checks out one exclusive HTTP/1 sender from this entry.
    ///
    /// A reuse-first delay is enabled only when the entry already contains work
    /// that may yield a sender. [`EntryUse`] keeps the map entry alive until the
    /// checkout either fails or transfers ownership to [`Pooled`].
    fn checkout(&mut self, mut target: PoolTarget, enabled: bool) -> Checkout<B> {
        target.wait_for_reuse = enabled && !self.is_empty();
        let service = self.service.clone();
        let usage = EntryUse::new(self.state.clone());
        Checkout::Service(Box::pin(async move {
            Oneshot::new(service, target)
                .await
                .map(|service| Pooled::new(Negotiated::Left(service), enabled, usage))
        }))
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
        self.state.uses.load(Ordering::Acquire) == 0 && self.service.idle_is_empty()
    }

    /// Identifies the fixed HTTP/1 topology in tests.
    #[cfg(test)]
    fn protocol(&self) -> HttpVersion {
        HttpVersion::Http1
    }
}

// ===== impl Http2Entry =====

impl<M, B> Entry<B> for Http2Entry<singleton::Singleton<M, PoolTarget>>
where
    M: Service<
            PoolTarget,
            Response = http2::Connection<B>,
            Error = BoxError,
            Future = H2MakeFuture<B>,
        > + Clone
        + Send
        + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Joins the current HTTP/2 generation or starts one when the entry is empty.
    ///
    /// A fixed HTTP/2 cold start never waits for HTTP/1-style reuse. Every
    /// participant still carries [`EntryUse`] until singleton checkout finishes.
    fn checkout(&mut self, mut target: PoolTarget, enabled: bool) -> Checkout<B> {
        target.wait_for_reuse = false;
        let usage = EntryUse::new(self.state.clone());
        if let Some(future) = self.service.checkout() {
            return Checkout::Http2 {
                future,
                discarded: None,
                _connection: target.connection,
                usage: Some(usage),
                enabled,
            };
        }
        let service = self.service.clone();
        Checkout::Service(Box::pin(async move {
            let service = Oneshot::new(service, target).await?;
            Ok(Pooled::new(Negotiated::Right(service), enabled, usage))
        }))
    }

    /// Removes a completed HTTP/2 sender when it is closed or has expired idle.
    ///
    /// Pending singleton creation is left untouched. Active sender checkouts are
    /// kept by [`http2::Connection::is_reusable`].
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Option<DeferredDrop> {
        if self.state.uses.load(Ordering::Acquire) != 0 {
            return None;
        }

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
    fn protocol(&self) -> HttpVersion {
        HttpVersion::Http2
    }
}

// ===== impl NegotiatedEntry =====

impl<L, R, T, B> Entry<B> for NegotiatedEntry<L, R, Established<T>>
where
    L: Http1Pool<B>,
    L::Future: Send,
    R: Http2Pool<B>
        + negotiate::Existing<Established<T>, Response = H2Pooled<B>, Future = H2Checkout<B>>,
    R::Error: Into<BoxError>,
    R::Future: Send,
    T: Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Joins existing upgraded work or checks out through the composed service.
    fn checkout(&mut self, mut target: PoolTarget, enabled: bool) -> Checkout<B> {
        target.wait_for_reuse = enabled && !self.is_empty();
        let usage = EntryUse::new(self.state.clone());
        if let Some((future, discarded)) = self.service.checkout_existing() {
            return Checkout::Http2 {
                future,
                discarded: (!discarded.is_empty()).then(|| defer_drop(discarded)),
                _connection: target.connection,
                usage: Some(usage),
                enabled,
            };
        }
        let service = self.service.clone();
        Checkout::Service(Box::pin(async move {
            Oneshot::new(service, target)
                .await
                .map(|service| Pooled::new(service, enabled, usage))
        }))
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
        let upgrade = if entry_in_use {
            None
        } else {
            self.service.upgrade_mut().retain_idle(now, timeout)
        };

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
            && self.service.fallback().idle_is_empty()
            && self.service.upgrade().idle_is_empty()
    }

    /// Identifies the negotiated HTTP/1-or-HTTP/2 topology in tests.
    #[cfg(test)]
    fn protocol(&self) -> HttpVersion {
        HttpVersion::Auto
    }
}

// ===== impl Checkout =====

impl<B> Future for Checkout<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Output = Result<Pooled<B>, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Http2 {
                future,
                discarded,
                usage,
                enabled,
                ..
            } => {
                drop(discarded.take());
                let result = ready!(Pin::new(future).poll(cx));
                let Some(usage) = usage.take() else {
                    return Poll::Pending;
                };
                // Pooled::new starts H2 accounting before releasing EntryUse and
                // may run map maintenance, so it must execute outside the lock.
                Poll::Ready(
                    result
                        .map(|service| Pooled::new(Negotiated::Right(service), *enabled, usage))
                        .map_err(Into::into),
                )
            }
            Self::Service(future) => future.as_mut().poll(cx),
        }
    }
}

// ===== impl Cache =====

impl<M, Ev, B> Http1Pool<B> for cache::Cache<M, PoolTarget, Ev>
where
    M: Service<PoolTarget, Response = http1::Connection<B>, Error = BoxError>
        + Clone
        + Send
        + 'static,
    M::Future: Unpin + Send,
    M::Response: Unpin,
    Ev: cache::events::Events<cache::BackgroundConnect<M::Future, M::Response>>
        + Clone
        + Send
        + Unpin
        + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Retains reusable HTTP/1 senders.
    fn retain_idle(
        &mut self,
        now: Instant,
        timeout: Option<Duration>,
    ) -> Vec<http1::Connection<B>> {
        self.retain(|connection| connection.is_reusable(now, timeout))
    }

    /// Drains unreserved idle HTTP/1 senders.
    fn drain_idle(&mut self) -> Vec<http1::Connection<B>> {
        cache::Cache::drain_idle(self)
    }

    /// Reports whether an unreserved HTTP/1 sender is idle.
    fn has_idle(&self) -> bool {
        cache::Cache::has_idle(self)
    }

    /// Returns whether the cache owns no ready, idle, or active sender.
    fn idle_is_empty(&self) -> bool {
        self.is_empty()
    }
}

// ===== impl Singleton =====

impl<M, Dst, B> Http2Pool<B> for singleton::Singleton<M, Dst>
where
    M: Service<Dst, Response = http2::Connection<B>> + Clone + Send + 'static,
    M::Future: Send + 'static,
    Dst: Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Removes a completed sender only when the pool's health policy rejects it.
    ///
    /// A maker generation still in progress is never canceled by maintenance.
    fn retain_idle(
        &mut self,
        now: Instant,
        timeout: Option<Duration>,
    ) -> Option<http2::Connection<B>> {
        self.retain(|connection| connection.is_reusable(now, timeout))
    }

    /// Detaches the completed sender without interrupting an active maker.
    fn take_idle(&mut self) -> Option<http2::Connection<B>> {
        self.take()
    }

    /// Returns whether neither a completed sender nor a maker generation exists.
    fn idle_is_empty(&self) -> bool {
        self.is_empty()
    }

    /// Returns whether singleton creation has produced a shared sender.
    fn has_service(&self) -> bool {
        self.has_service()
    }
}

impl<M, S> negotiate::Existing<S> for singleton::Singleton<M, S>
where
    M: Service<S>,
    M::Response: Clone,
    M::Error: Into<BoxError>,
{
    /// Joins only existing or in-progress singleton state.
    fn checkout(&self) -> Option<Self::Future> {
        singleton::Singleton::checkout(self)
    }
}

// ===== impl ConnectionMaker =====

impl<C> Service<PoolTarget> for ConnectionMaker<C>
where
    C: Service<ConnectContext> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
{
    type Response = Established<C::Response>;
    type Error = BoxError;
    type Future = ConnectFuture<Self::Response>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: PoolTarget) -> Self::Future {
        let PoolTarget {
            connection,
            version,
            wait_for_reuse,
        } = target;
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
        let timer = self.timer.clone();

        let future = Box::pin(async move {
            if let Some(duration) = reuse_delay {
                timer.sleep(duration).await;
            }

            if let Some(started) = &start_signal {
                started.store(true, Ordering::Release);
            }
            let io = Oneshot::new(connector, connection.ctx.clone())
                .await
                .map_err(Into::into)?;
            let connected = io.connected();
            Ok(Established::new(
                io,
                connected,
                version,
                connection,
                clock_now(&timer),
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

impl<B> Pooled<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Wraps a negotiated sender and registers an HTTP/2 checkout when needed.
    fn new(inner: PooledInner<B>, pool_enabled: bool, usage: EntryUse) -> Self {
        if let Negotiated::Right(service) = &inner {
            service.inner().begin_checkout();
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

    /// Returns whether this checkout uses HTTP/1.
    pub(super) fn is_http1(&self) -> bool {
        matches!(self.inner, Negotiated::Left(_))
    }

    /// Returns whether this checkout uses HTTP/2.
    pub(super) fn is_http2(&self) -> bool {
        matches!(self.inner, Negotiated::Right(_))
    }

    /// Returns whether the sender came from an existing pooled connection.
    pub(super) fn is_reused(&self) -> bool {
        match &self.inner {
            Negotiated::Left(service) => service.is_reused(),
            Negotiated::Right(service) => service.is_reused(),
        }
    }

    /// Returns whether completed senders may be retained for reuse.
    pub(super) fn is_pool_enabled(&self) -> bool {
        self.pool_enabled
    }

    /// Returns whether the protocol sender can accept a request immediately.
    pub(super) fn is_ready(&self) -> bool {
        match &self.inner {
            Negotiated::Left(service) => service.inner().is_ready(),
            Negotiated::Right(service) => service.inner().is_ready(),
        }
    }

    /// Returns metadata for the underlying physical connection.
    pub(super) fn conn_info(&self) -> &Connected {
        match &self.inner {
            Negotiated::Left(service) => service.inner().conn_info(),
            Negotiated::Right(service) => service.inner().conn_info(),
        }
    }
}

impl<B> Service<Request<B>> for Pooled<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Incoming>;
    type Error = SendError<B>;
    type Future = tower::util::future::EitherResponseFuture<
        <http1::Connection<B> as Service<Request<B>>>::Future,
        <http2::Connection<B> as Service<Request<B>>>::Future,
    >;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        self.inner.call(req)
    }
}

impl<B> Drop for Pooled<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    fn drop(&mut self) {
        match &mut self.inner {
            Negotiated::Left(service) => {
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
            Negotiated::Right(service) => {
                let discard = {
                    let connection = service.inner();
                    connection.finish_checkout();
                    connection.conn_info().poisoned() || connection.is_closed()
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

impl<B> fmt::Debug for Pooled<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pooled")
            .field("http2", &self.is_http2())
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

#[cfg(test)]
mod tests {
    use std::io;

    use bytes::Bytes;
    use http_body_util::Empty;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::group::Group;

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
        Http2(Arc<AtomicUsize>, Arc<tokio::sync::Semaphore>),
    }

    impl Service<ConnectContext> for TestConnector {
        type Response = tokio::io::DuplexStream;
        type Error = BoxError;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _ctx: ConnectContext) -> Self::Future {
            match self {
                Self::Fails => Box::pin(std::future::ready(Err(io::Error::from(
                    io::ErrorKind::ConnectionRefused,
                )
                .into()))),
                Self::Pending => Box::pin(std::future::pending()),
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
                            .serve_connection(hyper_util::rt::TokioIo::new(server), service)
                            .await;
                        });
                        Ok(client)
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
                    Ok(client)
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
                    Ok(client)
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
                        Ok(client)
                    })
                }
            }
        }
    }

    /// Creates connection inputs for a local test origin.
    fn context() -> ConnectContext {
        grouped_context(Group::new("test"))
    }

    /// Supplies default protocol configuration for a test connection.
    fn connection(ctx: ConnectContext) -> Arc<ConnectionConfig> {
        Arc::new(ConnectionConfig {
            ctx,
            proto: Arc::new((
                conn::http1::Builder::default(),
                conn::http2::Builder::new(Executor::default()),
            )),
        })
    }

    /// Creates connection inputs with an explicit compatibility group.
    fn grouped_context(group: Group) -> ConnectContext {
        let mut extensions = crate::conn::context::Extensions::default();
        extensions.insert(group);
        ConnectContext::new(
            "http://localhost/".parse().expect("valid test URI"),
            None,
            extensions,
        )
        .unwrap()
    }

    /// Creates a pool without periodic cleanup so empty-entry removal is explicit.
    fn test_pool(connector: TestConnector) -> Pool<TestConnector, crate::Body> {
        Pool::new(
            Config {
                idle_timeout: None,
                ..Config::default()
            },
            connector,
            Executor::default(),
            Timer::default(),
            true,
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
        let connector = tower::service_fn(move |_: ConnectContext| {
            let _counter = &counter;
            std::future::pending::<Result<tokio::io::DuplexStream, BoxError>>()
        });
        let pool = Pool::<_, crate::Body>::new(
            Config::default(),
            connector,
            Executor::default(),
            Timer::default(),
            true,
        );
        assert_eq!(clones.load(Ordering::Relaxed), 0);

        for (index, version) in [HttpVersion::Http1, HttpVersion::Http2, HttpVersion::Auto]
            .into_iter()
            .enumerate()
        {
            let target = PoolTarget {
                connection: connection(context()),
                version,
                wait_for_reuse: false,
            };
            let entry = pool.inner.targeter.service(&target);

            assert_eq!(entry.protocol(), version);
            assert_eq!(clones.load(Ordering::Relaxed), index + 1);
        }
    }

    #[tokio::test]
    async fn http2_checkouts_preserve_generation_and_cancellation() {
        for version in [HttpVersion::Http2, HttpVersion::Auto] {
            let calls = Arc::new(AtomicUsize::new(0));
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let pool = test_pool(TestConnector::Http2(calls.clone(), gate.clone()));
            let checkout = || {
                let target = PoolTarget {
                    connection: connection(context()),
                    version,
                    wait_for_reuse: false,
                };
                pool.inner.services.lock().with_service(
                    &pool.inner.targeter,
                    target,
                    |entry, mut target| {
                        assert_eq!(entry.protocol(), version);
                        // Exercise the Auto graph without TLS by selecting H2 at
                        // the transport stage, where ALPN would normally choose it.
                        target.version = HttpVersion::Http2;
                        entry.checkout(target, true)
                    },
                )
            };

            let mut driver = tokio_test::task::spawn(checkout());
            assert!(driver.poll().is_pending());
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            let held = if version == HttpVersion::Http2 {
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

            let poisoned = checkout().await.unwrap();
            poisoned.conn_info().poison();
            drop(poisoned);
            gate.add_permits(1);
            let mut replacement = tokio::time::timeout(Duration::from_secs(1), checkout())
                .await
                .unwrap()
                .unwrap();
            assert!(!replacement.is_reused());
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
            replacement.conn_info().poison();
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
        let pool = Pool::<_, crate::Body>::new(
            Config {
                idle_timeout: Some(Duration::from_millis(10)),
                ..Config::default()
            },
            TestConnector::KeepsAlive,
            Executor::default(),
            Timer::default(),
            true,
        );
        let pooled = pool
            .checkout(connection(context()), HttpVersion::Http1)
            .await
            .expect("successful checkout");

        assert!(!pool.inner.expire.is_running());
        drop(pooled);
        assert!(pool.inner.expire.is_running());

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;

        assert!(pool.inner.services.lock().is_empty());
        assert!(!pool.inner.expire.is_running());

        let pool = Pool::<_, crate::Body>::new(
            Config {
                idle_timeout: Some(Duration::ZERO),
                ..Config::default()
            },
            TestConnector::KeepsAlive,
            Executor::default(),
            Timer::default(),
            true,
        );
        let pooled = pool
            .checkout(connection(context()), HttpVersion::Http1)
            .await
            .expect("successful checkout");

        drop(pooled);
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;

        assert!(!pool.inner.services.lock().is_empty());
        assert!(!pool.inner.expire.is_running());
    }

    #[tokio::test]
    async fn checkouts_remove_empty_map_entries() {
        for version in [HttpVersion::Http1, HttpVersion::Http2, HttpVersion::Auto] {
            let pool = test_pool(TestConnector::Fails);
            let result = pool.checkout(connection(context()), version).await;
            assert!(result.is_err());
            assert!(pool.inner.services.lock().is_empty());
            assert!(!pool.inner.expire.is_running());

            let pool = test_pool(TestConnector::Pending);
            let mut first = tokio_test::task::spawn(pool.checkout(connection(context()), version));
            let mut second = tokio_test::task::spawn(pool.checkout(connection(context()), version));
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
            .checkout(connection(context()), HttpVersion::Http1)
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
            .checkout(connection(context()), HttpVersion::Http1)
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
        let ctx = grouped_context(Group::new("active"));
        let mut first = pool
            .checkout(connection(ctx.clone()), HttpVersion::Http1)
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
            .checkout(connection(ctx), HttpVersion::Http1)
            .await
            .expect("second checkout");

        assert!(second.is_reused());
        assert_eq!(pool.inner.services.lock().iter_mut().count(), 1);
        drop(second);
    }

    #[tokio::test]
    async fn pool_max_size_evicts_only_idle_groups() {
        async fn send(client: &mut Pooled<crate::Body>) {
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
                max_pool_size: NonZeroUsize::new(1),
                ..Config::default()
            },
            TestConnector::KeepsAlive,
            Executor::default(),
            Timer::default(),
            true,
        );
        let first_context = grouped_context(Group::new("first"));
        let second_context = grouped_context(Group::new("second"));
        let first_key = first_context.key();
        let second_key = second_context.key();

        let mut first = pool
            .checkout(connection(first_context), HttpVersion::Http1)
            .await
            .expect("first checkout");
        send(&mut first).await;

        let mut second = pool
            .checkout(connection(second_context), HttpVersion::Http1)
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
}
