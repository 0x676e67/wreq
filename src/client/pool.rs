//! Composes the client connection pool from small service components.
//!
//! [`Map`] owns one entry per complete connection compatibility group. Fixed
//! protocol entries build only an HTTP/1 [`cache::Cache`] or an HTTP/2
//! [`singleton::Singleton`]. Automatic entries use [`Negotiate`] to route an
//! established connection between both pools.
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
//! 3. The established transport carries the request's protocol builders into the selected
//!    handshake.
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
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures_util::future::{BoxFuture, Either};
use http::{Request, Response};
use http_body::Body;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Layer, Service, util::Oneshot};
use wreq_proto::{
    body::Incoming,
    conn::{self},
    rt::Timer as _,
};

pub(super) use self::cache::Started;
use self::{
    cache::Cached,
    expire::{Expire, Inspect},
    map::{Map, Target},
    negotiate::{Negotiate, Negotiated},
    singleton::Singled,
};
use super::proto::{
    Established, SendError,
    http1::{Http1Client, Http1Connect, Http1Layer},
    http2::{Http2Client, Http2Connect, Http2Layer},
};
use crate::{
    conn::{
        Connected, Connection,
        descriptor::{ConnectionDescriptor, ConnectionId},
    },
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

/// Protocol mode requested for a pooled connection.
///
/// This value tells negotiation whether ALPN may choose the protocol or one
/// protocol is mandatory.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Ver {
    /// Selects the protocol from request requirements and connection negotiation.
    Auto,
    /// Requires an HTTP/1 connection.
    Http1,
    /// Requires an HTTP/2 connection.
    Http2,
}

/// Immutable retention and acquisition policy for one connection pool.
///
/// The client builder assembles this value once. Every mapped entry inherits the
/// same idle policy and acquisition strategy while retaining request-specific
/// protocol handshake builders in [`PoolTarget`].
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
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
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
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
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
/// The descriptor is both the physical connection blueprint and the source of
/// the map compatibility key. Handshake builders remain request-local because
/// protocol settings may vary between otherwise compatible connection attempts.
/// `wait_for_reuse` is computed by the existing entry, keeping cold starts free
/// of the reuse-first delay.
#[derive(Clone)]
pub(super) struct PoolTarget {
    /// Complete blueprint for the physical connection.
    descriptor: ConnectionDescriptor,

    /// Requested protocol selection mode.
    version: Ver,

    /// Whether this checkout can wait for existing pool state to become reusable.
    wait_for_reuse: bool,

    /// HTTP/1 handshake configuration for this request.
    h1_builder: conn::http1::Builder,

    /// HTTP/2 handshake configuration for this request.
    h2_builder: conn::http2::Builder<Executor>,
}

/// Factory that creates one protocol-specific service graph per destination group.
///
/// [`Map`] calls this targeter only on a key miss. Fixed HTTP/1 and HTTP/2
/// targets receive only their matching pool. Automatic targets combine both
/// paths with [`Negotiate`]. Every entry holds only a weak reference back to
/// [`PoolInner`].
struct PoolTargeter<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
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
    reuse_delay: Option<(Duration, Timer)>,

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
    /// Checks out a protocol sender for `target`.
    fn checkout(
        &mut self,
        target: PoolTarget,
        enabled: bool,
    ) -> BoxFuture<'static, Result<Pooled<B>, BoxError>>;

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
    fn protocol(&self) -> Ver;
}

/// Entry containing only an HTTP/1 connection cache.
///
/// This is created for a fixed HTTP/1 target. It owns exclusive senders until
/// checkout and returns reusable senders to the cache after dispatch.
struct Http1Entry<L> {
    /// Exclusive HTTP/1 sender cache.
    service: L,

    /// Checkout count and identity-aware cleanup for this entry.
    state: Arc<EntryState>,
}

/// Entry containing only an HTTP/2 singleton.
///
/// This is created for a fixed HTTP/2 target. Concurrent cold checkouts join
/// one connection generation and later checkouts clone its shared sender.
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

/// Idle-management operations required from the HTTP/1 cache.
///
/// This local trait keeps the type-erased entry independent of the exact cache
/// builder type while exposing only cleanup and empty-state checks.
trait Http1Pool<B>:
    Service<PoolTarget, Response = Cached<Http1Client<B>>, Error = BoxError> + Clone + Send + 'static
{
    /// Removes closed or expired idle HTTP/1 senders.
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) -> Vec<Http1Client<B>>;

    /// Removes all unreserved idle HTTP/1 senders.
    fn drain_idle(&mut self) -> Vec<Http1Client<B>>;

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
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) -> Option<Http2Client<B>>;

    /// Removes the completed shared HTTP/2 sender without canceling its maker.
    fn take_idle(&mut self) -> Option<Http2Client<B>>;

    /// Returns whether the HTTP/2 singleton is empty.
    fn idle_is_empty(&self) -> bool;

    /// Returns whether the singleton has completed its shared sender.
    fn has_service(&self) -> bool;
}

/// Boxed future that establishes the singleton HTTP/2 sender.
type H2MakeFuture<B> = BoxFuture<'static, Result<Http2Client<B>, BoxError>>;

/// Generation-aware checkout of the shared HTTP/2 sender.
type H2Pooled<B> = Singled<H2MakeFuture<B>, Http2Client<B>>;

/// HTTP sender selected for one pool checkout.
type PooledInner<B> = Negotiated<Cached<Http1Client<B>>, H2Pooled<B>>;

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
struct ConnectionMaker<C>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
{
    /// Physical transport connector.
    connector: C,

    /// Optional delay giving connection reuse time to win.
    reuse_delay: Option<(Duration, Timer)>,

    /// Clock used to timestamp established transports.
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

/// Layer that turns established transports into cached HTTP/1 senders.
///
/// The layer applies [`Http1Layer`] before the cache and retains at most
/// `max_idle` exclusive senders.
struct Http1PoolLayer<B> {
    /// Entry maintenance invoked after a background connection finishes.
    entry_state: Arc<EntryState>,

    /// Runtime used by protocol drivers and lost-race work.
    exec: Executor,

    /// Maximum idle senders retained by the cache.
    max_idle: usize,

    /// Clock used for idle timestamps.
    timer: Timer,

    /// Whether HTTP/1 should generate a missing `Host` field.
    set_host: bool,

    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// Layer that turns established transports into one shared HTTP/2 sender.
///
/// The layer applies [`Http2Layer`] before the singleton. An inspected transport
/// is consumed exactly once; later checkouts clone the shared sender.
struct Http2PoolLayer<B, T> {
    /// Runtime used by the protocol driver.
    exec: Executor,

    /// Clock used for idle timestamps.
    timer: Timer,

    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,

    /// Carries the transport type selected by negotiation.
    _io: PhantomData<fn(T)>,
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
/// mapped entry. Healthy return paths leave the guard disarmed and avoid taking
/// the outer map lock.
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

// ===== impl PoolTargeter =====

impl<C, B> Clone for PoolTargeter<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            max_idle_per_host: self.max_idle_per_host,
            reuse_delay: self.reuse_delay.clone(),
            pool: self.pool.clone(),
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            set_host: self.set_host,
            _body: PhantomData,
        }
    }
}

// ===== impl ConnectionMaker =====

impl<C> Clone for ConnectionMaker<C>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
{
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            reuse_delay: self.reuse_delay.clone(),
            timer: self.timer.clone(),
        }
    }
}

// ===== impl Http1PoolLayer =====

impl<B> Clone for Http1PoolLayer<B> {
    fn clone(&self) -> Self {
        Self {
            entry_state: self.entry_state.clone(),
            exec: self.exec.clone(),
            max_idle: self.max_idle,
            timer: self.timer.clone(),
            set_host: self.set_host,
            _body: PhantomData,
        }
    }
}

// ===== impl Http2PoolLayer =====

impl<B, T> Clone for Http2PoolLayer<B, T> {
    fn clone(&self) -> Self {
        Self {
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            _body: PhantomData,
            _io: PhantomData,
        }
    }
}

// ===== impl Pool =====

impl<C, B> Pool<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
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
                Some((duration, timer.clone()))
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
                services: Mutex::new(Map::new(targeter.clone(), config.max_pool_size)),
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
        descriptor: ConnectionDescriptor,
        version: Ver,
        h1_builder: conn::http1::Builder,
        h2_builder: conn::http2::Builder<Executor>,
    ) -> Result<Pooled<B>, BoxError> {
        let target = PoolTarget {
            descriptor,
            version,
            wait_for_reuse: false,
            h1_builder,
            h2_builder,
        };

        let (future, discarded) = if self.inner.enabled {
            let now = self.inner.now();
            let mut services = self.inner.services.lock();
            let result = services.with_service(target, |service, target| {
                let discarded = service.retain(now, self.inner.idle_timeout);
                let future = service.checkout(target, true);
                (future, discarded)
            });
            services.prune_retained(|entry| entry.is_retained());
            result
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
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
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
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
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
    fn maintain_entry(self: &Arc<Self>, key: &ConnectionId, identity: &Arc<EntryState>) {
        let (removed, discarded, schedule_expiration) = {
            let mut services = self.services.lock();
            services.prune_retained(|entry| entry.is_retained());

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
                    if let Some(evicted) = services.mark_retained(key) {
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
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Removes expired senders and empty entries for unlocked destruction.
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

    /// Returns the idle inspection interval while reusable state remains.
    fn next(&self) -> Option<Duration> {
        let has_retained = self
            .services
            .lock()
            .iter_mut()
            .any(|(_, entry)| entry.is_retained());

        self.expiration_interval(has_retained)
    }
}

impl<C, B> Target<PoolTarget> for PoolTargeter<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Key = ConnectionId;
    type Service = Box<dyn Entry<B>>;

    /// Uses the descriptor's complete compatibility identifier.
    fn key(&self, target: &PoolTarget) -> Self::Key {
        target.descriptor.id()
    }

    /// Builds only the pool components required by the target's protocol mode.
    fn service(&self, target: &PoolTarget) -> Self::Service {
        let pool = self.pool.clone();
        let key = target.descriptor.id();
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
            reuse_delay: self.reuse_delay.clone(),
            timer: self.timer.clone(),
        };

        let http1 = Http1PoolLayer {
            entry_state: state.clone(),
            exec: self.exec.clone(),
            max_idle: self.max_idle_per_host,
            timer: self.timer.clone(),
            set_host: self.set_host,
            _body: PhantomData,
        };

        // Fixed protocol modes use smaller service graphs; only Auto needs both
        // pools and negotiation: https://github.com/hyperium/hyper/issues/3948
        match target.version {
            Ver::Http1 => Box::new(Http1Entry {
                service: http1.layer(connect),
                state,
            }),
            Ver::Http2 => {
                let maker = Http2Layer::new(self.exec.clone(), self.timer.clone()).layer(connect);
                Box::new(Http2Entry {
                    service: singleton::Singleton::new(maker),
                    state,
                })
            }
            Ver::Auto => {
                let inspect: fn(&Established<C::Response>) -> bool = Established::should_use_http2;
                let service = negotiate::builder()
                    .connect(connect)
                    .inspect(inspect)
                    .fallback(http1)
                    .upgrade(Http2PoolLayer {
                        exec: self.exec.clone(),
                        timer: self.timer.clone(),
                        _body: PhantomData,
                        _io: PhantomData,
                    })
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
    fn checkout(
        &mut self,
        mut target: PoolTarget,
        enabled: bool,
    ) -> BoxFuture<'static, Result<Pooled<B>, BoxError>> {
        target.wait_for_reuse = enabled && !self.is_empty();
        let service = self.service.clone();
        let usage = EntryUse::new(self.state.clone());
        Box::pin(async move {
            Oneshot::new(service, target)
                .await
                .map(|service| Pooled::new(Negotiated::Left(service), enabled, usage))
        })
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
    fn protocol(&self) -> Ver {
        Ver::Http1
    }
}

// ===== impl Http2Entry =====

impl<M, B> Entry<B> for Http2Entry<singleton::Singleton<M, PoolTarget>>
where
    M: Service<PoolTarget, Response = Http2Client<B>, Error = BoxError, Future = H2MakeFuture<B>>
        + Clone
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
    fn checkout(
        &mut self,
        mut target: PoolTarget,
        enabled: bool,
    ) -> BoxFuture<'static, Result<Pooled<B>, BoxError>> {
        target.wait_for_reuse = false;
        let future = match self.service.checkout() {
            Some(future) => Either::Left(future),
            None => Either::Right(Oneshot::new(self.service.clone(), target)),
        };
        let usage = EntryUse::new(self.state.clone());
        Box::pin(async move {
            let service = match future {
                Either::Left(future) => {
                    future.await.map_err(|error| Box::new(error) as BoxError)?
                }
                Either::Right(future) => {
                    future.await.map_err(|error| Box::new(error) as BoxError)?
                }
            };
            Ok(Pooled::new(Negotiated::Right(service), enabled, usage))
        })
    }

    /// Removes a completed HTTP/2 sender when it is closed or has expired idle.
    ///
    /// Pending singleton creation is left untouched. Active sender checkouts are
    /// kept by [`Http2Client::is_reusable`].
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Option<DeferredDrop> {
        if self.state.uses.load(Ordering::Acquire) != 0 {
            return None;
        }

        self.service
            .retain(|client| client.is_reusable(now, timeout))
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
    fn protocol(&self) -> Ver {
        Ver::Http2
    }
}

// ===== impl NegotiatedEntry =====

impl<L, R, T, B> Entry<B> for NegotiatedEntry<L, R, Established<T>>
where
    L: Http1Pool<B>,
    L::Future: Send,
    R: Http2Pool<B> + negotiate::Existing<Established<T>, Response = H2Pooled<B>>,
    R::Error: Into<BoxError>,
    R::Future: Send,
    T: Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Clones the composed service and keeps the map entry active until completion.
    fn checkout(
        &mut self,
        mut target: PoolTarget,
        enabled: bool,
    ) -> BoxFuture<'static, Result<Pooled<B>, BoxError>> {
        target.wait_for_reuse = enabled && !self.is_empty();
        let service = self.service.clone();
        let usage = EntryUse::new(self.state.clone());
        Box::pin(async move {
            let future = Oneshot::new(service, target);
            match future.await {
                Ok(service) => Ok(Pooled::new(service, enabled, usage)),
                Err(error) => Err(error),
            }
        })
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
    fn protocol(&self) -> Ver {
        Ver::Auto
    }
}

// ===== impl Cache =====

impl<M, Ev, B> Http1Pool<B> for cache::Cache<M, PoolTarget, Ev>
where
    M: Service<PoolTarget, Response = Http1Client<B>, Error = BoxError> + Clone + Send + 'static,
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
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) -> Vec<Http1Client<B>> {
        self.retain(|client| client.is_reusable(now, timeout))
    }

    /// Drains unreserved idle HTTP/1 senders.
    fn drain_idle(&mut self) -> Vec<Http1Client<B>> {
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
    M: Service<Dst, Response = Http2Client<B>> + Clone + Send + 'static,
    M::Future: Send + 'static,
    Dst: Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Removes a completed sender only when the pool's health policy rejects it.
    ///
    /// A maker generation still in progress is never canceled by maintenance.
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) -> Option<Http2Client<B>> {
        self.retain(|client| client.is_reusable(now, timeout))
    }

    /// Detaches the completed sender without interrupting an active maker.
    fn take_idle(&mut self) -> Option<Http2Client<B>> {
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

impl<C> Service<PoolTarget> for ConnectionMaker<C>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
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
            descriptor,
            version,
            wait_for_reuse,
            h1_builder,
            h2_builder,
        } = target;
        let reuse_delay = if wait_for_reuse {
            self.reuse_delay.clone()
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
            if let Some((duration, timer)) = reuse_delay {
                timer.sleep(duration).await;
            }

            if let Some(started) = &start_signal {
                started.store(true, Ordering::Release);
            }
            let io = Oneshot::new(connector, descriptor)
                .await
                .map_err(Into::into)?;
            let connected = io.connected();
            Ok(Established::new(
                io,
                connected,
                version,
                h1_builder,
                h2_builder,
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
    /// Returns whether useful connection work has begun after policy waits.
    fn started(&self) -> bool {
        self.started
            .as_ref()
            .map_or(self.polled, |started| started.load(Ordering::Acquire))
    }
}

impl<B, S, T> Layer<S> for Http1PoolLayer<B>
where
    S: Service<PoolTarget, Response = Established<T>, Error = BoxError> + Clone,
    S::Future: Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Service =
        cache::Cache<Http1Connect<S, B>, PoolTarget, cache::events::WithExecutor<Executor>>;

    fn layer(&self, service: S) -> Self::Service {
        let entry_state = self.entry_state.clone();
        cache::builder()
            .executor(self.exec.clone())
            .on_background_complete(move || (entry_state.maintain)(&entry_state))
            .max_idle(self.max_idle)
            .build(
                Http1Layer::new(self.exec.clone(), self.timer.clone(), self.set_host)
                    .layer(service),
            )
    }
}

impl<B, S, T> Layer<S> for Http2PoolLayer<B, T>
where
    S: Service<Established<T>, Response = Established<T>, Error = BoxError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Service = singleton::Singleton<Http2Connect<S, B>, Established<T>>;

    fn layer(&self, service: S) -> Self::Service {
        let maker = Http2Layer::new(self.exec.clone(), self.timer.clone()).layer(service);
        singleton::Singleton::new(maker)
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
        <Http1Client<B> as Service<Request<B>>>::Future,
        <Http2Client<B> as Service<Request<B>>>::Future,
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
                    let client = service.inner();
                    client.finish_checkout();
                    client.conn_info().poisoned() || client.is_closed()
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
    }

    impl Service<ConnectionDescriptor> for TestConnector {
        type Response = tokio::io::DuplexStream;
        type Error = BoxError;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _target: ConnectionDescriptor) -> Self::Future {
            match self {
                Self::Fails => Box::pin(std::future::ready(Err(io::Error::from(
                    io::ErrorKind::ConnectionRefused,
                )
                .into()))),
                Self::Pending => Box::pin(std::future::pending()),
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

    /// Creates a descriptor for a local test origin.
    fn descriptor() -> ConnectionDescriptor {
        grouped_descriptor(Group::default())
    }

    /// Creates a descriptor with an explicit connection compatibility group.
    fn grouped_descriptor(group: Group) -> ConnectionDescriptor {
        ConnectionDescriptor::new(
            "http://localhost/".parse().expect("valid test URI"),
            group,
            None,
            None,
            None,
            None,
        )
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
        let pool = test_pool(TestConnector::Pending);

        for version in [Ver::Http1, Ver::Http2, Ver::Auto] {
            let target = PoolTarget {
                descriptor: descriptor(),
                version,
                wait_for_reuse: false,
                h1_builder: conn::http1::Builder::default(),
                h2_builder: conn::http2::Builder::new(Executor::default()),
            };
            let entry = pool.inner.targeter.service(&target);

            assert_eq!(entry.protocol(), version);
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
            .checkout(
                descriptor(),
                Ver::Http1,
                conn::http1::Builder::default(),
                conn::http2::Builder::new(Executor::default()),
            )
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
            .checkout(
                descriptor(),
                Ver::Http1,
                conn::http1::Builder::default(),
                conn::http2::Builder::new(Executor::default()),
            )
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
        let pool = test_pool(TestConnector::Fails);
        let result = pool
            .checkout(
                descriptor(),
                Ver::Http1,
                conn::http1::Builder::default(),
                conn::http2::Builder::new(Executor::default()),
            )
            .await;
        assert!(result.is_err());
        assert!(pool.inner.services.lock().is_empty());
        assert!(!pool.inner.expire.is_running());

        let pool = test_pool(TestConnector::Pending);
        let mut first = tokio_test::task::spawn(pool.checkout(
            descriptor(),
            Ver::Http1,
            conn::http1::Builder::default(),
            conn::http2::Builder::new(Executor::default()),
        ));
        let mut second = tokio_test::task::spawn(pool.checkout(
            descriptor(),
            Ver::Http1,
            conn::http1::Builder::default(),
            conn::http2::Builder::new(Executor::default()),
        ));
        assert!(first.poll().is_pending());
        assert!(second.poll().is_pending());
        drop(first);
        assert!(!pool.inner.services.lock().is_empty());
        drop(second);
        assert!(pool.inner.services.lock().is_empty());
        assert!(!pool.inner.expire.is_running());

        let pool = test_pool(TestConnector::ClosesAfterResponse);
        let mut pooled = pool
            .checkout(
                descriptor(),
                Ver::Http1,
                conn::http1::Builder::default(),
                conn::http2::Builder::new(Executor::default()),
            )
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
            .checkout(
                descriptor(),
                Ver::Http1,
                conn::http1::Builder::default(),
                conn::http2::Builder::new(Executor::default()),
            )
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
        let descriptor = grouped_descriptor(Group::new("active"));
        let mut first = pool
            .checkout(
                descriptor.clone(),
                Ver::Http1,
                conn::http1::Builder::default(),
                conn::http2::Builder::new(Executor::default()),
            )
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
            .checkout(
                descriptor,
                Ver::Http1,
                conn::http1::Builder::default(),
                conn::http2::Builder::new(Executor::default()),
            )
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
        let first_descriptor = grouped_descriptor(Group::new("first"));
        let second_descriptor = grouped_descriptor(Group::new("second"));
        let first_key = first_descriptor.id();
        let second_key = second_descriptor.id();

        let mut first = pool
            .checkout(
                first_descriptor,
                Ver::Http1,
                conn::http1::Builder::default(),
                conn::http2::Builder::new(Executor::default()),
            )
            .await
            .expect("first checkout");
        send(&mut first).await;

        let mut second = pool
            .checkout(
                second_descriptor,
                Ver::Http1,
                conn::http1::Builder::default(),
                conn::http2::Builder::new(Executor::default()),
            )
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
