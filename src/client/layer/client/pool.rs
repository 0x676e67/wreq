//! Composes the client connection pool from small service components.
//!
//! [`Map`] owns one entry per complete connection compatibility group. Each
//! entry uses [`Negotiate`] to route an established connection into an HTTP/1
//! [`cache::Cache`] or HTTP/2 [`singleton::Singleton`]. [`Capacity`] applies
//! global and scoped physical-connection limits across every map entry.
//!
//! ```text
//! Pool
//!  `- Map<connection group>
//!      `- Negotiate
//!          |- Cache<HTTP/1 sender>
//!          `- Singleton<HTTP/2 sender>
//! ```
//!
//! HTTP/1 checkouts own a sender until the response body releases it. HTTP/2
//! checkouts clone a shared sender. A connection permit is held by both sender
//! and protocol driver so capacity is released only after the socket task exits.
//!
//! # Checkout flow
//!
//! 1. The map finds or creates the complete connection-compatibility group.
//! 2. Negotiation first tries reusable HTTP/2 state, then HTTP/1 reuse, and only then allows the
//!    connection maker to dial.
//! 3. Capacity is reserved before the physical connector starts. The established transport carries
//!    that permit and the request's protocol builders into the selected handshake.
//! 4. A successful checkout transfers entry cleanup into [`Pooled`]. Cancellation instead removes
//!    the same map entry when no shared work remains.
//!
//! Pool locks protect routing and bookkeeping only. Any operation that can
//! destroy a sender, release a permit, poll user-provided service code, or wake a
//! task first moves the affected value out of the lock.

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
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};
use tower::{BoxError, Layer, Service, util::Oneshot};
use wreq_proto::{
    body::Incoming,
    conn::{self},
    rt::{Executor as _, Timer as _},
};

use self::{
    cache::Cached,
    map::{Map, Target},
    negotiate::{Negotiate, Negotiated},
    singleton::Singled,
};
pub(super) use self::{
    cache::Started,
    capacity::{BlockedBy, Capacity, ConnectionPermit, LimitKey},
};
use super::{
    Error,
    conn::{
        Established, Http1Client, Http1Connect, Http1Layer, Http2Client, Http2Connect, Http2Layer,
        SendError,
    },
};
use crate::{
    conn::{
        Connected, Connection,
        descriptor::{ConnectionDescriptor, ConnectionId},
    },
    pool::{PoolLimitScope, PoolLimits, PoolStrategy},
    rt::{Executor, Timer},
    sync::Mutex,
};

mod cache;
mod capacity;
mod map;
mod negotiate;
mod singleton;

/// Returns whether an internal singleton batch asks the client to retry.
pub(super) fn is_canceled(error: &(dyn std::error::Error + 'static)) -> bool {
    singleton::SingletonError::is_canceled(error)
}

/// Protocol mode requested for a pooled connection.
///
/// This value participates in capacity scope selection and tells negotiation
/// whether ALPN may choose the protocol or one protocol is mandatory.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(super) enum Ver {
    /// Selects the protocol from request requirements and connection negotiation.
    Auto,
    /// Requires an HTTP/1 connection.
    Http1,
    /// Requires an HTTP/2 connection.
    Http2,
}

/// Complete internal configuration used to construct a connection pool.
///
/// The client builder assembles this value once. Every mapped entry inherits the
/// same idle policy, acquisition strategy, and physical connection limits while
/// retaining request-specific protocol handshake builders in [`PoolTarget`].
#[derive(Clone, Copy, Debug)]
pub(super) struct Config {
    /// Maximum time an unused connection remains reusable.
    pub(super) idle_timeout: Option<Duration>,

    /// Maximum HTTP/1 connections retained per compatibility group.
    pub(super) max_idle_per_host: usize,

    /// Maximum number of compatibility groups retained by the outer map.
    pub(super) max_pool_size: Option<NonZeroUsize>,

    /// Delay policy applied before starting a new connection.
    pub(super) strategy: PoolStrategy,

    /// Global and per-scope physical connection limits.
    pub(super) limits: PoolLimits,
}

// ===== impl Config =====

impl Config {
    /// Returns whether completed connections may be retained for reuse.
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
            limits: PoolLimits::default(),
        }
    }
}

/// Cloneable connection-pool handle used by the HTTP client.
///
/// Cloning this type shares every mapped entry, capacity counter, and cleanup
/// task. A checkout locks the outer map only long enough to locate or create one
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
/// checkout cleanup and capacity reclamation.
///
/// At most one periodic idle task is active. Its watch receiver is notified when
/// this coordinator is dropped, allowing long idle timers to stop immediately.
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

    /// Ensures at most one periodic cleanup task is running.
    idle_task_running: AtomicBool,

    /// Closes the periodic cleanup task when the pool is dropped.
    idle_shutdown: watch::Sender<()>,

    /// Runtime used for protocol drivers and cleanup.
    exec: Executor,

    /// Clock and sleep provider used by idle cleanup.
    timer: Timer,

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

/// Factory that creates one composable service graph per destination group.
///
/// [`Map`] calls this targeter only on a key miss. It wires the physical
/// [`ConnectionMaker`] through an HTTP/1 cache and HTTP/2 singleton, then wraps
/// both paths in [`Negotiate`]. Every entry shares the client-wide capacity
/// manager and holds only a weak reference back to [`PoolInner`].
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

    /// Shared physical connection-capacity manager.
    capacity: Option<Capacity>,

    /// Scope used to build connection-limit keys.
    limit_scope: PoolLimitScope,

    /// HTTP/1 idle capacity configured for each entry.
    max_idle_per_host: usize,

    /// Optional delay before a cache miss starts connecting.
    reuse_delay: Option<(Duration, Timer)>,

    /// Pool coordinator used to reclaim idle capacity.
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
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Vec<DeferredDrop>;

    /// Reclaims one idle connection for destruction after the map lock is released.
    fn reclaim(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> Option<DeferredDrop>;

    /// Returns whether this is the entry identified by `state`.
    fn matches_identity(&self, state: &Arc<EntryState>) -> bool;

    /// Returns whether the entry has no active, pending, or idle work.
    fn is_empty(&self) -> bool;
}

/// Concrete negotiated entry stored behind the type-erased [`Entry`] trait.
///
/// `service` combines the HTTP/1 cache and HTTP/2 singleton for one compatibility
/// group. `state` counts checkout futures and carries the identity-aware cleanup
/// operation used when the final unsuccessful checkout leaves an empty entry.
struct TypedEntry<L, R, S> {
    /// Fallback and upgraded pool composition.
    service: Negotiate<L, R, S>,
    /// Checkout count and failed-checkout cleanup for this entry.
    state: Arc<EntryState>,
}

/// Idle-management operations required from the HTTP/1 cache.
///
/// This local trait keeps the type-erased entry independent of the exact cache
/// builder type while exposing only cleanup, capacity reclamation, and empty
/// state checks.
trait Http1Pool<B>:
    Service<PoolTarget, Response = Cached<Http1Client<B>>, Error = BoxError> + Clone + Send + 'static
{
    /// Removes closed or expired idle HTTP/1 senders.
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) -> Vec<Http1Client<B>>;

    /// Reclaims one matching idle HTTP/1 sender.
    fn reclaim_idle(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> Option<Http1Client<B>>;

    /// Returns whether the HTTP/1 cache owns no services.
    fn idle_is_empty(&self) -> bool;
}

/// Idle-management operations required from the HTTP/2 singleton.
///
/// In addition to singleton checkout, the entry needs to inspect and remove a
/// completed sender without starting another maker. In-progress handshakes are
/// retained because canceling them would also cancel participating checkouts.
trait Http2Pool<B, S>: negotiate::Existing<S, Response = H2Pooled<B>> + Clone + Send + 'static
where
    Self::Error: Into<BoxError>,
{
    /// Removes a closed or expired idle HTTP/2 sender.
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) -> Option<Http2Client<B>>;

    /// Reclaims the matching HTTP/2 sender when it has no checkout.
    fn reclaim_idle(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> Option<Http2Client<B>>;

    /// Returns whether the HTTP/2 singleton is empty.
    fn idle_is_empty(&self) -> bool;

    /// Returns whether the singleton has completed its shared sender.
    fn has_service(&self) -> bool;
}

/// Boxed future that establishes the singleton HTTP/2 sender.
type H2MakeFuture<B> = BoxFuture<'static, Result<Http2Client<B>, BoxError>>;

/// Generation-aware checkout of the shared HTTP/2 sender.
type H2Pooled<B> = Singled<H2MakeFuture<B>, Http2Client<B>>;

/// Type-erased connection state held until the outer map lock is released.
type DeferredDrop = Box<dyn Send>;

/// Identity-aware cleanup operation for an entry that may have become empty.
type EntryCleanup = dyn Fn(&Arc<EntryState>) + Send + Sync;

/// Protocol-agnostic sender checked out from one pool entry.
///
/// HTTP/1 owns an exclusive [`Cached`] sender that returns to its cache on drop.
/// HTTP/2 owns a [`Singled`] clone and increments shared checkout state. The
/// wrapper presents one request interface to the client and records whether
/// pooling remains enabled for response-body return handling.
///
/// Dropping this value marks HTTP/1 idle or ends the HTTP/2 checkout. A poisoned,
/// closed, or capacity-reclaimed sender is removed instead of being reused.
pub(super) struct Pooled<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// HTTP/1 cache checkout or HTTP/2 singleton checkout.
    inner: Negotiated<Cached<Http1Client<B>>, H2Pooled<B>>,
    /// Whether healthy senders should return to their pool.
    pool_enabled: bool,
    /// Runs after `inner` is dropped when this checkout discarded its sender.
    cleanup: EntryCleanupGuard,
}

/// Lazily creates physical connections under reuse and capacity policies.
///
/// The maker defers every expensive step until its future is polled. It may wait
/// for a reuse-first window, register a capacity waiter, reclaim one eligible
/// idle connection, and finally run a cloned connector through `Oneshot` so
/// readiness and `call` use the same service instance.
///
/// A weak pool reference avoids a cycle and lets capacity reclamation inspect
/// other entries only while the client still owns the pool.
struct ConnectionMaker<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Physical transport connector.
    connector: C,

    /// Optional shared capacity manager.
    capacity: Option<Capacity>,

    /// Scope used to derive the capacity key.
    limit_scope: PoolLimitScope,

    /// Pool used to reclaim idle capacity before waiting.
    pool: Weak<PoolInner<C, B>>,

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
    /// Deferred delay, capacity acquisition, and physical connect work.
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
    /// Capacity manager copied into completed senders.
    capacity: Option<Capacity>,

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
    /// Capacity manager copied into the completed sender.
    capacity: Option<Capacity>,

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
    /// Removes this exact entry after failed or discarded work leaves it empty.
    cleanup: Box<EntryCleanup>,
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
            capacity: self.capacity.clone(),
            limit_scope: self.limit_scope,
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

impl<C, B> Clone for ConnectionMaker<C, B>
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
            capacity: self.capacity.clone(),
            limit_scope: self.limit_scope,
            pool: self.pool.clone(),
            reuse_delay: self.reuse_delay.clone(),
            timer: self.timer.clone(),
        }
    }
}

// ===== impl Http1PoolLayer =====

impl<B> Clone for Http1PoolLayer<B> {
    fn clone(&self) -> Self {
        Self {
            capacity: self.capacity.clone(),
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
            capacity: self.capacity.clone(),
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
    /// Builds the outer map, entry factory, and optional capacity manager.
    pub(super) fn new(
        config: Config,
        connector: C,
        exec: Executor,
        timer: Timer,
        set_host: bool,
    ) -> Self {
        let capacity = Capacity::new(config.limits);
        let reuse_delay = match config.strategy {
            PoolStrategy::ReuseFirst(duration)
                if config.is_enabled() && duration != Duration::ZERO && !timer.is_empty() =>
            {
                Some((duration, timer.clone()))
            }
            _ => None,
        };

        let (idle_shutdown, _) = watch::channel(());
        let inner = Arc::new_cyclic(|pool| {
            let targeter = PoolTargeter {
                connector,
                capacity,
                limit_scope: config.limits.scope,
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
                idle_task_running: AtomicBool::new(false),
                idle_shutdown,
                exec,
                timer,
                services: Mutex::new(Map::new(targeter.clone(), config.max_pool_size)),
                targeter,
            }
        });

        Self { inner }
    }

    /// Checks out a sender compatible with the supplied destination and builders.
    ///
    /// Pooling-disabled calls create a temporary entry but still honor configured
    /// physical connection limits.
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

        let (future, discarded, evicted) = if self.inner.enabled {
            let mut services = self.inner.services.lock();
            let now = self.inner.now();
            let ((future, discarded), evicted) =
                services.with_service(target, |service, target| {
                    let discarded = service.retain(now, self.inner.idle_timeout);
                    let future = service.checkout(target, true);
                    (future, discarded)
                });
            (future, discarded, evicted)
        } else {
            (
                self.inner.targeter.service(&target).checkout(target, false),
                Vec::new(),
                None,
            )
        };
        drop(evicted);
        drop(discarded);

        let result = future.await;
        if result.is_ok() {
            self.inner.ensure_idle_task();
        }
        result
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
        clock_now(&self.timer)
    }

    /// Starts the single periodic idle cleanup task when one is required.
    ///
    /// The empty-pool recheck closes the race where a checkout inserts an entry
    /// while the previous cleanup task is stopping.
    fn ensure_idle_task(self: &Arc<Self>) {
        let Some(timeout) = self.idle_timeout else {
            return;
        };
        if !self.enabled || timeout == Duration::ZERO || self.timer.is_empty() {
            return;
        }
        if self
            .idle_task_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let interval = timeout.max(Duration::from_millis(90));
        let pool = Arc::downgrade(self);
        let timer = self.timer.clone();
        let mut shutdown = self.idle_shutdown.subscribe();
        self.exec.execute(async move {
            loop {
                if !wait_for_idle_tick(timer.sleep(interval), &mut shutdown).await {
                    return;
                }
                let Some(pool) = pool.upgrade() else {
                    return;
                };
                let now = pool.now();
                let (empty, removed, discarded) = {
                    let mut services = pool.services.lock();
                    let mut discarded = Vec::new();
                    let removed = services.retain(|_, entry| {
                        discarded.extend(entry.retain(now, pool.idle_timeout));
                        !entry.is_empty()
                    });
                    (services.is_empty(), removed, discarded)
                };
                drop(removed);
                drop(discarded);

                if empty {
                    pool.idle_task_running.store(false, Ordering::Release);

                    if !pool.services.lock().is_empty()
                        && pool
                            .idle_task_running
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                    {
                        continue;
                    }
                    return;
                }
            }
        });
    }

    /// Drops one idle connection to make progress for a blocked acquisition.
    fn reclaim(&self, key: &LimitKey, blocked_by: BlockedBy) {
        let (reclaimed, removed) = {
            let mut services = self.services.lock();
            let mut emptied = None;
            let reclaimed = services.iter_mut().rev().find_map(|(entry_key, entry)| {
                let reclaimed = entry.reclaim(key, blocked_by);
                if reclaimed.is_some() && entry.is_empty() {
                    emptied = Some(entry_key.clone());
                }
                reclaimed
            });
            let removed = emptied
                .and_then(|entry_key| services.remove_if(&entry_key, |entry| entry.is_empty()));
            (reclaimed, removed)
        };
        if reclaimed.is_some() {
            trace!("evicting idle connection to satisfy pool capacity");
        }
        drop(removed);
        drop(reclaimed);
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

    /// Composes connection making, inspection, HTTP/1 cache, and HTTP/2 singleton.
    fn service(&self, target: &PoolTarget) -> Self::Service {
        let connect = ConnectionMaker {
            connector: self.connector.clone(),
            capacity: self.capacity.clone(),
            limit_scope: self.limit_scope,
            pool: self.pool.clone(),
            reuse_delay: self.reuse_delay.clone(),
            timer: self.timer.clone(),
        };
        let inspect: fn(&Established<C::Response>) -> bool = Established::should_use_http2;
        let service = negotiate::builder()
            .connect(connect)
            .inspect(inspect)
            .fallback(Http1PoolLayer {
                capacity: self.capacity.clone(),
                exec: self.exec.clone(),
                max_idle: self.max_idle_per_host,
                timer: self.timer.clone(),
                set_host: self.set_host,
                _body: PhantomData,
            })
            .upgrade(Http2PoolLayer {
                capacity: self.capacity.clone(),
                exec: self.exec.clone(),
                timer: self.timer.clone(),
                _body: PhantomData,
                _io: PhantomData,
            })
            .build::<PoolTarget>();

        let pool = self.pool.clone();
        let key = target.descriptor.id();
        let state = Arc::new(EntryState {
            uses: AtomicUsize::new(0),
            cleanup: Box::new(move |identity| {
                let Some(pool) = pool.upgrade() else {
                    return;
                };
                let (removed, retained) = {
                    let mut services = pool.services.lock();
                    let removed = services.remove_if(&key, |entry| {
                        entry.matches_identity(identity) && entry.is_empty()
                    });
                    let retained = removed.is_none()
                        && services.iter_mut().any(|(entry_key, entry)| {
                            entry_key == &key
                                && entry.matches_identity(identity)
                                && !entry.is_empty()
                        });
                    (removed, retained)
                };
                drop(removed);
                if retained {
                    pool.ensure_idle_task();
                }
            }),
        });

        Box::new(TypedEntry { service, state })
    }
}

// ===== impl TypedEntry =====

impl<L, R, T, B> Entry<B> for TypedEntry<L, R, Established<T>>
where
    L: Http1Pool<B>,
    L::Future: Send,
    R: Http2Pool<B, Established<T>>,
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
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Vec<DeferredDrop> {
        let mut discarded = Vec::new();
        if self.service.upgrade().has_service() {
            discarded.extend(
                self.service
                    .retain_pending(|_| false)
                    .into_iter()
                    .map(|connection| Box::new(connection) as DeferredDrop),
            );
        } else if self.state.uses.load(Ordering::Acquire) == 0 {
            discarded.extend(
                self.service
                    .retain_pending(|connection| !is_expired(connection.idle_at(), now, timeout))
                    .into_iter()
                    .map(|connection| Box::new(connection) as DeferredDrop),
            );
        }
        discarded.extend(
            self.service
                .fallback_mut()
                .retain_idle(now, timeout)
                .into_iter()
                .map(|connection| Box::new(connection) as DeferredDrop),
        );
        discarded.extend(
            self.service
                .upgrade_mut()
                .retain_idle(now, timeout)
                .into_iter()
                .map(|connection| Box::new(connection) as DeferredDrop),
        );
        discarded
    }

    /// Reclaims pending, HTTP/1, or idle HTTP/2 connections in that order.
    fn reclaim(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> Option<DeferredDrop> {
        if let Some(connection) = self
            .service
            .take_pending_if(|connection| connection.matches_limit(key, blocked_by))
        {
            return Some(Box::new(connection));
        }
        if let Some(connection) = self.service.fallback_mut().reclaim_idle(key, blocked_by) {
            return Some(Box::new(connection));
        }
        self.service
            .upgrade_mut()
            .reclaim_idle(key, blocked_by)
            .map(|connection| Box::new(connection) as DeferredDrop)
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

    /// Removes one HTTP/1 sender matching the blocked capacity.
    fn reclaim_idle(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> Option<Http1Client<B>> {
        self.try_pop_idle_if(|client| client.matches_limit(key, blocked_by))
    }

    /// Returns whether the cache owns no ready, idle, or active sender.
    fn idle_is_empty(&self) -> bool {
        self.is_empty()
    }
}

// ===== impl Singleton =====

impl<M, B, S: 'static> Http2Pool<B, S> for singleton::Singleton<M, S>
where
    M: Service<S, Response = Http2Client<B>, Error = BoxError, Future = H2MakeFuture<B>>
        + Clone
        + Send
        + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Retains a reusable HTTP/2 sender or clears the singleton.
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) -> Option<Http2Client<B>> {
        self.retain(|client| client.is_reusable(now, timeout))
    }

    /// Removes a matching HTTP/2 sender only when no checkout uses it.
    fn reclaim_idle(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> Option<Http2Client<B>> {
        self.try_take_if(|client| client.is_idle() && client.matches_limit(key, blocked_by))
    }

    /// Returns whether no HTTP/2 sender exists or is being made.
    fn idle_is_empty(&self) -> bool {
        self.is_empty()
    }

    /// Returns whether the HTTP/2 sender has completed creation.
    fn has_service(&self) -> bool {
        singleton::Singleton::has_service(self)
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

impl<C, B> Service<PoolTarget> for ConnectionMaker<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
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
        let deferred = self.capacity.is_some() || reuse_delay.is_some();
        let started = deferred.then(|| Arc::new(AtomicBool::new(false)));
        let start_signal = started.clone();
        let capacity = self.capacity.clone();
        let limit_scope = self.limit_scope;
        let connector = self.connector.clone();
        let pool = self.pool.clone();
        let timer = self.timer.clone();

        let future = Box::pin(async move {
            if let Some((duration, timer)) = reuse_delay {
                timer.sleep(duration).await;
            }

            let limit_key = capacity
                .as_ref()
                .map(|_| LimitKey::new(limit_scope, descriptor.uri(), version, &descriptor.id()));
            let permit = match (capacity.as_ref(), limit_key.as_ref()) {
                (Some(capacity), Some(key)) => {
                    let mut acquire = capacity.acquire(key.clone());
                    let mut reclaim = true;
                    std::future::poll_fn(|cx| {
                        let result = Pin::new(&mut acquire).poll(cx);
                        if reclaim && result.is_pending() {
                            reclaim = false;
                            if let Some(blocked_by) = capacity.blocked_by(key) {
                                if let Some(pool) = pool.upgrade() {
                                    pool.reclaim(key, blocked_by);
                                }
                            }
                        }
                        result
                    })
                    .await?
                }
                _ => ConnectionPermit::default(),
            };

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
                permit,
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
        cache::builder()
            .executor(self.exec.clone())
            .max_idle(self.max_idle)
            .build(
                Http1Layer::new(
                    self.capacity.clone(),
                    self.exec.clone(),
                    self.timer.clone(),
                    self.set_host,
                )
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
        singleton::Singleton::new(
            Http2Layer::new(self.capacity.clone(), self.exec.clone(), self.timer.clone())
                .layer(service),
        )
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
    fn new(
        inner: Negotiated<Cached<Http1Client<B>>, H2Pooled<B>>,
        pool_enabled: bool,
        usage: EntryUse,
    ) -> Self {
        if let Negotiated::Upgraded(service) = &inner {
            service.inner().begin_checkout();
        }
        let cleanup = usage.into_cleanup();
        Self {
            inner,
            pool_enabled,
            cleanup,
        }
    }

    /// Returns whether this checkout uses HTTP/1.
    pub(super) fn is_http1(&self) -> bool {
        matches!(self.inner, Negotiated::Fallback(_))
    }

    /// Returns whether this checkout uses HTTP/2.
    pub(super) fn is_http2(&self) -> bool {
        matches!(self.inner, Negotiated::Upgraded(_))
    }

    /// Returns whether the sender came from an existing pooled connection.
    pub(super) fn is_reused(&self) -> bool {
        match &self.inner {
            Negotiated::Fallback(service) => service.is_reused(),
            Negotiated::Upgraded(service) => service.is_reused(),
        }
    }

    /// Returns whether completed senders may be retained for reuse.
    pub(super) fn is_pool_enabled(&self) -> bool {
        self.pool_enabled
    }

    /// Returns whether the connection consumes a configured capacity slot.
    pub(super) fn has_connection_limit(&self) -> bool {
        match &self.inner {
            Negotiated::Fallback(service) => service.inner().has_connection_limit(),
            Negotiated::Upgraded(service) => service.inner().has_connection_limit(),
        }
    }

    /// Returns whether the protocol sender can accept a request immediately.
    pub(super) fn is_ready(&self) -> bool {
        match &self.inner {
            Negotiated::Fallback(service) => service.inner().is_ready(),
            Negotiated::Upgraded(service) => service.inner().is_ready(),
        }
    }

    /// Polls protocol readiness and discards a sender that has failed.
    pub(super) fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        match &mut self.inner {
            Negotiated::Fallback(service) => {
                let ready = service.inner_mut().poll_ready(cx);
                if matches!(&ready, Poll::Ready(Err(_))) {
                    service.discard_on_drop();
                }
                ready
            }
            Negotiated::Upgraded(service) => {
                let ready = service.inner_mut().poll_ready(cx);
                if matches!(&ready, Poll::Ready(Err(_))) {
                    service.inner().poison();
                    service.discard_shared();
                }
                ready
            }
        }
    }

    /// Returns metadata for the underlying physical connection.
    pub(super) fn conn_info(&self) -> &Connected {
        match &self.inner {
            Negotiated::Fallback(service) => service.inner().conn_info(),
            Negotiated::Upgraded(service) => service.inner().conn_info(),
        }
    }

    /// Sends a request without waiting for an additional readiness transition.
    #[allow(clippy::result_large_err)]
    pub(super) fn try_send_request(
        &mut self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, SendError<B>>> {
        match &mut self.inner {
            Negotiated::Fallback(service) => {
                Either::Left(service.inner_mut().try_send_request(req))
            }
            Negotiated::Upgraded(service) => {
                Either::Right(service.inner_mut().try_send_request(req))
            }
        }
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
            Negotiated::Fallback(service) => {
                service.inner_mut().mark_idle();
                if !service.inner().is_open() {
                    service.discard_on_drop();
                }
                let returned = service.return_to_cache_if(|client| !client.should_release_idle());
                if self.pool_enabled && !returned {
                    self.cleanup.arm();
                }
            }
            Negotiated::Upgraded(service) => {
                let discard = {
                    let client = service.inner();
                    client.finish_checkout();
                    client.should_release_idle()
                        || client.conn_info().poisoned()
                        || client.is_closed()
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
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
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
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
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
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            });
        if self.cleanup_on_drop && previous == Ok(1) {
            (state.cleanup)(state);
        }
    }
}

// ===== impl EntryCleanupGuard =====

impl EntryCleanupGuard {
    /// Requests one identity-aware empty-entry check after sender destruction.
    fn arm(&mut self) {
        self.armed = true;
    }
}

impl Drop for EntryCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Some(state) = &self.state {
                (state.cleanup)(state);
            }
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

/// Waits for the next cleanup tick or for the pool shutdown signal.
async fn wait_for_idle_tick<F>(mut sleep: F, shutdown: &mut watch::Receiver<()>) -> bool
where
    F: Future<Output = ()> + Unpin,
{
    let mut changed = std::pin::pin!(shutdown.changed());

    std::future::poll_fn(|cx| {
        if changed.as_mut().poll(cx).is_ready() {
            Poll::Ready(false)
        } else if Pin::new(&mut sleep).poll(cx).is_ready() {
            Poll::Ready(true)
        } else {
            Poll::Pending
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::io;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::group::Group;

    /// Connector behavior used to exercise unsuccessful checkout cleanup.
    #[derive(Clone, Copy)]
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
        StallsAfterRequest,
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
                        assert!(read > 0);
                        server
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .expect("write response");
                        while server.read(&mut request).await.unwrap_or_default() != 0 {}
                    });
                    Ok(client)
                }),
                Self::StallsAfterRequest => Box::pin(async {
                    let (client, mut server) = tokio::io::duplex(1024);
                    tokio::spawn(async move {
                        let mut request = [0; 1024];
                        let read = server.read(&mut request).await.expect("read request");
                        assert!(read > 0);
                        std::future::pending::<()>().await;
                    });
                    Ok(client)
                }),
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

    #[tokio::test]
    async fn idle_wait_stops_when_pool_is_dropped() {
        let (shutdown, mut receiver) = watch::channel(());
        let wait = wait_for_idle_tick(std::future::pending(), &mut receiver);

        drop(shutdown);

        assert!(!wait.await);
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
        assert!(!pool.inner.idle_task_running.load(Ordering::Acquire));

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
        assert!(!pool.inner.idle_task_running.load(Ordering::Acquire));

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
            .try_send_request(
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
        assert!(!pool.inner.idle_task_running.load(Ordering::Acquire));

        let pool = test_pool(TestConnector::StallsAfterRequest);
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
            pooled.try_send_request(
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            ),
        );
        assert!(response.poll().is_pending());
        drop(response);
        drop(pooled);

        assert!(pool.inner.services.lock().is_empty());
        assert!(!pool.inner.idle_task_running.load(Ordering::Acquire));

        let pool = Pool::new(
            Config {
                idle_timeout: None,
                limits: PoolLimits::builder().max_connections(1).build(),
                ..Config::default()
            },
            TestConnector::KeepsAlive,
            Executor::default(),
            Timer::default(),
            true,
        );
        let mut first = pool
            .checkout(
                grouped_descriptor(Group::new("first")),
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
            .try_send_request(
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

        let second = tokio::time::timeout(
            Duration::from_secs(1),
            pool.checkout(
                grouped_descriptor(Group::new("second")),
                Ver::Http1,
                conn::http1::Builder::default(),
                conn::http2::Builder::new(Executor::default()),
            ),
        )
        .await
        .expect("capacity reclaim should make progress")
        .expect("second checkout");

        assert_eq!(pool.inner.services.lock().iter_mut().count(), 1);
        drop(second);
    }
}
