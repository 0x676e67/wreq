//! Composes the client connection pool from small service components.
//!
//! [`Map`] owns one entry per complete connection compatibility group. Each
//! entry uses [`Negotiate`] to route an established connection into an HTTP/1
//! [`cache::Cache`] or HTTP/2 [`singleton::Singleton`]. [`Capacity`] applies
//! global and scoped physical-connection limits across every map entry.
//!
//! HTTP/1 checkouts own a sender until the response body releases it. HTTP/2
//! checkouts clone a shared sender. A connection permit is held by both sender
//! and protocol driver so capacity is released only after the socket task exits.

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

use futures_util::future::{BoxFuture, Either};
use http::{Request, Response};
use http_body::Body;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Layer, Service, util::Oneshot};
use wreq_proto::{
    body::Incoming,
    conn::{self, TrySendError as ConnTrySendError},
    rt::{Executor as _, Timer as _},
};

use self::{
    cache::{Cached, Started},
    capacity::{BlockedBy, Capacity, ConnectionPermit, LimitKey},
    map::{Map, Target},
    negotiate::{Negotiate, Negotiated},
    singleton::Singled,
};
use super::Error;
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

/// A marker identifying the protocol mode of a pooled connection.
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

/// Internal connection-pool configuration.
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

impl Config {
    /// Returns whether completed connections may be retained for reuse.
    pub(super) fn is_enabled(self) -> bool {
        self.max_idle_per_host > 0
    }
}

impl Default for Config {
    /// Creates an unbounded pool with no idle timeout.
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

/// Shared pool coordinator around the composable entry services.
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
#[derive(Clone)]
pub(super) struct PoolTarget {
    /// Complete blueprint for the physical connection.
    descriptor: ConnectionDescriptor,
    /// Requested protocol selection mode.
    version: Ver,
    /// HTTP/1 handshake configuration for this request.
    h1_builder: conn::http1::Builder,
    /// HTTP/2 handshake configuration for this request.
    h2_builder: conn::http2::Builder<Executor>,
}

/// Creates one composable pool entry for a destination group.
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
    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// Type-erased operations required from one mapped pool entry.
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
    /// Removes expired or closed idle connections.
    fn retain(&mut self, now: Instant, timeout: Option<Duration>);

    /// Reclaims one idle connection that can satisfy a blocked capacity key.
    fn reclaim(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> bool;

    /// Returns whether the entry has no active, pending, or idle work.
    fn is_empty(&self) -> bool;
}

/// Concrete negotiated entry stored behind the type-erased [`Entry`] trait.
struct TypedEntry<L, R, S> {
    /// Fallback and upgraded pool composition.
    service: Negotiate<L, R, S>,
    /// Number of checkout futures keeping this map entry active.
    uses: Arc<AtomicUsize>,
}

/// Idle-management operations required from the HTTP/1 cache.
trait Http1Pool<B>:
    Service<PoolTarget, Response = Cached<Http1Client<B>>, Error = BoxError> + Clone + Send + 'static
{
    /// Removes closed or expired idle HTTP/1 senders.
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>);
    /// Reclaims one matching idle HTTP/1 sender.
    fn reclaim_idle(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> bool;
    /// Returns whether the HTTP/1 cache owns no services.
    fn idle_is_empty(&self) -> bool;
}

/// Idle-management operations required from the HTTP/2 singleton.
trait Http2Pool<B, S>: negotiate::Existing<S, Response = H2Pooled<B>> + Clone + Send + 'static
where
    Self::Error: Into<BoxError>,
{
    /// Removes a closed or expired idle HTTP/2 sender.
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>);
    /// Reclaims the matching HTTP/2 sender when it has no checkout.
    fn reclaim_idle(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> bool;
    /// Returns whether the HTTP/2 singleton is empty.
    fn idle_is_empty(&self) -> bool;
    /// Returns whether the singleton has completed its shared sender.
    fn has_service(&self) -> bool;
}

type H2MakeFuture<B> = BoxFuture<'static, Result<Http2Client<B>, BoxError>>;
type H2Pooled<B> = Singled<H2MakeFuture<B>, Http2Client<B>>;

/// Protocol-agnostic sender checked out from a pool entry.
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
}

/// Reusable HTTP/1 sender and its physical connection metadata.
struct Http1Client<B> {
    /// Metadata and poisoning state for the connection.
    conn_info: Connected,
    /// HTTP/1 request sender, uniquely checked out.
    tx: conn::http1::SendRequest<B>,
    /// Physical connection-capacity reservation.
    permit: ConnectionPermit,
    /// Capacity manager used to detect queued work.
    capacity: Option<Capacity>,
    /// Last time the sender became idle.
    idle_at: Instant,
    /// Clock used for idle timestamps.
    timer: Timer,
}

/// Cloneable HTTP/2 sender and its shared connection metadata.
struct Http2Client<B> {
    /// Metadata and poisoning state for the connection.
    conn_info: Connected,
    /// Cloneable multiplexed request sender.
    tx: conn::http2::SendRequest<B>,
    /// Physical connection-capacity reservation.
    permit: ConnectionPermit,
    /// Capacity manager used to detect queued work.
    capacity: Option<Capacity>,
    /// Checkout count and idle timestamp shared by sender clones.
    state: Arc<Http2State>,
    /// Clock used for idle timestamps.
    timer: Timer,
}

/// Shared checkout state for one HTTP/2 connection.
struct Http2State {
    /// Number of `Pooled` handles currently using the sender.
    checkouts: AtomicUsize,
    /// Time when the final checkout was released.
    idle_at: Mutex<Instant>,
}

/// Physical connection plus metadata needed by protocol handshakes.
struct Established<T> {
    /// Connected transport stream.
    io: T,
    /// Metadata supplied by the connector.
    connected: Connected,
    /// Permit retained for the physical connection lifetime.
    permit: ConnectionPermit,
    /// Requested protocol mode.
    version: Ver,
    /// Time the transport became available for handshake.
    idle_at: Instant,
}

/// Lazily creates physical connections under reuse and capacity policies.
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
struct ConnectFuture<T> {
    /// Deferred delay, capacity acquisition, and physical connect work.
    future: BoxFuture<'static, Result<T, BoxError>>,
    /// Records whether the future has ever been polled.
    polled: bool,
    /// Separates waiting for policy from useful connection work.
    started: Option<Arc<AtomicBool>>,
}

/// Layer that turns established transports into cached HTTP/1 senders.
struct Http1PoolLayer<B> {
    /// HTTP/1 handshake configuration.
    builder: conn::http1::Builder,
    /// Capacity manager copied into completed senders.
    capacity: Option<Capacity>,
    /// Runtime used by protocol drivers and lost-race work.
    exec: Executor,
    /// Maximum idle senders retained by the cache.
    max_idle: usize,
    /// Clock used for idle timestamps.
    timer: Timer,
    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// Layer that turns established transports into one shared HTTP/2 sender.
struct Http2PoolLayer<B, T> {
    /// HTTP/2 handshake configuration.
    builder: conn::http2::Builder<Executor>,
    /// Capacity manager copied into the completed sender.
    capacity: Option<Capacity>,
    /// Runtime used by the protocol driver.
    exec: Executor,
    /// Clock used for idle timestamps.
    timer: Timer,
    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
    /// Carries the transport type required by the layer.
    _io: PhantomData<fn(T)>,
}

/// Makes cached HTTP/1 senders from pool targets.
struct Http1Handshake<S, B> {
    /// Service producing established transports.
    service: S,
    /// HTTP/1 handshake configuration.
    builder: conn::http1::Builder,
    /// Capacity manager copied into completed senders.
    capacity: Option<Capacity>,
    /// Runtime used by the protocol driver.
    exec: Executor,
    /// Clock used for idle timestamps.
    timer: Timer,
    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// Future that connects and then performs the HTTP/1 handshake.
struct Http1HandshakeFuture<F, T, B> {
    /// Current connect or handshake phase.
    state: Http1HandshakeState<F, B>,
    /// HTTP/1 handshake configuration moved into the handshake phase.
    builder: Option<conn::http1::Builder>,
    /// Capacity manager moved into the completed sender.
    capacity: Option<Capacity>,
    /// Runtime used by the protocol driver.
    exec: Option<Executor>,
    /// Clock used for idle timestamps.
    timer: Option<Timer>,
    /// Carries the transport type produced by the connect future.
    _io: PhantomData<fn(T)>,
}

/// Phases of an HTTP/1 pooled-service creation.
enum Http1HandshakeState<F, B> {
    /// Waiting for the physical transport.
    Connecting(F),
    /// Performing the protocol handshake.
    Handshaking(BoxFuture<'static, Result<Http1Client<B>, BoxError>>),
    /// Future has completed or entered an invalid state.
    Done,
}

/// Makes one cloneable HTTP/2 sender from an established transport.
struct Http2Handshake<S, B> {
    /// Identity service supplying the negotiated transport.
    service: S,
    /// HTTP/2 handshake configuration.
    builder: conn::http2::Builder<Executor>,
    /// Capacity manager copied into the completed sender.
    capacity: Option<Capacity>,
    /// Runtime used by the protocol driver.
    exec: Executor,
    /// Clock used for idle timestamps.
    timer: Timer,
    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// RAII count keeping a mapped entry alive while checkout is pending.
struct EntryUse(Arc<AtomicUsize>);

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
    /// Clones configuration while sharing connector, capacity, and pool state.
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
            _body: PhantomData,
        }
    }
}

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
    /// Clones the lazy physical-connection maker.
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

impl<B> Clone for Http1PoolLayer<B> {
    /// Clones HTTP/1 layer configuration.
    fn clone(&self) -> Self {
        Self {
            builder: self.builder.clone(),
            capacity: self.capacity.clone(),
            exec: self.exec.clone(),
            max_idle: self.max_idle,
            timer: self.timer.clone(),
            _body: PhantomData,
        }
    }
}

impl<B, T> Clone for Http2PoolLayer<B, T> {
    /// Clones HTTP/2 layer configuration.
    fn clone(&self) -> Self {
        Self {
            builder: self.builder.clone(),
            capacity: self.capacity.clone(),
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            _body: PhantomData,
            _io: PhantomData,
        }
    }
}

impl<S: Clone, B> Clone for Http1Handshake<S, B> {
    /// Clones the HTTP/1 handshake service and runtime configuration.
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            builder: self.builder.clone(),
            capacity: self.capacity.clone(),
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            _body: PhantomData,
        }
    }
}

impl<S: Clone, B> Clone for Http2Handshake<S, B> {
    /// Clones the HTTP/2 handshake service and runtime configuration.
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            builder: self.builder.clone(),
            capacity: self.capacity.clone(),
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            _body: PhantomData,
        }
    }
}

impl<B> Clone for Http2Client<B> {
    /// Clones the multiplexed sender while sharing checkout state and capacity.
    fn clone(&self) -> Self {
        Self {
            conn_info: self.conn_info.clone(),
            tx: self.tx.clone(),
            permit: self.permit.clone(),
            capacity: self.capacity.clone(),
            state: self.state.clone(),
            timer: self.timer.clone(),
        }
    }
}

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
    pub(super) fn new(config: Config, connector: C, exec: Executor, timer: Timer) -> Self {
        let capacity = Capacity::new(config.limits);
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
                capacity,
                limit_scope: config.limits.scope,
                max_idle_per_host: config.max_idle_per_host,
                reuse_delay,
                pool: pool.clone(),
                exec: exec.clone(),
                timer: timer.clone(),
                _body: PhantomData,
            };

            PoolInner {
                enabled: config.is_enabled(),
                idle_timeout: config.idle_timeout,
                idle_task_running: AtomicBool::new(false),
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
            h1_builder,
            h2_builder,
        };

        let future = if self.inner.enabled {
            let mut services = self.inner.services.lock();
            let now = self.inner.now();
            let service = services.service(&target);
            service.retain(now, self.inner.idle_timeout);
            service.checkout(target, true)
        } else {
            self.inner.targeter.service(&target).checkout(target, false)
        };

        self.inner.ensure_idle_task();
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
    /// Creates a handle sharing every pool entry and limit counter.
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

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
        self.exec.execute(async move {
            loop {
                timer.sleep(interval).await;
                let Some(pool) = pool.upgrade() else {
                    return;
                };
                let now = pool.now();
                let mut services = pool.services.lock();
                services.retain(|_, entry| {
                    entry.retain(now, pool.idle_timeout);
                    !entry.is_empty()
                });
                if services.is_empty() {
                    drop(services);
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
        let reclaimed = self
            .services
            .lock()
            .iter_mut()
            .any(|(_, entry)| entry.reclaim(key, blocked_by));
        if reclaimed {
            trace!("evicting idle connection to satisfy pool capacity");
        }
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
        let inspect: fn(&Established<C::Response>) -> bool = should_use_http2;
        let service = negotiate::builder()
            .connect(connect)
            .inspect(inspect)
            .fallback(Http1PoolLayer {
                builder: target.h1_builder.clone(),
                capacity: self.capacity.clone(),
                exec: self.exec.clone(),
                max_idle: self.max_idle_per_host,
                timer: self.timer.clone(),
                _body: PhantomData,
            })
            .upgrade(Http2PoolLayer {
                builder: target.h2_builder.clone(),
                capacity: self.capacity.clone(),
                exec: self.exec.clone(),
                timer: self.timer.clone(),
                _body: PhantomData,
                _io: PhantomData,
            })
            .build::<PoolTarget>();

        Box::new(TypedEntry {
            service,
            uses: Arc::new(AtomicUsize::new(0)),
        })
    }
}

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
        target: PoolTarget,
        enabled: bool,
    ) -> BoxFuture<'static, Result<Pooled<B>, BoxError>> {
        let service = self.service.clone();
        let usage = EntryUse::new(self.uses.clone());
        Box::pin(async move {
            let _usage = usage;
            Oneshot::new(service, target)
                .await
                .map(|service| Pooled::new(service, enabled))
        })
    }

    /// Cleans pending negotiation results and both protocol pools.
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) {
        if self.service.upgrade().has_service() {
            self.service.retain_pending(|_| false);
        } else if self.uses.load(Ordering::Acquire) == 0 {
            self.service
                .retain_pending(|connection| !is_expired(connection.idle_at, now, timeout));
        }
        self.service.fallback_mut().retain_idle(now, timeout);
        self.service.upgrade_mut().retain_idle(now, timeout);
    }

    /// Reclaims pending, HTTP/1, or idle HTTP/2 connections in that order.
    fn reclaim(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> bool {
        self.service
            .take_pending_if(|connection| {
                matches!(blocked_by, BlockedBy::Total) || connection.permit.matches(key)
            })
            .is_some()
            || self.service.fallback_mut().reclaim_idle(key, blocked_by)
            || self.service.upgrade_mut().reclaim_idle(key, blocked_by)
    }

    /// Returns whether no checkout or protocol pool state remains.
    fn is_empty(&self) -> bool {
        self.uses.load(Ordering::Acquire) == 0
            && self.service.pending_is_empty()
            && self.service.fallback().idle_is_empty()
            && self.service.upgrade().idle_is_empty()
    }
}

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
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) {
        self.retain(|client| client.is_reusable(now, timeout));
    }

    /// Removes one HTTP/1 sender matching the blocked capacity.
    fn reclaim_idle(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> bool {
        self.try_pop_idle_if(|client| client.matches_limit(key, blocked_by))
            .is_some()
    }

    /// Returns whether the cache owns no ready, idle, or active sender.
    fn idle_is_empty(&self) -> bool {
        self.is_empty()
    }
}

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
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) {
        self.retain(|client| client.is_reusable(now, timeout));
    }

    /// Removes a matching HTTP/2 sender only when no checkout uses it.
    fn reclaim_idle(&mut self, key: &LimitKey, blocked_by: BlockedBy) -> bool {
        self.try_take_if(|client| client.is_idle() && client.matches_limit(key, blocked_by))
            .is_some()
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

    /// Delegates readiness to the physical connector.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.connector.poll_ready(cx).map_err(Into::into)
    }

    /// Defers reuse delay, capacity acquisition, and connecting until polled.
    fn call(&mut self, target: PoolTarget) -> Self::Future {
        let deferred = self.capacity.is_some() || self.reuse_delay.is_some();
        let started = deferred.then(|| Arc::new(AtomicBool::new(false)));
        let start_signal = started.clone();
        let capacity = self.capacity.clone();
        let limit_key = capacity.as_ref().map(|_| {
            LimitKey::new(
                self.limit_scope,
                target.descriptor.uri(),
                target.version,
                &target.descriptor.id(),
            )
        });
        let connector = self.connector.clone();
        let pool = self.pool.clone();
        let reuse_delay = self.reuse_delay.clone();
        let timer = self.timer.clone();
        let version = target.version;

        let future = Box::pin(async move {
            if let Some((duration, timer)) = reuse_delay {
                timer.sleep(duration).await;
            }

            let permit = match (capacity.as_ref(), limit_key.as_ref()) {
                (Some(capacity), Some(key)) => {
                    if let Some(blocked_by) = capacity.blocked_by(key) {
                        if let Some(pool) = pool.upgrade() {
                            pool.reclaim(key, blocked_by);
                        }
                    }
                    capacity.acquire(key.clone()).await?
                }
                _ => ConnectionPermit::default(),
            };

            if let Some(started) = &start_signal {
                started.store(true, Ordering::Release);
            }
            let io = Oneshot::new(connector, target.descriptor)
                .await
                .map_err(Into::into)?;
            let connected = io.connected();
            Ok(Established {
                io,
                connected,
                permit,
                version,
                idle_at: clock_now(&timer),
            })
        });

        ConnectFuture {
            future,
            polled: false,
            started,
        }
    }
}

impl<T> Future for ConnectFuture<T> {
    type Output = Result<T, BoxError>;

    /// Marks the future as observed and polls deferred connection work.
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
        cache::Cache<Http1Handshake<S, B>, PoolTarget, cache::events::WithExecutor<Executor>>;

    /// Wraps the connector with HTTP/1 handshaking and an idle-service cache.
    fn layer(&self, service: S) -> Self::Service {
        cache::builder()
            .executor(self.exec.clone())
            .max_idle(self.max_idle)
            .build(Http1Handshake {
                service,
                builder: self.builder.clone(),
                capacity: self.capacity.clone(),
                exec: self.exec.clone(),
                timer: self.timer.clone(),
                _body: PhantomData,
            })
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
    type Service = singleton::Singleton<Http2Handshake<S, B>, Established<T>>;

    /// Wraps negotiated transports with HTTP/2 handshaking and shared checkout.
    fn layer(&self, service: S) -> Self::Service {
        singleton::Singleton::new(Http2Handshake {
            service,
            builder: self.builder.clone(),
            capacity: self.capacity.clone(),
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            _body: PhantomData,
        })
    }
}

impl<S, T, B> Service<PoolTarget> for Http1Handshake<S, B>
where
    S: Service<PoolTarget, Response = Established<T>, Error = BoxError> + Clone,
    S::Future: Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Http1Client<B>;
    type Error = BoxError;
    type Future = Http1HandshakeFuture<S::Future, T, B>;

    /// Delegates readiness to the physical-connection service.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    /// Starts connection establishment before advancing to the HTTP/1 handshake.
    fn call(&mut self, target: PoolTarget) -> Self::Future {
        Http1HandshakeFuture {
            state: Http1HandshakeState::Connecting(self.service.call(target)),
            builder: Some(self.builder.clone()),
            capacity: self.capacity.clone(),
            exec: Some(self.exec.clone()),
            timer: Some(self.timer.clone()),
            _io: PhantomData,
        }
    }
}

impl<F, T, B> Future for Http1HandshakeFuture<F, T, B>
where
    F: Future<Output = Result<Established<T>, BoxError>> + Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Output = Result<Http1Client<B>, BoxError>;

    /// Advances connection establishment and the HTTP/1 handshake in sequence.
    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        loop {
            match &mut self.state {
                Http1HandshakeState::Connecting(future) => {
                    let established = match ready!(Pin::new(future).poll(cx)) {
                        Ok(established) => established,
                        Err(error) => {
                            self.state = Http1HandshakeState::Done;
                            return Poll::Ready(Err(error));
                        }
                    };
                    let Some(builder) = self.builder.take() else {
                        self.state = Http1HandshakeState::Done;
                        return Poll::Ready(Err(HandshakeStateError.into()));
                    };
                    let Some(exec) = self.exec.take() else {
                        self.state = Http1HandshakeState::Done;
                        return Poll::Ready(Err(HandshakeStateError.into()));
                    };
                    let Some(timer) = self.timer.take() else {
                        self.state = Http1HandshakeState::Done;
                        return Poll::Ready(Err(HandshakeStateError.into()));
                    };
                    let capacity = self.capacity.take();
                    self.state = Http1HandshakeState::Handshaking(Box::pin(establish_http1(
                        established,
                        builder,
                        capacity,
                        exec,
                        timer,
                    )));
                }
                Http1HandshakeState::Handshaking(future) => {
                    let result = ready!(future.as_mut().poll(cx));
                    self.state = Http1HandshakeState::Done;
                    return Poll::Ready(result);
                }
                Http1HandshakeState::Done => return Poll::Pending,
            }
        }
    }
}

impl<F, T, B> Started for Http1HandshakeFuture<F, T, B>
where
    F: Future<Output = Result<Established<T>, BoxError>> + Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Returns whether connection or handshake work has started.
    fn started(&self) -> bool {
        match &self.state {
            Http1HandshakeState::Connecting(future) => future.started(),
            Http1HandshakeState::Handshaking(_) | Http1HandshakeState::Done => true,
        }
    }
}

impl<S, T, B> Service<Established<T>> for Http2Handshake<S, B>
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
    type Response = Http2Client<B>;
    type Error = BoxError;
    type Future = H2MakeFuture<B>;

    /// Delegates readiness to the negotiated-transport service.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    /// Starts the HTTP/2 handshake for an already negotiated transport.
    fn call(&mut self, target: Established<T>) -> Self::Future {
        let future = self.service.call(target);
        let builder = self.builder.clone();
        let capacity = self.capacity.clone();
        let exec = self.exec.clone();
        let timer = self.timer.clone();
        Box::pin(
            async move { establish_http2(future.await?, builder, capacity, exec, timer).await },
        )
    }
}

/// Handshakes an HTTP/1 transport and starts its connection driver.
///
/// The sender and driver each retain the same capacity permit. Capacity is
/// released only after both the pooled sender and physical connection are gone.
async fn establish_http1<T, B>(
    established: Established<T>,
    builder: conn::http1::Builder,
    capacity: Option<Capacity>,
    exec: Executor,
    timer: Timer,
) -> Result<Http1Client<B>, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let Established {
        io,
        connected,
        permit,
        ..
    } = established;
    let (mut tx, connection) = builder.handshake(io).await?;
    let (error_tx, error_rx) = tokio::sync::oneshot::channel();
    let connection_permit = permit.clone();
    exec.execute(async move {
        // Keep capacity reserved until the physical connection driver exits.
        let _permit = connection_permit;
        if let Err(error) = connection.with_upgrades().await {
            debug!("client connection error: {error:?}");
            let _ = error_tx.send(error);
        }
    });

    match tx.ready().await {
        Ok(()) => drop(error_rx),
        Err(error) if error.is_closed() => match error_rx.await {
            Ok(connection_error) => return Err(connection_error.into()),
            Err(_) => return Err(error.into()),
        },
        Err(error) => return Err(error.into()),
    }

    Ok(Http1Client {
        conn_info: connected,
        tx,
        permit,
        capacity,
        idle_at: clock_now(&timer),
        timer,
    })
}

/// Handshakes an HTTP/2 transport and starts its multiplexed connection driver.
///
/// The sender and driver share the capacity permit so removing the singleton
/// does not free a slot while the physical connection is still shutting down.
async fn establish_http2<T, B>(
    established: Established<T>,
    builder: conn::http2::Builder<Executor>,
    capacity: Option<Capacity>,
    exec: Executor,
    timer: Timer,
) -> Result<Http2Client<B>, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let Established {
        io,
        connected,
        permit,
        ..
    } = established;
    let (mut tx, connection) = builder.handshake(io).await?;
    let connection_permit = permit.clone();
    exec.execute(async move {
        // Keep capacity reserved until the physical connection driver exits.
        let _permit = connection_permit;
        if let Err(_error) = connection.await {
            debug!("client connection error: {_error}");
        }
    });
    tx.ready().await?;

    Ok(Http2Client {
        conn_info: connected,
        tx,
        permit,
        capacity,
        state: Arc::new(Http2State {
            checkouts: AtomicUsize::new(0),
            idle_at: Mutex::new(clock_now(&timer)),
        }),
        timer,
    })
}

impl<B> Pooled<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Wraps a negotiated sender and registers an HTTP/2 checkout when needed.
    fn new(inner: Negotiated<Cached<Http1Client<B>>, H2Pooled<B>>, pool_enabled: bool) -> Self {
        if let Negotiated::Upgraded(service) = &inner {
            service.inner().begin_checkout();
        }
        Self {
            inner,
            pool_enabled,
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
            Negotiated::Fallback(service) => service.inner().permit.is_limited(),
            Negotiated::Upgraded(service) => service.inner().permit.is_limited(),
        }
    }

    /// Returns whether the protocol sender can accept a request immediately.
    pub(super) fn is_ready(&self) -> bool {
        match &self.inner {
            Negotiated::Fallback(service) => service.inner().tx.is_ready(),
            Negotiated::Upgraded(service) => service.inner().tx.is_ready(),
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
                    service.inner().conn_info.poison();
                    service.discard_shared();
                }
                ready
            }
        }
    }

    /// Returns metadata for the underlying physical connection.
    pub(super) fn conn_info(&self) -> &Connected {
        match &self.inner {
            Negotiated::Fallback(service) => &service.inner().conn_info,
            Negotiated::Upgraded(service) => &service.inner().conn_info,
        }
    }

    /// Prevents the checked-out sender from being reused.
    pub(super) fn discard(&mut self) {
        match &mut self.inner {
            Negotiated::Fallback(service) => service.discard_on_drop(),
            Negotiated::Upgraded(service) => {
                service.inner().conn_info.poison();
                service.discard_shared();
            }
        }
    }

    /// Sends a request without waiting for an additional readiness transition.
    #[allow(clippy::result_large_err)]
    pub(super) fn try_send_request(
        &mut self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, ConnTrySendError<Request<B>>>> {
        match &mut self.inner {
            Negotiated::Fallback(service) => {
                Either::Left(service.inner_mut().tx.try_send_request(req))
            }
            Negotiated::Upgraded(service) => {
                Either::Right(service.inner_mut().tx.try_send_request(req))
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
    /// Returns HTTP/1 senders to the cache and ends HTTP/2 checkout tracking.
    fn drop(&mut self) {
        match &mut self.inner {
            Negotiated::Fallback(service) => {
                let has_waiters = service.has_waiters();
                let release = {
                    let client = service.inner_mut();
                    client.mark_idle();
                    !has_waiters && client.should_release_idle()
                };
                if release {
                    service.discard_on_drop();
                }
            }
            Negotiated::Upgraded(service) => {
                let release = {
                    let client = service.inner();
                    client.finish_checkout();
                    client.should_release_idle()
                };
                if release {
                    service.discard_shared();
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
    /// Formats protocol and reuse state without exposing sender internals.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pooled")
            .field("http2", &self.is_http2())
            .field("reused", &self.is_reused())
            .finish()
    }
}

impl<B> Http1Client<B> {
    /// Polls whether the HTTP/1 sender can accept its next request.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        self.tx.poll_ready(cx).map_err(Error::closed)
    }

    /// Records when the exclusive sender becomes idle.
    fn mark_idle(&mut self) {
        self.idle_at = clock_now(&self.timer);
    }

    /// Returns whether the sender is healthy and within its idle timeout.
    fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        !self.conn_info.poisoned() && self.tx.is_ready() && !is_expired(self.idle_at, now, timeout)
    }

    /// Returns whether reclaiming this sender can satisfy a blocked limit.
    fn matches_limit(&self, key: &LimitKey, blocked_by: BlockedBy) -> bool {
        matches!(blocked_by, BlockedBy::Total) || self.permit.matches(key)
    }

    /// Returns whether this idle connection should yield its capacity slot.
    fn should_release_idle(&self) -> bool {
        self.capacity
            .as_ref()
            .is_some_and(|capacity| capacity.should_release_idle(&self.permit))
    }
}

impl<B> Http2Client<B> {
    /// Polls whether the HTTP/2 sender can open another request stream.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        self.tx.poll_ready(cx).map_err(Error::closed)
    }

    /// Registers a checkout of the shared HTTP/2 sender.
    fn begin_checkout(&self) {
        let _ = self
            .state
            .checkouts
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_add(1))
            });
    }

    /// Ends a checkout and records when the shared sender became idle.
    fn finish_checkout(&self) {
        let _ = self
            .state
            .checkouts
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            });
        *self.state.idle_at.lock() = clock_now(&self.timer);
    }

    /// Returns whether no client checkout currently references this sender.
    fn is_idle(&self) -> bool {
        self.state.checkouts.load(Ordering::Acquire) == 0
    }

    /// Returns whether the shared sender is healthy and not expired while idle.
    fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        // TODO(task 9): Replace this checkout-only signal with a stream lease once
        // wreq-proto exposes HTTP/2 stream occupancy.
        !self.conn_info.poisoned()
            && self.tx.is_ready()
            && (!self.is_idle() || !is_expired(*self.state.idle_at.lock(), now, timeout))
    }

    /// Returns whether reclaiming this sender can satisfy a blocked limit.
    fn matches_limit(&self, key: &LimitKey, blocked_by: BlockedBy) -> bool {
        matches!(blocked_by, BlockedBy::Total) || self.permit.matches(key)
    }

    /// Returns whether this idle connection should yield its capacity slot.
    fn should_release_idle(&self) -> bool {
        self.capacity
            .as_ref()
            .is_some_and(|capacity| capacity.should_release_idle(&self.permit))
    }
}

impl EntryUse {
    /// Registers one checkout against a mapped pool entry.
    fn new(uses: Arc<AtomicUsize>) -> Self {
        let _ = uses.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            Some(count.saturating_add(1))
        });
        Self(uses)
    }
}

impl Drop for EntryUse {
    /// Releases this checkout's reference to the mapped pool entry.
    fn drop(&mut self) {
        let _ = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            });
    }
}

/// Chooses HTTP/2 when explicitly requested or negotiated by the transport.
fn should_use_http2<T>(established: &Established<T>) -> bool {
    established.version == Ver::Http2
        || (established.version != Ver::Http1 && established.connected.is_negotiated_h2())
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

/// Error raised when an HTTP/1 handshake future is polled after losing state.
#[derive(Debug)]
struct HandshakeStateError;

impl fmt::Display for HandshakeStateError {
    /// Writes a stable description of the invalid handshake state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("connection handshake state is unavailable")
    }
}

impl std::error::Error for HandshakeStateError {}
