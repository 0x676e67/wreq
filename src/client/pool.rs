//! Composable client connection pooling, adapted from [hyper-util].
//! Connections are isolated by configuration and managed by acquisition and idle policies.
//!
//! [hyper-util]: https://github.com/hyperium/hyper-util/blob/master/src/client/pool/mod.rs
//!
//! [`Map`] groups connections by [`PoolKey`], including request-local
//! configuration and an optional [`crate::Group`] partition. Fixed modes use
//! an HTTP/1 [`Cache`] or an HTTP/2 or HTTP/3 [`Singleton`]. Auto negotiates
//! between HTTP/1 and HTTP/2 through [`Negotiate`].
//!
//! HTTP/1 senders are exclusive and return only when ready. HTTP/2 and HTTP/3
//! senders are shared; checkout accounting ends at response headers, while streams netty
//! reports live keep the connection out of idle expiry and eviction.
//!
//! # Checkout flow
//!
//! 1. Find or create the entry for the connection key.
//! 2. Check the fixed protocol pool, or try HTTP/2 then HTTP/1 reuse in Auto mode before allowing a
//!    new connection.
//! 3. Handshake with the entry's builders, which apply the key's protocol options.
//! 4. Transfer cleanup to [`Pooled`] on success; on cancellation, remove the same entry only when
//!    no shared work remains.
//!
//! Locks protect routing and bookkeeping. Sender destruction, user service
//! polling, and task wakeups run after releasing them.

mod entry;
#[cfg(test)]
mod tests;

pub(super) mod cache;
pub(super) mod expire;
pub(super) mod map;
#[cfg(feature = "http2")]
pub(super) mod negotiate;
pub(super) mod pooled;
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) mod singleton;

use std::{
    future::Future,
    hash::{BuildHasher, Hash, Hasher},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures_util::future::BoxFuture;
use http::{Request, Uri};
use lru::DefaultHasher;
use netty::{conn, http1::Http1Options};
use tower::{BoxError, Layer, Service, ServiceBuilder, util::Oneshot};
#[cfg(feature = "http2")]
use {
    self::{entry::NegotiatedEntry, negotiate::Negotiate},
    super::proto::http2,
    netty::http2::Http2Options,
};
#[cfg(feature = "http3")]
use {super::proto::http3, netty::http3::Http3Options};

#[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
use self::entry::EntryUse;
use self::{
    cache::{Cache, Started},
    entry::{Entry, EntryState, Http1Entry},
    expire::{Expire, Retain},
    map::Map,
    pooled::Pooled,
};
#[cfg(any(feature = "http2", feature = "http3"))]
use self::{
    entry::MuxEntry,
    singleton::{Singleton, SingletonError},
};
use super::proto::{Established, http1};
use crate::{
    config::connect::ConnectConfig,
    conn::{Conn, ConnectRequestExt, options::Options},
    protocol::Protocol,
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
/// same idle policy and acquisition strategy.
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
}

// ===== impl Config =====

impl Config {
    /// Returns whether mapped pooling and sender retention are enabled.
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
    services: Mutex<Map<PoolKey<PoolTarget>, Box<dyn Entry<PoolTarget>>>>,
}

/// Compatibility key for pool entries and extended CONNECT lookups.
#[derive(Clone, Debug)]
pub(super) struct PoolKey<K> {
    key: K,
    hash: u64,
}

/// Origin and normalized options shared by pool lookup and connection setup.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct PoolTarget {
    pub(super) origin: Uri,
    pub(super) protocol: Protocol,
    pub(super) options: Options,
}

/// A checkout's owned connection input and reuse policy.
#[derive(Clone)]
pub(super) struct Checkout<T> {
    pub(super) target: T,
    /// Whether this checkout can wait for existing pool state to become reusable.
    wait_for_reuse: bool,
}

/// Factory that creates one protocol-specific service graph per destination group.
///
/// Fixed protocols receive their matching pool. Auto combines HTTP/1 and HTTP/2
/// through [`Negotiate`], and unpooled checkouts create a temporary entry.
/// Entries hold only a weak reference to [`PoolInner`].
struct PoolTargeter<C> {
    /// Physical connection service.
    connector: C,

    /// HTTP/1 idle capacity configured for each entry.
    max_idle_per_host: usize,

    /// Optional delay before a cache miss starts connecting.
    reuse_delay: Option<Duration>,

    /// Runtime used by cache races and protocol drivers.
    runtime: DynRuntime,

    /// Whether HTTP/1 should generate a missing `Host` field.
    set_host: bool,

    http1: Arc<conn::http1::Builder>,
    #[cfg(feature = "http2")]
    http2: Arc<conn::http2::Builder<DynRuntime>>,
    #[cfg(feature = "http3")]
    http3: Arc<conn::http3::Builder<DynRuntime>>,
}

/// Lazily creates physical connections under the configured reuse policy.
///
/// The maker defers every expensive step until its future is polled. It may wait
/// for a reuse-first window, then runs a cloned connector through `Oneshot` so
/// readiness and `call` use the same service instance.
#[derive(Clone)]
struct ConnectionMaker<C> {
    /// Clock shared by reuse waits and transport timestamps.
    runtime: DynRuntime,

    /// Physical transport connector.
    connector: C,

    /// Optional delay giving connection reuse time to win.
    reuse_delay: Option<Duration>,
}

/// Connection-maker future with explicit started-work tracking.
///
/// `polled` distinguishes a never-started checkout from one that has entered
/// policy work. When `started` is present, it becomes true immediately before
/// the physical connector is awaited. The HTTP/1 cache uses this distinction to
/// decide whether a lost reuse race is worth completing in the background.
struct MakeFuture<T> {
    /// Deferred delay and physical connect work.
    future: BoxFuture<'static, Result<T, BoxError>>,

    /// Records whether the future has ever been polled.
    polled: bool,

    /// Separates waiting for policy from useful connection work.
    started: Option<Arc<AtomicBool>>,
}

// ===== impl Pool =====

impl<C> Pool<C>
where
    C: Service<Request<ConnectConfig>, Response = Conn, Error = BoxError, Future: Send + 'static>
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Builds the shared map and protocol-specific entry factory.
    ///
    /// Handshake builders start from the client's connection settings. Idle maintenance
    /// remains dormant until an entry retains reusable state.
    #[must_use]
    pub(super) fn new(
        connector: C,
        runtime: DynRuntime,
        pool_config: Config,
        config: &ConnectConfig,
        set_host: bool,
    ) -> Self {
        let reuse_delay = match pool_config.strategy {
            PoolStrategy::ReuseFirst(duration)
                if pool_config.is_enabled() && duration != Duration::ZERO =>
            {
                Some(duration)
            }
            _ => None,
        };

        let mut http1 = conn::http1::Builder::default();
        if let Some(options) = config.get_ref::<Http1Options>() {
            http1 = http1.options(options.clone());
        }

        #[cfg(feature = "http2")]
        let http2 = {
            let builder = conn::http2::Builder::new(runtime.clone()).timer(runtime.clone());
            match config.get_ref::<Http2Options>() {
                Some(options) => builder.options(options.clone()),
                None => builder,
            }
        };

        #[cfg(feature = "http3")]
        let http3 = {
            let builder = conn::http3::Builder::new(runtime.clone());
            match config.get_ref::<Http3Options>() {
                Some(options) => builder.options(options.clone()),
                None => builder,
            }
        };

        let inner = Arc::new_cyclic(|pool| {
            let targeter = PoolTargeter {
                connector,
                max_idle_per_host: pool_config.max_idle_per_host,
                reuse_delay,
                runtime: runtime.clone(),
                set_host,
                http1: Arc::new(http1),
                #[cfg(feature = "http2")]
                http2: Arc::new(http2),
                #[cfg(feature = "http3")]
                http3: Arc::new(http3),
            };

            PoolInner {
                enabled: pool_config.is_enabled(),
                idle_timeout: pool_config.idle_timeout,
                expire: Expire::new(pool.clone(), runtime),
                services: Mutex::new(Map::new(pool_config.max_size)),
                targeter,
            }
        });

        Self { inner }
    }

    /// Checks out a sender for the request's origin and connection identity.
    ///
    /// The map lock is released before the returned future is polled. When pooling
    /// is disabled or the checkout is `dedicated`, which always connects and never
    /// returns the sender, the call creates a temporary entry for this request.
    pub(super) async fn checkout(
        &self,
        key: &PoolKey<PoolTarget>,
        dedicated: bool,
    ) -> Result<Pooled, BoxError> {
        if !self.inner.enabled || dedicated {
            return self
                .inner
                .new_entry(key)
                .checkout(key.as_ref(), false)
                .await;
        }

        // The guard needs a lexical scope outside await for this future to remain Send.
        let future = {
            let now = self.inner.now();
            let mut services = self.inner.services.lock();
            // Inspect only this group on checkout. A global retained-group scan
            // would add O(group count) work and nested locking to every pool hit.
            let service = services.get_or_insert_with(key, || self.inner.new_entry(key));
            let discarded = service.retain(now, self.inner.idle_timeout);
            let future = service.checkout(key.as_ref(), true);
            drop(services);
            drop(discarded);
            future
        };

        future.await
    }

    /// Checks out an established HTTP/2 or HTTP/3 sender whose peer enabled extended CONNECT.
    ///
    /// Never creates entries or connections, joins pending handshakes, or touches
    /// HTTP/1 state, so a miss costs one map lookup.
    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    #[must_use]
    pub(super) fn checkout_extended_connect(&self, key: &PoolKey<PoolTarget>) -> Option<Pooled> {
        if !self.inner.enabled {
            return None;
        }
        let (service, state) = self.inner.services.lock().get_mut(key)?.checkout_made()?;
        // Pooled::new runs map maintenance, so it must stay outside the map lock.
        let connection = service.inner();
        let usable = connection.extended_connect() == Some(true)
            && connection.is_reusable(self.inner.now(), self.inner.idle_timeout);
        usable.then(|| Pooled::new_mux(service, true, EntryUse::new(state)))
    }
}

impl<C> Clone for Pool<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

// ===== impl PoolKey =====

impl<K> PoolKey<K> {
    /// Builds a pool key and precomputes its lookup hash.
    #[must_use]
    pub(super) fn new(key: K) -> Self
    where
        K: Eq + Hash,
    {
        static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);
        let hash = HASHER.hash_one(&key);
        Self { key, hash }
    }
}

impl<K> AsRef<K> for PoolKey<K> {
    #[inline]
    fn as_ref(&self) -> &K {
        &self.key
    }
}

impl<K: Eq> PartialEq for PoolKey<K> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.key == other.key
    }
}

impl<K: Eq> Eq for PoolKey<K> {}

impl<K> Hash for PoolKey<K> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

// ===== impl PoolTarget =====

impl From<PoolTarget> for Request<ConnectConfig> {
    fn from(target: PoolTarget) -> Self {
        Request::new_connect(target.origin, target.protocol, target.options.into_config())
    }
}

// ===== impl Checkout =====

impl<T: Clone> Checkout<T> {
    #[must_use]
    fn new(target: &T, wait_for_reuse: bool) -> Self {
        Self {
            target: target.clone(),
            wait_for_reuse,
        }
    }
}

// ===== impl PoolInner =====

impl<C> PoolInner<C>
where
    C: Send + Sync + 'static,
{
    /// Assembles an entry and binds its cleanup to the key and entry identity.
    fn new_entry(self: &Arc<Self>, key: &PoolKey<PoolTarget>) -> Box<dyn Entry<PoolTarget>>
    where
        C: Service<
                Request<ConnectConfig>,
                Response = Conn,
                Error = BoxError,
                Future: Send + 'static,
            > + Clone,
    {
        let pool = Arc::downgrade(self);
        let entry_key = key.clone();
        let state = Arc::new(EntryState {
            uses: AtomicUsize::new(0),
            maintain: Box::new(move |identity| {
                if let Some(pool) = pool.upgrade() {
                    pool.maintain_entry(&entry_key, identity);
                }
            }),
        });
        self.targeter.service(key.as_ref(), state)
    }

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
    fn maintain_entry(self: &Arc<Self>, key: &PoolKey<PoolTarget>, identity: &Arc<EntryState>) {
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
                let (pruned, evicted) = services.mark_retained(key, |entry| entry.is_evictable());
                // Pruned groups lost reusable state between sweeps, such as a closed QUIC
                // connection, or are in use and so not evicted, as HTTP/1 evicts only idle
                // senders. Idle sweeps may be disabled, so clean them up here; groups in use
                // are marked again on their next checkout.
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

impl<C> Retain for PoolInner<C>
where
    C: Send + Sync + 'static,
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
    /// Composes an HTTP/1 cache around protocol handshaking with the entry's builder.
    /// Only the cache's background-completion callback owns an entry-state clone.
    fn http1_pool<'layer, S>(
        &'layer self,
        state: &'layer Arc<EntryState>,
        options: &'layer Options,
    ) -> impl Layer<
        S,
        Service = Cache<http1::Connect<S>, Checkout<PoolTarget>, cache::events::WithRuntime>,
    > + use<'layer, C, S>
    where
        S: Service<Checkout<PoolTarget>, Response = Established, Error = BoxError> + Clone,
        S::Future: Started + Unpin,
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
            .layer(self.http1_layer(options))
            .into_inner()
    }

    /// Creates the HTTP/1 handshake layer.
    #[must_use]
    fn http1_layer<'layer>(&'layer self, options: &'layer Options) -> http1::ConnectLayer<'layer> {
        http1::ConnectLayer::new(
            &self.http1,
            options.http1.as_deref(),
            &self.runtime,
            self.set_host,
        )
    }

    /// Creates the HTTP/2 handshake layer.
    #[must_use]
    #[cfg(feature = "http2")]
    fn http2_layer<'layer>(&'layer self, options: &'layer Options) -> http2::ConnectLayer<'layer> {
        http2::ConnectLayer::new(&self.http2, options.http2.as_deref(), &self.runtime)
    }

    /// Creates the HTTP/3 handshake layer.
    #[must_use]
    #[cfg(feature = "http3")]
    fn http3_layer<'layer>(&'layer self, options: &'layer Options) -> http3::ConnectLayer<'layer> {
        http3::ConnectLayer::new(&self.http3, options.http3.as_deref(), &self.runtime)
    }

    /// Builds only the pool components required by the target's protocol mode.
    ///
    /// A pool entry's builders use the effective HTTP options of that protocol.
    fn service(&self, target: &PoolTarget, state: Arc<EntryState>) -> Box<dyn Entry<PoolTarget>>
    where
        C: Service<
                Request<ConnectConfig>,
                Response = Conn,
                Error = BoxError,
                Future: Send + 'static,
            > + Clone
            + Send
            + 'static,
    {
        let (protocol, options) = (target.protocol, &target.options);
        let connect = || ConnectionMaker {
            runtime: self.runtime.clone(),
            connector: self.connector.clone(),
            reuse_delay: self.reuse_delay,
        };

        // Fixed protocol modes use smaller service graphs; only Auto needs both
        // pools and negotiation: https://github.com/hyperium/hyper/issues/3948
        match protocol {
            Protocol::Http1 => {
                let service = self.http1_pool(&state, options).layer(connect());
                Box::new(Http1Entry { service, state })
            }
            #[cfg(feature = "http3")]
            Protocol::Http3 => Box::new(MuxEntry {
                service: ServiceBuilder::new()
                    .layer_fn(Singleton::new)
                    .layer(self.http3_layer(options))
                    .service(self.connector.clone()),
                state,
            }),
            #[cfg(feature = "http2")]
            Protocol::Http2 => Box::new(MuxEntry {
                service: ServiceBuilder::new()
                    .layer_fn(Singleton::new)
                    .layer(self.http2_layer(options))
                    .service(connect()),
                state,
            }),
            Protocol::Auto => cfg_select! {
                feature = "http2" => Box::new({
                    let inspect: fn(&Established) -> bool =
                        |established| established.connected().is_negotiated_h2();

                    let upgrade = ServiceBuilder::new()
                        .layer_fn(Singleton::new)
                        .layer(self.http2_layer(options));

                    let service = Negotiate::new(
                        connect(),
                        inspect,
                        self.http1_pool(&state, options),
                        upgrade,
                    );

                    NegotiatedEntry { service, state }
                }),
                _ => Box::new({
                    let service = self.http1_pool(&state, options).layer(connect());
                    Http1Entry { service, state }
                }),
            },
        }
    }
}

// ===== impl ConnectionMaker =====

impl<C> Service<Checkout<PoolTarget>> for ConnectionMaker<C>
where
    C: Service<Request<ConnectConfig>, Response = Conn, Error = BoxError, Future: Send + 'static>
        + Clone
        + Send
        + 'static,
{
    type Response = Established;
    type Error = BoxError;
    type Future = MakeFuture<Self::Response>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, checkout: Checkout<PoolTarget>) -> Self::Future {
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
        let runtime = self.runtime.clone();

        let future = Box::pin(async move {
            if let Some(duration) = reuse_delay {
                runtime.sleep(duration).await;
            }
            if let Some(started) = &start_signal {
                started.store(true, Ordering::Release);
            }

            let Conn {
                transport,
                connected,
            } = Oneshot::new(connector, checkout.target.into()).await?;

            Ok(Established::new(
                transport.into_stream()?,
                connected,
                #[cfg(feature = "http2")]
                runtime.now(),
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
