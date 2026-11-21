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
use netty::http1::Http1Options;
use tower::{BoxError, Layer, Service, ServiceBuilder, ServiceExt, util::Oneshot};
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
    config::ConnectConfig,
    conn::{Conn, Request, Unnameable},
    protocol::Protocol,
    rt::{DynRuntime, Timer as _},
    sync::{Mutex, MutexGuard},
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

/// Shared connection pool handle keyed by `K`.
///
/// The outer map lock is held only to look up or insert an entry; dialing and handshakes run
/// unlocked. Dropping the last handle stops the idle-cleanup task (checked-out senders hold
/// only weak references to the pool).
pub(super) struct Pool<K, C> {
    /// Shared pool state; dropping the last strong handle stops the expiration watcher.
    inner: Arc<PoolInner<K, C>>,
}

/// Shared pool state and idle expiration coordinator.
///
/// `entries` is the only outer lock; each entry manages its own synchronization so no network
/// I/O runs while `entries` is locked. `expire` holds a weak reference to `self` so idle
/// cleanup stops promptly on drop.
struct PoolInner<K, C> {
    /// Whether checkouts may reuse and return connections (`max_idle_per_host > 0`).
    enabled: bool,
    /// Idle timeout applied during checkout pruning and periodic expiration sweeps.
    idle_timeout: Option<Duration>,
    /// Whether `entries` enforces a retained-group LRU cap (reused hits must refresh LRU).
    has_group_limit: bool,
    /// Single background watcher sweeping expired entries across the whole pool.
    expire: Expire<Self>,
    /// Factory composing the protocol service stack when a new map entry is created.
    targeter: PoolTargeter<C>,
    /// Outer map from reuse key `K` to its type-erased protocol entry.
    entries: Mutex<Map<K, BoxedEntry>>,
}

type BoxedEntry = Box<dyn Entry<Request<ConnectConfig>>>;

/// Owned connection input paired with whether the checkout may wait for reuse.
///
/// Passed into [`StreamMaker`] so dedicated or unpooled checkouts skip any reuse-first delay.
#[derive(Clone)]
pub(super) struct Checkout<T> {
    /// Connection request forwarded to the underlying connector on a dial.
    target: T,
    /// Whether this checkout may wait out a reuse-first delay before dialing.
    wait_for_reuse: bool,
}

/// Factory that builds the protocol service stack for each connection pool group.
///
/// Shares client-wide HTTP handshake builders and runtime handles; unpooled checkouts build
/// a temporary entry without inserting it into the map.
struct PoolTargeter<C> {
    /// Base transport connector cloned once per new map entry.
    connector: C,
    /// Per-entry HTTP/1 idle connection cap passed into [`Cache`].
    max_idle_per_host: usize,
    /// Non-zero reuse-first delay passed into [`StreamMaker`], if enabled.
    reuse_delay: Option<Duration>,
    /// Runtime driving timers, handshakes, and detached background connects.
    runtime: DynRuntime,
    /// Whether HTTP/1 handshakes populate a default `Host` header.
    set_host: bool,
    /// Client-wide default HTTP/1 handshake builder.
    http1: Arc<netty::conn::http1::Builder>,
    /// Client-wide default HTTP/2 handshake builder.
    #[cfg(feature = "http2")]
    http2: Arc<netty::conn::http2::Builder<DynRuntime>>,
    /// Client-wide default HTTP/3 handshake builder.
    #[cfg(feature = "http3")]
    http3: Arc<netty::conn::http3::Builder<DynRuntime>>,
}

/// Connector wrapper that defers dialing until its future is polled.
///
/// Optionally waits out a reuse-first window, then runs a cloned connector through `Oneshot`
/// so readiness and `call` happen on the same service instance.
#[derive(Clone)]
struct StreamMaker<C> {
    /// Underlying connector cloned for each dial attempt.
    connector: C,
    /// Reuse-first delay applied when `Checkout::wait_for_reuse` is set.
    reuse_delay: Option<Duration>,
    /// Runtime providing the delay timer and connection establishment timestamp.
    runtime: DynRuntime,
}

/// Dial future that tracks whether physical connection work has started.
///
/// `started` flips to `true` right before awaiting the connector (after any reuse delay),
/// letting the HTTP/1 cache decide whether a lost race is worth finishing in the background.
struct MakeFuture<T> {
    /// Boxed async dial pipeline (optional delay followed by connector `Oneshot`).
    future: BoxFuture<'static, Result<T, BoxError>>,
    /// Tracks first poll when there is no reuse delay (`started` is `None`).
    polled: bool,
    /// Shared flag set right after the reuse delay finishes and dialing begins.
    started: Option<Arc<AtomicBool>>,
}

// ===== impl Pool =====

impl<K, C> Pool<K, C>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    C: Service<Unnameable, Response = Conn, Error = BoxError, Future: Send + 'static>
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Creates a connection pool using the client's default HTTP options.
    ///
    /// The idle-cleanup task stays dormant until an entry retains idle state.
    #[must_use]
    pub(super) fn new(
        connector: C,
        runtime: DynRuntime,
        pool_config: Config,
        connect_config: &ConnectConfig,
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

        let mut http1 = netty::conn::http1::Builder::default();
        if let Some(options) = connect_config.get_ref::<Http1Options>() {
            http1 = http1.options(options.clone());
        }

        #[cfg(feature = "http2")]
        let http2 = {
            let builder = netty::conn::http2::Builder::new(runtime.clone()).timer(runtime.clone());
            match connect_config.get_ref::<Http2Options>() {
                Some(options) => builder.options(options.clone()),
                None => builder,
            }
        };

        #[cfg(feature = "http3")]
        let http3 = {
            let builder = netty::conn::http3::Builder::new(runtime.clone());
            match connect_config.get_ref::<Http3Options>() {
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
                has_group_limit: pool_config.max_size.is_some(),
                expire: Expire::new(pool.clone(), runtime),
                entries: Mutex::new(Map::new(pool_config.max_size)),
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
            return self
                .inner
                .new_entry(None, request)
                .checkout(request, false)
                .await;
        };

        // The guard needs a lexical scope outside await for this future to remain Send.
        let future = {
            let now = self.inner.now();
            let mut entries = self.inner.entries.lock();
            // Prune only this group on checkout. A global retained-group scan
            // would add O(group count) work and nested locking to every pool hit.
            let entry =
                entries.get_or_insert_with(key, || self.inner.new_entry(Some(key), request));
            let discarded = entry.prune(now, self.inner.idle_timeout);
            let future = entry.checkout(request, true);
            drop(entries);
            drop(discarded);
            future
        };

        future.await
    }

    /// Checks out an established HTTP/2 or HTTP/3 sender whose peer enabled extended CONNECT.
    ///
    /// Probes completed senders only. A miss leaves pool entries intact.
    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    #[must_use]
    pub(super) fn checkout_extended_connect(&self, key: &K) -> Option<Pooled> {
        if !self.inner.enabled {
            return None;
        }
        let (service, state) = self.inner.entries.lock().get_mut(key)?.checkout_made()?;
        // Pooled::new_mux runs map maintenance, so it must stay outside the map lock.
        let connection = service.inner();
        let usable = connection.extended_connect() == Some(true)
            && connection.is_reusable(self.inner.now(), self.inner.idle_timeout);
        usable.then(|| Pooled::new_mux(service, true, EntryUse::new(state)))
    }
}

impl<K, C> Clone for Pool<K, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
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

// ===== impl PoolInner =====

impl<K, C> PoolInner<K, C>
where
    K: Eq + Hash + Clone + Send + 'static,
    C: Send + Sync + 'static,
{
    /// Builds an entry for `request`, binding it to the pool only when given a `key`.
    #[must_use]
    fn new_entry(self: &Arc<Self>, key: Option<&K>, request: &Request<ConnectConfig>) -> BoxedEntry
    where
        K: Sync,
        C: Service<Unnameable, Response = Conn, Error = BoxError> + Clone,
        C::Future: Send + 'static,
    {
        let state = Arc::new(EntryState {
            uses: AtomicUsize::new(0),
            #[cfg(any(feature = "http2", feature = "http3"))]
            track_on_idle: AtomicBool::new(false),
            maintain: match key {
                Some(key) => {
                    let pool = Arc::downgrade(self);
                    let key = key.clone();
                    Box::new(move |state, reused| {
                        let Some(pool) = pool.upgrade() else {
                            return;
                        };
                        // LRU reconciliation and starting a stopped watcher still need the map.
                        if !reused
                            || pool.has_group_limit
                            || (pool.expiration_interval(true).is_some()
                                && !pool.expire.is_running())
                        {
                            pool.update_entry(&key, state);
                        }
                    })
                }
                None => Box::new(|_, _| {}),
            },
        });
        self.targeter.service(request, state)
    }

    /// Reads the configured runtime clock.
    #[must_use]
    fn now(&self) -> Instant {
        self.expire.now()
    }

    /// Returns the proactive idle-check interval when retained state exists.
    #[must_use]
    fn expiration_interval(&self, has_retained: bool) -> Option<Duration> {
        self.idle_timeout
            .filter(|timeout| self.enabled && has_retained && *timeout != Duration::ZERO)
            .map(|timeout| timeout.max(Duration::from_millis(90)))
    }

    /// Mutates `entries` under the lock, then drops `detached` after releasing it.
    ///
    /// The field order of `detached` controls the drop order.
    fn with_entries<R, D>(
        guard: MutexGuard<'_, Map<K, BoxedEntry>>,
        mut detached: D,
        clean: impl FnOnce(&mut Map<K, BoxedEntry>, &mut D) -> R,
    ) -> R {
        let result = {
            let mut guard = guard;
            clean(&mut guard, &mut detached)
        };
        drop(detached);
        result
    }

    /// Removes an empty entry or reconciles its idle-group capacity tracking.
    fn update_entry(self: &Arc<Self>, key: &K, state: &Arc<EntryState>) {
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
        let (pruned, evicted) = entries.mark_retained(key, |entry| entry.prepare_eviction());
        // A later checkout may restore the record before the final release.
        #[cfg(any(feature = "http2", feature = "http3"))]
        if state.track_on_idle.load(Ordering::Relaxed) {
            state.track_on_idle.store(false, Ordering::Relaxed);
        }

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

        self.expire.schedule(self.expiration_interval(true));
    }
}

impl<K, C> Retain for PoolInner<K, C>
where
    K: Eq + Hash + Clone + Send + 'static,
    C: Send + Sync + 'static,
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
                entries.prune_retained(|entry| entry.has_retained());
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

impl<C> PoolTargeter<C> {
    /// Wraps the HTTP/1 handshake layer in an idle connection cache.
    fn http1_pool<'layer, S>(
        &'layer self,
        state: &'layer Arc<EntryState>,
        config: &'layer ConnectConfig,
    ) -> impl Layer<
        S,
        Service = Cache<
            http1::Connect<S>,
            Checkout<Request<ConnectConfig>>,
            cache::events::WithRuntime,
        >,
    > + use<'layer, C, S>
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
                    .on_background_complete(move || (state.maintain)(&state, false))
                    .max_idle(self.max_idle_per_host)
                    .build(service)
            })
            .layer(self.http1_layer(config))
            .into_inner()
    }

    /// Creates the HTTP/1 handshake layer.
    #[must_use]
    fn http1_layer<'layer>(
        &'layer self,
        config: &'layer ConnectConfig,
    ) -> http1::ConnectLayer<'layer> {
        let options = config.override_if_different(PartialEq::eq).map(Arc::as_ref);
        http1::ConnectLayer::new(&self.runtime, &self.http1, options, self.set_host)
    }

    /// Creates the HTTP/2 handshake layer.
    #[must_use]
    #[cfg(feature = "http2")]
    fn http2_layer<'layer>(
        &'layer self,
        config: &'layer ConnectConfig,
    ) -> http2::ConnectLayer<'layer> {
        let options = config.override_if_different(PartialEq::eq).map(Arc::as_ref);
        http2::ConnectLayer::new(&self.runtime, &self.http2, options)
    }

    /// Creates the HTTP/3 handshake layer.
    #[must_use]
    #[cfg(feature = "http3")]
    fn http3_layer<'layer>(
        &'layer self,
        config: &'layer ConnectConfig,
    ) -> http3::ConnectLayer<'layer> {
        let options = config.override_if_different(PartialEq::eq).map(Arc::as_ref);
        http3::ConnectLayer::new(&self.runtime, &self.http3, options)
    }

    /// Builds the entry service stack for `request`'s protocol mode and HTTP option overrides.
    #[must_use]
    fn service(&self, request: &Request<ConnectConfig>, state: Arc<EntryState>) -> BoxedEntry
    where
        C: Service<Unnameable, Response = Conn, Error = BoxError> + Clone + Send + 'static,
        C::Future: Send + 'static,
    {
        let connector = || self.connector.clone().map_request(Unnameable::from);
        let connect = || StreamMaker {
            runtime: self.runtime.clone(),
            connector: connector(),
            reuse_delay: self.reuse_delay,
        };
        let config = request.body();

        // Fixed protocol modes use smaller service graphs; only Auto needs both
        // pools and negotiation: https://github.com/hyperium/hyper/issues/3948
        match request.protocol() {
            Protocol::Http1 => {
                let service = self.http1_pool(&state, config).layer(connect());
                Box::new(Http1Entry { service, state })
            }
            #[cfg(feature = "http2")]
            Protocol::Http2 => Box::new(MuxEntry {
                service: ServiceBuilder::new()
                    .layer_fn(Singleton::new)
                    .layer(self.http2_layer(config))
                    .service(connect()),
                state,
            }),
            #[cfg(feature = "http3")]
            Protocol::Http3 => Box::new(MuxEntry {
                service: ServiceBuilder::new()
                    .layer_fn(Singleton::new)
                    .layer(self.http3_layer(config))
                    .service(connector()),
                state,
            }),
            Protocol::Auto => cfg_select! {
                feature = "http2" => Box::new({
                    let inspect: fn(&Established) -> bool =
                        |established| established.connected().is_negotiated_h2();
                    let upgrade = ServiceBuilder::new()
                        .layer_fn(Singleton::new)
                        .layer(self.http2_layer(config));
                    let service = Negotiate::new(
                        connect(),
                        inspect,
                        self.http1_pool(&state, config),
                        upgrade,
                    );

                    NegotiatedEntry { service, state }
                }),
                _ => Box::new({
                    let service = self.http1_pool(&state, config).layer(connect());
                    Http1Entry { service, state }
                }),
            },
        }
    }
}

// ===== impl StreamMaker =====

impl<C, T> Service<Checkout<T>> for StreamMaker<C>
where
    C: Service<Checkout<T>, Response = Conn, Error = BoxError, Future: Send + 'static>
        + Clone
        + Send
        + 'static,
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
            } = Oneshot::new(connector, checkout).await?;

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
