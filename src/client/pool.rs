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
//! 3. Handshake with the entry's builders, which apply the key's protocol options.
//! 4. Transfer cleanup to [`Pooled`] on success; on cancellation, remove the same entry only when
//!    no shared work remains.
//!
//! Locks protect routing and bookkeeping. Sender destruction, user service
//! polling, and task wakeups run after releasing them.

pub(super) mod cache;
mod entry;
pub(super) mod expire;
mod maker;
pub(super) mod map;
#[cfg(feature = "http2")]
pub(super) mod negotiate;
mod pooled;
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) mod singleton;
#[cfg(test)]
mod tests;

use std::{
    num::NonZeroUsize,
    sync::{Arc, Weak, atomic::AtomicUsize},
    time::{Duration, Instant},
};

#[cfg(feature = "http2")]
use netty::http2::Http2Options;
#[cfg(feature = "http3")]
use netty::http3::Http3Options;
use netty::{conn, http1::Http1Options};
use tower::{BoxError, Layer, Service, ServiceBuilder};

pub(super) use self::pooled::Pooled;
use self::{
    cache::{Cache, Started},
    entry::{Entry, EntryState, Http1Entry},
    expire::{Expire, Retain},
    maker::ConnectionMaker,
    map::{Map, Target},
};
#[cfg(any(feature = "http2", feature = "http3"))]
use self::{
    entry::MuxEntry,
    singleton::{Singleton, SingletonError},
};
#[cfg(feature = "http2")]
use self::{
    entry::{EntryUse, NegotiatedEntry},
    negotiate::Negotiate,
};
#[cfg(feature = "http2")]
use super::proto::http2;
#[cfg(feature = "http3")]
use super::proto::http3;
use super::proto::{Established, http1};
use crate::{
    Protocol,
    conn::{
        Conn,
        config::{ConfigSet, ConnectConfig},
        request::{ConnectRequest, ConnectionKey},
    },
    rt::DynRuntime,
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

/// Destination of one pool checkout.
///
/// The request's key fixes the origin and relevant configuration before checkout, and
/// its resolved protocol selects the entry's topology. `wait_for_reuse` is computed by
/// the existing entry, keeping cold starts free of the reuse-first delay.
#[derive(Clone)]
pub(super) struct PoolTarget {
    /// Frozen connection request, moved into the connector by a new connection.
    pub(super) req: ConnectRequest,

    /// Whether this checkout can wait for existing pool state to become reusable.
    wait_for_reuse: bool,
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

    /// Handshake builders with the client's protocol options applied.
    http1: Arc<conn::http1::Builder>,
    #[cfg(feature = "http2")]
    http2: Arc<conn::http2::Builder<DynRuntime>>,
    #[cfg(feature = "http3")]
    http3: Arc<conn::http3::Builder<DynRuntime>>,

    /// Deadline of each HTTP/3 connect and handshake.
    #[cfg(feature = "http3")]
    http3_connect_timeout: Option<Duration>,
}

/// Applies the request's counted `O` override to a copy of the client's builder.
/// Without one, the entry shares the client's builder.
fn configure<B, O>(builder: &Arc<B>, req: &ConnectRequest, apply: fn(B, O) -> B) -> Arc<B>
where
    B: Clone,
    O: ConnectConfig + Clone,
{
    match req.config_override::<O>() {
        Some(options) => Arc::new(apply(B::clone(builder), options.clone())),
        None => builder.clone(),
    }
}

// ===== impl Pool =====

impl<C> Pool<C>
where
    C: TransportConnector,
{
    /// Builds the shared map and protocol-specific entry factory.
    ///
    /// Handshake builders start from the client's `config_set`. Idle maintenance
    /// remains dormant until an entry retains reusable state.
    pub(super) fn new(
        config: Config,
        connector: C,
        runtime: DynRuntime,
        config_set: &ConfigSet,
        set_host: bool,
    ) -> Self {
        let reuse_delay = match config.strategy {
            PoolStrategy::ReuseFirst(duration)
                if config.is_enabled() && duration != Duration::ZERO =>
            {
                Some(duration)
            }
            _ => None,
        };

        let mut http1 = conn::http1::Builder::default();
        if let Some(options) = config_set.get::<Http1Options>() {
            http1 = http1.options(options.clone());
        }
        #[cfg(feature = "http2")]
        let mut http2 = conn::http2::Builder::new(runtime.clone()).timer(runtime.clone());
        #[cfg(feature = "http2")]
        if let Some(options) = config_set.get::<Http2Options>() {
            http2 = http2.options(options.clone());
        }
        #[cfg(feature = "http3")]
        let mut http3 = conn::http3::Builder::new(runtime.clone());
        #[cfg(feature = "http3")]
        if let Some(options) = config_set.get::<Http3Options>() {
            http3 = http3.options(options.clone());
        }

        let inner = Arc::new_cyclic(|pool| {
            let targeter = PoolTargeter {
                connector,
                max_idle_per_host: config.max_idle_per_host,
                reuse_delay,
                pool: pool.clone(),
                runtime: runtime.clone(),
                set_host,
                http1: Arc::new(http1),
                #[cfg(feature = "http2")]
                http2: Arc::new(http2),
                #[cfg(feature = "http3")]
                http3: Arc::new(http3),
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

    /// Checks out a sender compatible with the request's connection key.
    ///
    /// The map lock is released before the returned future is polled. When pooling
    /// is disabled or the checkout is `dedicated`, which always connects and never
    /// returns the sender, the call creates a temporary entry for this request.
    pub(super) async fn checkout(
        &self,
        req: ConnectRequest,
        dedicated: bool,
    ) -> Result<Pooled, BoxError> {
        let target = PoolTarget {
            req,
            wait_for_reuse: false,
        };

        if !self.inner.enabled || dedicated {
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

impl<C> Retain for PoolInner<C>
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
    /// Composes an HTTP/1 cache around protocol handshaking with the entry's builder.
    /// Only the cache's background-completion callback owns an entry-state clone.
    fn http1_layer<S>(
        &self,
        state: &Arc<EntryState>,
        req: &ConnectRequest,
    ) -> impl Layer<S, Service = Cache<http1::Connect<S>, PoolTarget, cache::events::WithRuntime>>
    where
        S: Service<PoolTarget, Response = Established, Error = BoxError> + Clone,
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
            .layer(http1::ConnectLayer::new(
                configure(&self.http1, req, conn::http1::Builder::options),
                self.runtime.clone(),
                self.set_host,
            ))
            .into_inner()
    }

    /// Creates the HTTP/2 handshake layer with the entry's builder.
    #[cfg(feature = "http2")]
    fn http2_layer(&self, req: &ConnectRequest) -> http2::ConnectLayer {
        http2::ConnectLayer::new(
            configure(&self.http2, req, conn::http2::Builder::options),
            self.runtime.clone(),
        )
    }
}

impl<C> Target<PoolTarget> for PoolTargeter<C>
where
    C: TransportConnector,
{
    type Key = ConnectionKey;
    type Service = Box<dyn Entry>;

    fn key(&self, target: &PoolTarget) -> Self::Key {
        target.req.key()
    }

    /// Builds only the pool components required by the target's protocol mode.
    ///
    /// One key fixes the counted HTTP options, so an entry's builders serve all its requests.
    fn service(&self, target: &PoolTarget) -> Self::Service {
        let req = &target.req;
        let pool = self.pool.clone();
        let key = req.key();
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
        match req.resolved_protocol() {
            Protocol::Http1 => {
                let service = self.http1_layer(&state, req).layer(connect);
                Box::new(Http1Entry { service, state })
            }
            // QUIC dials directly, so take the maker's connector instead of cloning again.
            #[cfg(feature = "http3")]
            Protocol::Http3 => Box::new(MuxEntry {
                service: Singleton::new(http3::Connect::new(
                    connect.connector,
                    configure(&self.http3, req, conn::http3::Builder::options),
                    connect.runtime,
                    self.http3_connect_timeout,
                )),
                state,
                #[cfg(test)]
                protocol: Protocol::Http3,
            }),
            #[cfg(feature = "http2")]
            Protocol::Http2 => Box::new(MuxEntry {
                service: ServiceBuilder::new()
                    .layer_fn(Singleton::new)
                    .layer(self.http2_layer(req))
                    .service(connect),
                state,
                #[cfg(test)]
                protocol: Protocol::Http2,
            }),
            #[cfg(not(feature = "http2"))]
            Protocol::Auto => {
                let service = self.http1_layer(&state, req).layer(connect);
                Box::new(Http1Entry { service, state })
            }
            #[cfg(feature = "http2")]
            Protocol::Auto => {
                let inspect: fn(&Established) -> bool =
                    |established| established.connected().is_negotiated_h2();
                let upgrade = ServiceBuilder::new()
                    .layer_fn(Singleton::new)
                    .layer(self.http2_layer(req));
                let service =
                    Negotiate::new(connect, inspect, self.http1_layer(&state, req), upgrade);

                Box::new(NegotiatedEntry { service, state })
            }
        }
    }
}
