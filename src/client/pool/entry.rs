//! Mapped pool entries and their checkout accounting.
//!
//! [`Entry`] erases the protocol service stacks in the pool map. [`EntryUse`] and
//! [`EntryCleanupGuard`] remove an empty entry by identity once its last checkout
//! fails or discards the sender.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures_util::future::BoxFuture;
use tower::{BoxError, Service, util::Oneshot};
#[cfg(feature = "http2")]
use {
    super::negotiate::{Negotiate, Negotiated},
    crate::client::proto::{Established, is_expired},
    std::collections::VecDeque,
};
#[cfg(any(feature = "http2", feature = "http3"))]
use {
    super::singleton::{Singled, Singleton, SingletonFuture},
    crate::client::proto::mux,
    std::sync::atomic::AtomicBool,
};

use super::{
    Checkout,
    cache::{self, BackgroundConnect, Cache, Cached},
    pooled::Pooled,
};
use crate::client::proto::http1;

/// Checkout and maintenance interface shared by the protocol service stacks.
pub(super) trait Entry<T>: Send {
    /// Selects a checkout, cloning `target` only if the chosen path needs it.
    ///
    /// Poll or drop the returned future after releasing the map lock.
    fn checkout(&mut self, target: &T, pool_enabled: bool) -> CheckoutFuture;

    /// Clones an established shared sender without creating, joining, or draining work.
    ///
    /// Returns `None` for HTTP/1 entries or generations still being established.
    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    fn checkout_made(&self) -> Option<(MuxSingled, Arc<EntryState>)>;

    /// Prunes stale state and returns it for drop after unlocking.
    ///
    /// Pending or active multiplexed checkouts defer idle expiry.
    fn prune(&mut self, now: Instant, timeout: Option<Duration>) -> Option<Discarded>;

    /// Returns whether the entry holds connection state for reuse.
    fn has_retained(&self) -> bool;

    /// Returns whether the entry can stay tracked as an eviction candidate.
    ///
    /// Multiplexed entries with active checkouts return `false` so LRU eviction skips them,
    /// setting `track_on_idle` so [`Pooled`] re-registers the entry once its last checkout ends.
    fn prepare_eviction(&self) -> bool {
        self.has_retained()
    }

    /// Detaches reusable state to enforce pool capacity.
    ///
    /// Drop the returned state after releasing the map lock.
    fn evict(&mut self) -> Option<Discarded>;

    /// Returns whether this entry holds the given state instance.
    fn has_state(&self, state: &Arc<EntryState>) -> bool;

    /// Returns whether the entry has no active, pending, or idle work.
    fn is_empty(&self) -> bool;
}

/// Fixed HTTP/1 pool entry.
///
/// Hands out exclusive senders from an HTTP/1 cache, returning healthy senders on drop
/// while `state` tracks active checkouts and guards empty-entry cleanup.
pub(super) struct Http1Entry<S> {
    /// Exclusive HTTP/1 sender cache.
    pub(super) service: S,
    /// Active checkout count and identity-checked cleanup state.
    pub(super) state: Arc<EntryState>,
}

/// Fixed HTTP/2 or HTTP/3 pool entry backed by a shared singleton.
///
/// Concurrent checkouts join a single connection generation and clone its sender once
/// established; `state` tracks pending checkouts and identifies this entry during cleanup.
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) struct MuxEntry<S> {
    /// Shared multiplexed sender singleton.
    pub(super) service: S,
    /// Active checkout count and identity-checked cleanup state.
    pub(super) state: Arc<EntryState>,
}

/// Pool entry that chooses HTTP/1 or HTTP/2 after transport negotiation.
///
/// Combines an HTTP/1 fallback cache with an HTTP/2 upgrade singleton, while `state`
/// tracks active checkouts and guards empty-entry cleanup by identity.
#[cfg(feature = "http2")]
pub(super) struct NegotiatedEntry<L, R, S> {
    /// Composed HTTP/1 fallback and HTTP/2 upgrade pools.
    pub(super) service: Negotiate<L, R, S>,
    /// Active checkout count and identity-checked cleanup state.
    pub(super) state: Arc<EntryState>,
}

/// HTTP/1 cache maintenance used by entries without naming the maker type.
trait Http1Cache<R>:
    Service<R, Response = Cached<http1::Connection>, Error = BoxError> + Clone + Send + 'static
{
    /// Removes closed or expired idle HTTP/1 senders.
    #[must_use]
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) -> Vec<http1::Connection>;

    /// Removes all unreserved idle HTTP/1 senders.
    #[must_use]
    fn drain_idle(&mut self) -> Vec<http1::Connection>;

    /// Returns whether at least one unreserved idle HTTP/1 sender exists.
    #[must_use]
    fn has_idle(&self) -> bool;

    /// Returns whether the HTTP/1 cache owns no services.
    #[must_use]
    fn is_empty(&self) -> bool;
}

/// Handshake future for an HTTP/2 or HTTP/3 connection.
#[cfg(any(feature = "http2", feature = "http3"))]
type MuxMake = BoxFuture<'static, Result<mux::Connection, BoxError>>;

/// Future joining an existing singleton generation.
#[cfg(any(feature = "http2", feature = "http3"))]
type MuxCheckout = SingletonFuture<MuxMake, mux::Connection>;

/// Shared sender clone checked out from a singleton.
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) type MuxSingled = Singled<MuxMake, mux::Connection>;

/// Deferred checkout future polled after the pool map lock is released.
///
/// Existing HTTP/2 and HTTP/3 generations avoid an extra box by holding their singleton
/// future directly, while cold dials and HTTP/1 races stay boxed. In both cases the entry
/// stays active until ownership transfers to [`Pooled`].
pub(super) enum CheckoutFuture {
    /// Unboxed checkout joining an existing multiplexed generation.
    #[cfg(any(feature = "http2", feature = "http3"))]
    Mux {
        /// Singleton checkout future for the active or completed generation.
        future: MuxCheckout,
        /// Redundant negotiated transports dropped on first poll or drop.
        #[cfg(feature = "http2")]
        discarded: VecDeque<Established>,
        /// Dropped after `future` so cleanup observes the final singleton state.
        usage: Option<EntryUse>,
        /// Whether the checked-out sender participates in pool retention.
        pool_enabled: bool,
    },
    /// Boxed checkout for a cache race, cold dial, or protocol negotiation.
    Service(BoxFuture<'static, Result<Pooled, BoxError>>),
}

/// Connection state detached from an entry for drop after the map lock is released.
pub(super) enum Discarded {
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

/// Identity-aware maintenance callback for a map entry.
///
/// Reused checkouts may skip the map update when neither LRU reconciliation nor
/// starting the expiration watcher is needed.
type EntryMaintenance = Box<dyn Fn(&Arc<EntryState>, bool) + Send + Sync>;

/// RAII guard keeping a map entry alive while a checkout is in flight.
///
/// Successful checkouts transfer ownership to [`EntryCleanupGuard`], disarming failure
/// cleanup while decrementing the active count. On failure or cancellation, the last
/// guard invokes entry maintenance to remove the entry if it is still the same instance.
pub(super) struct EntryUse {
    /// Shared identity and checkout counter of the map entry.
    state: Option<Arc<EntryState>>,
    /// Triggers empty-entry cleanup on failure or cancellation when still armed.
    armed: bool,
}

/// Deferred entry maintenance guard owned by a checked-out [`Pooled`] sender.
///
/// Dropped after the underlying sender so maintenance sees the updated cache or
/// singleton state when discarding a connection or resuming capacity tracking.
pub(super) struct EntryCleanupGuard {
    /// Entry identity and maintenance callback handed off from [`EntryUse`].
    state: Option<Arc<EntryState>>,
    /// Runs entry maintenance on drop when armed.
    armed: bool,
}

/// Shared checkout count and identity-aware cleanup callback for a map entry.
///
/// The callback owns the map key and a weak pool reference once per entry instead of
/// cloning both per request, and compares `Arc` identity before removal so a stale
/// checkout cannot delete a newer entry inserted under the same key after LRU eviction.
pub(super) struct EntryState {
    /// Number of checkout futures keeping the entry active.
    pub(super) uses: AtomicUsize,
    /// Whether to track the entry again when the last checkout returns.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) track_on_idle: AtomicBool,
    /// Reconciles this exact entry with cleanup and idle-group limits.
    pub(super) maintain: EntryMaintenance,
}

// ===== impl Discarded =====

impl Discarded {
    /// Returns a batch when the HTTP/1 cache detached at least one sender.
    fn http1(senders: Vec<http1::Connection>) -> Option<Self> {
        (!senders.is_empty()).then_some(Self::Http1 { _senders: senders })
    }

    /// Groups resources detached from either side of negotiation into one batch.
    #[cfg(feature = "http2")]
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

// ===== impl Http1Entry =====

impl<L, T> Entry<T> for Http1Entry<L>
where
    T: Clone + Send + 'static,
    L: Http1Cache<Checkout<T>>,
    L::Future: Send,
{
    fn checkout(&mut self, target: &T, pool_enabled: bool) -> CheckoutFuture {
        // Only enable reuse-first delay when existing work may yield a sender.
        let checkout = Checkout::new(target.clone(), pool_enabled && !Entry::<T>::is_empty(self));
        let service = self.service.clone();
        let usage = EntryUse::new(self.state.clone());
        CheckoutFuture::Service(Box::pin(async move {
            Oneshot::new(service, checkout)
                .await
                .map(|service| Pooled::new_http1(service, pool_enabled, usage))
        }))
    }

    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    fn checkout_made(&self) -> Option<(MuxSingled, Arc<EntryState>)> {
        None
    }

    fn prune(&mut self, now: Instant, timeout: Option<Duration>) -> Option<Discarded> {
        Discarded::http1(self.service.retain_idle(now, timeout))
    }

    fn has_retained(&self) -> bool {
        self.service.has_idle()
    }

    fn evict(&mut self) -> Option<Discarded> {
        Discarded::http1(self.service.drain_idle())
    }

    fn has_state(&self, state: &Arc<EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    fn is_empty(&self) -> bool {
        self.state.uses.load(Ordering::Acquire) == 0 && self.service.is_empty()
    }
}

// ===== impl MuxEntry =====

#[cfg(any(feature = "http2", feature = "http3"))]
impl<M, T> Entry<T> for MuxEntry<Singleton<M, Checkout<T>>>
where
    T: Clone + Send + 'static,
    M: Service<Checkout<T>, Response = mux::Connection, Error = BoxError, Future = MuxMake>
        + Clone
        + Send
        + 'static,
{
    fn checkout(&mut self, target: &T, pool_enabled: bool) -> CheckoutFuture {
        let usage = EntryUse::new(self.state.clone());
        if let Some(future) = self.service.checkout() {
            return CheckoutFuture::Mux {
                future,
                #[cfg(feature = "http2")]
                discarded: VecDeque::new(),
                usage: Some(usage),
                pool_enabled,
            };
        }
        let checkout = Checkout::new(target.clone(), false);
        let service = self.service.clone();
        CheckoutFuture::Service(Box::pin(async move {
            let service = Oneshot::new(service, checkout).await?;
            Ok(Pooled::new_mux(service, pool_enabled, usage))
        }))
    }

    #[cfg(feature = "ws")]
    fn checkout_made(&self) -> Option<(MuxSingled, Arc<EntryState>)> {
        Some((self.service.checkout_made()?, self.state.clone()))
    }

    fn prune(&mut self, now: Instant, timeout: Option<Duration>) -> Option<Discarded> {
        // A checkout waiting on the singleton may not hold a sender yet.
        let timeout = timeout.filter(|_| self.state.uses.load(Ordering::Acquire) == 0);
        self.service
            .retain(|connection| connection.is_reusable(now, timeout))
            .map(|sender| Discarded::Mux { _sender: sender })
    }

    fn has_retained(&self) -> bool {
        // Check health because a peer may close an idle connection between sweeps.
        self.service.has_service_and(mux::Connection::is_open)
    }

    fn prepare_eviction(&self) -> bool {
        self.service.has_service_and(|connection| {
            connection.is_open() && !connection.defer_until_idle(&self.state.track_on_idle)
        })
    }

    fn evict(&mut self) -> Option<Discarded> {
        self.service
            .take()
            .map(|sender| Discarded::Mux { _sender: sender })
    }

    fn has_state(&self, state: &Arc<EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    fn is_empty(&self) -> bool {
        self.state.uses.load(Ordering::Acquire) == 0 && self.service.is_empty()
    }
}

// ===== impl NegotiatedEntry =====

#[cfg(feature = "http2")]
impl<L, M, T> Entry<T> for NegotiatedEntry<L, Singleton<M, Established>, Established>
where
    T: Clone + Send + 'static,
    L: Http1Cache<Checkout<T>>,
    L::Future: Send,
    M: Service<Established, Response = mux::Connection, Error = BoxError, Future = MuxMake>
        + Clone
        + Send
        + 'static,
{
    fn checkout(&mut self, target: &T, pool_enabled: bool) -> CheckoutFuture {
        let wait_for_reuse = pool_enabled && !Entry::<T>::is_empty(self);
        let usage = EntryUse::new(self.state.clone());
        if let Some((future, discarded)) = self.service.checkout_existing() {
            return CheckoutFuture::Mux {
                future,
                discarded,
                usage: Some(usage),
                pool_enabled,
            };
        }
        let checkout = Checkout::new(target.clone(), wait_for_reuse);
        let service = self.service.clone();
        CheckoutFuture::Service(Box::pin(async move {
            Oneshot::new(service, checkout)
                .await
                .map(|service| match service {
                    Negotiated::Left(service) => Pooled::new_http1(service, pool_enabled, usage),
                    Negotiated::Right(service) => Pooled::new_mux(service, pool_enabled, usage),
                })
        }))
    }

    #[cfg(feature = "ws")]
    fn checkout_made(&self) -> Option<(MuxSingled, Arc<EntryState>)> {
        Some((self.service.upgrade().checkout_made()?, self.state.clone()))
    }

    fn prune(&mut self, now: Instant, timeout: Option<Duration>) -> Option<Discarded> {
        let entry_in_use = self.state.uses.load(Ordering::Acquire) != 0;
        // Once an HTTP/2 singleton is established, queued transports are redundant;
        // otherwise prune expired ones only when no checkout is actively draining them.
        let pending = if self.service.upgrade().has_service_and(|_| true) {
            self.service.drain_pending()
        } else if !entry_in_use {
            self.service
                .retain_pending(|connection| !is_expired(connection.idle_at(), now, timeout))
        } else {
            Default::default()
        };
        let fallback = self.service.fallback_mut().retain_idle(now, timeout);
        // Keep health checks active while another checkout protects against idle expiry.
        let timeout = timeout.filter(|_| !entry_in_use);
        let upgrade = self
            .service
            .upgrade_mut()
            .retain(|connection| connection.is_reusable(now, timeout));

        Discarded::negotiated(pending, fallback, upgrade)
    }

    fn has_retained(&self) -> bool {
        !self.service.pending_is_empty()
            || self.service.fallback().has_idle()
            || self
                .service
                .upgrade()
                .has_service_and(mux::Connection::is_open)
    }

    fn prepare_eviction(&self) -> bool {
        Entry::<T>::has_retained(self)
            && !self.service.upgrade().has_service_and(|connection| {
                connection.defer_until_idle(&self.state.track_on_idle)
            })
    }

    fn evict(&mut self) -> Option<Discarded> {
        let pending = self.service.drain_pending();
        let fallback = self.service.fallback_mut().drain_idle();
        let upgrade = self.service.upgrade_mut().take();
        Discarded::negotiated(pending, fallback, upgrade)
    }

    fn has_state(&self, state: &Arc<EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    fn is_empty(&self) -> bool {
        self.state.uses.load(Ordering::Acquire) == 0
            && self.service.pending_is_empty()
            && self.service.fallback().is_empty()
            && self.service.upgrade().is_empty()
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
                #[cfg(feature = "http2")]
                discarded,
                usage,
                pool_enabled,
            } => {
                #[cfg(feature = "http2")]
                drop(std::mem::take(discarded));
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

// ===== impl Cache =====

impl<M, R, Ev> Http1Cache<R> for Cache<M, R, Ev>
where
    R: 'static,
    M: Service<R, Response = http1::Connection, Error = BoxError> + Clone + Send + 'static,
    M::Future: Unpin + Send,
    M::Response: Unpin,
    Ev: cache::events::Events<BackgroundConnect<M::Future, M::Response>>
        + Clone
        + Send
        + Unpin
        + 'static,
{
    fn retain_idle(&mut self, now: Instant, timeout: Option<Duration>) -> Vec<http1::Connection> {
        self.retain(|connection| connection.is_reusable(now, timeout))
    }

    fn drain_idle(&mut self) -> Vec<http1::Connection> {
        Cache::drain_idle(self)
    }

    fn has_idle(&self) -> bool {
        Cache::has_idle(self)
    }

    fn is_empty(&self) -> bool {
        Cache::is_empty(self)
    }
}

// ===== impl EntryUse =====

impl EntryUse {
    /// Registers an active checkout against a map entry.
    pub(super) fn new(state: Arc<EntryState>) -> Self {
        state
            .uses
            .update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.saturating_add(1)
            });
        Self {
            state: Some(state),
            armed: true,
        }
    }

    /// Transfers successful-checkout cleanup to the returned pooled sender.
    pub(super) fn into_cleanup(mut self) -> EntryCleanupGuard {
        self.armed = false;
        let state = self.state.take();
        if let Some(state) = &state {
            state
                .uses
                .update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    count.saturating_sub(1)
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
            .update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.saturating_sub(1)
            });
        if self.armed && previous == 1 {
            (state.maintain)(state, false);
        }
    }
}

// ===== impl EntryCleanupGuard =====

impl EntryCleanupGuard {
    /// Reconciles retained state, skipping redundant work for a reused checkout.
    pub(super) fn maintain(&self, reused: bool) {
        if let Some(state) = &self.state {
            (state.maintain)(state, reused);
        }
    }

    /// Returns whether this entry needs to be tracked again.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) fn needs_tracking(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(|state| state.track_on_idle.load(Ordering::Acquire))
    }

    /// Requests identity-aware maintenance after sender destruction.
    pub(super) fn arm(&mut self) {
        self.armed = true;
    }
}

impl Drop for EntryCleanupGuard {
    fn drop(&mut self) {
        if self.armed
            && let Some(state) = &self.state
        {
            (state.maintain)(state, false);
        }
    }
}
