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

/// Checkout and maintenance shared by the protocol service stacks.
pub(super) trait Entry<T>: Send {
    /// Selects a checkout without polling service code under the map lock.
    /// Poll or drop the checkout only after unlocking.
    fn checkout(&mut self, target: &T, pool_enabled: bool) -> CheckoutFuture;

    /// Clones an established shared sender without creating, joining, or draining
    /// work. HTTP/1 entries and generations still being made return `None`.
    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    fn checkout_made(&self) -> Option<(MuxSingled, Arc<EntryState>)>;

    /// Prunes stale state and returns it for destruction after unlocking.
    /// Pending or active multiplexed checkouts defer idle expiry.
    fn prune(&mut self, now: Instant, timeout: Option<Duration>) -> Option<Discarded>;

    /// Returns whether the entry holds connection state for reuse.
    fn has_retained(&self) -> bool;

    /// Returns whether the entry can stay tracked as an eviction candidate.
    ///
    /// If a shared checkout prevents eviction, marks the entry to track again on final return.
    fn prepare_eviction(&self) -> bool {
        self.has_retained()
    }

    /// Detaches reusable state to enforce pool capacity.
    /// The caller drops the returned state after releasing the map lock.
    fn evict(&mut self) -> Option<Discarded>;

    /// Returns whether this entry holds the given state instance.
    fn has_state(&self, state: &Arc<EntryState>) -> bool;

    /// Returns whether the entry has no active, pending, or idle work.
    fn is_empty(&self) -> bool;
}

/// Fixed HTTP/1 entry owning the cache and its checkout-cleanup identity.
/// Each checkout takes an exclusive sender from the cache or a new handshake.
/// Ready senders return to the cache; pending uses keep the entry from removal.
pub(super) struct Http1Entry<S> {
    /// Exclusive HTTP/1 sender cache.
    pub(super) service: S,
    /// Checkout count and identity-aware cleanup for this entry.
    pub(super) state: Arc<EntryState>,
}

/// Fixed HTTP/2 or HTTP/3 entry sharing one connection generation across cold checkouts.
/// Once established, the sender is cloned for concurrent requests.
/// Pending uses keep the entry alive; `state` identifies it during cleanup.
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) struct MuxEntry<S> {
    /// Shared sender singleton.
    pub(super) service: S,
    /// Checkout count and identity-aware cleanup for this entry.
    pub(super) state: Arc<EntryState>,
}

/// Entry that selects HTTP/1 or HTTP/2 after transport negotiation.
///
/// `service` combines the HTTP/1 cache and HTTP/2 singleton for one compatibility
/// group. `state` counts checkout futures and carries the identity-aware cleanup
/// operation used when the final unsuccessful checkout leaves an empty entry.
#[cfg(feature = "http2")]
pub(super) struct NegotiatedEntry<L, R, S> {
    /// Fallback and upgraded pool composition.
    pub(super) service: Negotiate<L, R, S>,
    /// Checkout count and failed-checkout cleanup for this entry.
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

/// Handshake future of one HTTP/2 or HTTP/3 connection.
#[cfg(any(feature = "http2", feature = "http3"))]
type MuxMake = BoxFuture<'static, Result<mux::Connection, BoxError>>;

/// Future joining an existing singleton generation.
#[cfg(any(feature = "http2", feature = "http3"))]
type MuxCheckout = SingletonFuture<MuxMake, mux::Connection>;

/// Shared sender clone checked out from a singleton.
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) type MuxSingled = Singled<MuxMake, mux::Connection>;

/// Defers checkout completion and resource destruction until the map is unlocked.
///
/// Existing HTTP/2 and HTTP/3 generations retain their concrete singleton future. Cold
/// creation and HTTP/1 races keep the composed service future boxed. In either
/// case, the entry remains active until it is transferred to the sender.
pub(super) enum CheckoutFuture {
    /// Existing singleton work, without another box around its future.
    #[cfg(any(feature = "http2", feature = "http3"))]
    Mux {
        /// Owns the sender clone or pending-generation participation.
        future: MuxCheckout,

        /// Redundant negotiated transports released on the first poll or drop.
        #[cfg(feature = "http2")]
        discarded: VecDeque<Established>,

        /// Drops after the singleton participant so cleanup sees its final state.
        usage: Option<EntryUse>,

        /// Whether the resulting sender belongs to a shared pool.
        pool_enabled: bool,
    },
    /// Composed cache or negotiation work, retaining its own scheduling state.
    Service(BoxFuture<'static, Result<Pooled, BoxError>>),
}

/// Connection state detached from one entry for destruction after the map unlocks.
pub(super) enum Discarded {
    /// Idle senders detached from the HTTP/1 cache.
    Http1 { _senders: Vec<http1::Connection> },

    /// Completed sender detached from a shared connection.
    #[cfg(any(feature = "http2", feature = "http3"))]
    Mux { _sender: mux::Connection },

    /// Queued transports and senders detached from the negotiated entry.
    #[cfg(feature = "http2")]
    Negotiated {
        _pending: VecDeque<Established>,
        _fallback: Vec<http1::Connection>,
        _upgrade: Option<mux::Connection>,
    },
}

/// Identity-aware maintenance operation for one mapped entry.
type EntryMaintenance = Box<dyn Fn(&Arc<EntryState>) + Send + Sync>;

/// RAII count keeping a mapped entry alive while checkout is pending.
///
/// Every entry checkout creates one guard. Success disarms cleanup but still
/// decrements the use count. Failure or cancellation lets the final guard invoke
/// the entry's identity-aware cleanup operation, removing only the same empty
/// entry that created it.
pub(super) struct EntryUse {
    /// Shared state of the map entry being used.
    state: Option<Arc<EntryState>>,
    /// Whether cancellation or failure should remove an empty entry.
    armed: bool,
}

/// Deferred entry maintenance for sender disposal or resumed capacity tracking.
///
/// In [`Pooled`], this guard drops after the sender so cleanup sees the updated cache
/// or singleton state.
pub(super) struct EntryCleanupGuard {
    /// Entry identity and cleanup operation transferred from [`EntryUse`].
    state: Option<Arc<EntryState>>,
    /// Whether the entry needs maintenance after the sender is dropped.
    armed: bool,
}

/// Shared checkout count and cleanup operation for one mapped entry.
///
/// The cleanup closure owns the map key and a weak pool reference once per
/// entry, rather than cloning both for every request. It also compares this
/// state's `Arc` identity before removal, so an old checkout cannot delete a new
/// entry inserted under the same key after LRU eviction.
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
    /// Checks out one exclusive HTTP/1 sender from this entry.
    ///
    /// A reuse-first delay is enabled only when the entry already contains work
    /// that may yield a sender. [`EntryUse`] keeps the map entry alive until the
    /// checkout either fails or transfers ownership to [`Pooled`].
    fn checkout(&mut self, target: &T, pool_enabled: bool) -> CheckoutFuture {
        let target = Checkout::new(target, pool_enabled && !Entry::<T>::is_empty(self));
        let service = self.service.clone();
        let usage = EntryUse::new(self.state.clone());
        CheckoutFuture::Service(Box::pin(async move {
            Oneshot::new(service, target)
                .await
                .map(|service| Pooled::new_http1(service, pool_enabled, usage))
        }))
    }

    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    fn checkout_made(&self) -> Option<(MuxSingled, Arc<EntryState>)> {
        None
    }

    /// Removes closed or expired idle senders for unlocked destruction.
    ///
    /// Active checkouts and FIFO waiters remain owned by the cache.
    fn prune(&mut self, now: Instant, timeout: Option<Duration>) -> Option<Discarded> {
        Discarded::http1(self.service.retain_idle(now, timeout))
    }

    /// Reports whether the cache holds an idle or locally reserved sender.
    fn has_retained(&self) -> bool {
        self.service.has_idle()
    }

    /// Detaches idle senders when the group is evicted for capacity.
    ///
    /// Checked-out senders remain valid and can finish their requests.
    fn evict(&mut self) -> Option<Discarded> {
        Discarded::http1(self.service.drain_idle())
    }

    /// Compares cleanup state with this exact mapped entry.
    fn has_state(&self, state: &Arc<EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    /// Returns whether no checkout, waiter, reservation, or sender remains.
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
    /// Joins the current generation or starts one when the entry is empty.
    ///
    /// Every participant carries [`EntryUse`] until singleton checkout finishes.
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
        let target = Checkout::new(target, false);
        let service = self.service.clone();
        CheckoutFuture::Service(Box::pin(async move {
            let service = Oneshot::new(service, target).await?;
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

    /// Returns whether the singleton owns an open, unpoisoned sender.
    ///
    /// A peer can close an idle connection between sweeps, so check its health
    /// before counting the entry toward capacity.
    fn has_retained(&self) -> bool {
        self.service.has_service_and(mux::Connection::is_open)
    }

    fn prepare_eviction(&self) -> bool {
        self.service.has_service_and(|connection| {
            connection.is_open() && !connection.defer_until_idle(&self.state.track_on_idle)
        })
    }

    /// Detaches the completed sender when the group is evicted for capacity.
    ///
    /// Existing sender clones remain valid, while later checkouts create or join
    /// a new singleton generation.
    fn evict(&mut self) -> Option<Discarded> {
        self.service
            .take()
            .map(|sender| Discarded::Mux { _sender: sender })
    }

    /// Compares cleanup state with this exact mapped entry.
    fn has_state(&self, state: &Arc<EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    /// Returns whether no checkout or singleton generation remains.
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
    /// Joins existing upgraded work or checks out through the composed service.
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
        let target = Checkout::new(target, wait_for_reuse);
        let service = self.service.clone();
        CheckoutFuture::Service(Box::pin(async move {
            Oneshot::new(service, target)
                .await
                .map(|service| match service {
                    Negotiated::Left(service) => Pooled::new_http1(service, pool_enabled, usage),
                    Negotiated::Right(service) => Pooled::new_mux(service, pool_enabled, usage),
                })
        }))
    }

    /// Uses only the upgraded side; HTTP/1 fallback and pending transports stay untouched.
    #[cfg(feature = "ws")]
    fn checkout_made(&self) -> Option<(MuxSingled, Arc<EntryState>)> {
        Some((self.service.upgrade().checkout_made()?, self.state.clone()))
    }

    /// Prunes both protocol pools and clears stale or redundant negotiation results.
    fn prune(&mut self, now: Instant, timeout: Option<Duration>) -> Option<Discarded> {
        let entry_in_use = self.state.uses.load(Ordering::Acquire) != 0;
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

    /// Reports queued HTTP/2 transports, cached HTTP/1 senders, or a healthy HTTP/2 sender.
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

    /// Drains every reusable connection while preserving active HTTP/1 work.
    fn evict(&mut self) -> Option<Discarded> {
        let pending = self.service.drain_pending();
        let fallback = self.service.fallback_mut().drain_idle();
        let upgrade = self.service.upgrade_mut().take();
        Discarded::negotiated(pending, fallback, upgrade)
    }

    /// Compares shared checkout state with this exact entry instance.
    fn has_state(&self, state: &Arc<EntryState>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }

    /// Returns whether no checkout or protocol pool state remains.
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
                // Pooled::new starts checkout accounting before releasing EntryUse and
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

// ===== impl EntryUse =====

impl EntryUse {
    /// Registers one checkout against a mapped pool entry.
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
            (state.maintain)(state);
        }
    }
}

// ===== impl EntryCleanupGuard =====

impl EntryCleanupGuard {
    /// Reconciles retained state immediately after a successful transition.
    pub(super) fn maintain(&self) {
        if let Some(state) = &self.state {
            (state.maintain)(state);
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
            (state.maintain)(state);
        }
    }
}
