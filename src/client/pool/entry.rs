//! Mapped pool entries and their checkout accounting.
//!
//! [`Entry`] erases the fixed HTTP/1, fixed HTTP/2 or HTTP/3, and negotiated topologies
//! behind one trait object. [`EntryUse`] and [`EntryCleanupGuard`] count checkouts and
//! remove an empty entry by identity once its last checkout fails or discards the sender.

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
};
#[cfg(any(feature = "http2", feature = "http3"))]
use {
    super::singleton::{Singled, Singleton, SingletonFuture},
    crate::client::proto::mux,
};

use super::{
    PoolTarget,
    cache::{self, BackgroundConnect, Cache, Cached},
    pooled::Pooled,
};
#[cfg(test)]
use crate::protocol::Protocol;
use crate::{client::proto::http1, conn::request::ConnectRequest};

/// Type-erased operations required from one mapped pool entry.
///
/// The outer map stores different protocol pools through this trait object,
/// preserving static dispatch inside each entry. Maintenance methods return
/// removed connection state for destruction after the map lock is released.
pub(super) trait Entry: Send {
    /// Selects a checkout without polling service code under the map lock.
    /// Poll or drop the checkout and unused request only after unlocking.
    fn checkout(
        &mut self,
        target: PoolTarget,
        pool_enabled: bool,
    ) -> (Checkout, Option<ConnectRequest>);

    /// Clones an established shared sender without creating, joining, or draining
    /// work. HTTP/1 entries and generations still being made return `None`.
    #[cfg(any(feature = "http2", feature = "http3"))]
    fn checkout_made(&self) -> Option<(MuxPooled, Arc<EntryState>)>;

    /// Removes expired or closed idle connections for unlocked destruction.
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Option<DeferredDrop>;

    /// Returns whether this entry retains reusable connection state.
    fn is_retained(&self) -> bool;

    /// Returns whether LRU eviction would remove only idle state.
    ///
    /// HTTP/1 drains only idle senders; a shared HTTP/2 or HTTP/3 sender in use is never evicted.
    fn is_evictable(&self) -> bool {
        self.is_retained()
    }

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
pub(super) struct Http1Entry<L> {
    /// Exclusive HTTP/1 sender cache.
    pub(super) service: L,
    /// Checkout count and identity-aware cleanup for this entry.
    pub(super) state: Arc<EntryState>,
}

/// Fixed HTTP/2 or HTTP/3 entry sharing one connection generation across cold checkouts.
/// Once established, the sender is cloned for concurrent requests.
/// Pending uses keep the entry alive; `state` identifies it during cleanup.
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) struct MuxEntry<R> {
    /// Shared sender singleton.
    pub(super) service: R,
    /// Checkout count and identity-aware cleanup for this entry.
    pub(super) state: Arc<EntryState>,
    /// Protocol whose handshake the singleton runs.
    #[cfg(test)]
    pub(super) protocol: Protocol,
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
trait Http1Cache:
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

/// Handshake future of one HTTP/2 or HTTP/3 connection.
#[cfg(any(feature = "http2", feature = "http3"))]
type MuxMake = BoxFuture<'static, Result<mux::Connection, BoxError>>;

/// Shared sender clone checked out from a singleton.
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) type MuxPooled = Singled<MuxMake, mux::Connection>;

/// Future joining an existing singleton generation.
#[cfg(any(feature = "http2", feature = "http3"))]
type MuxCheckout = SingletonFuture<MuxMake, mux::Connection>;

/// Defers checkout completion and resource destruction until the map is unlocked.
///
/// Existing HTTP/2 and HTTP/3 generations retain their concrete singleton future. Cold
/// creation and HTTP/1 races keep the composed service future boxed. In either
/// case, the entry remains active until it is transferred to the sender.
pub(super) enum Checkout {
    /// Existing singleton work, without another box around its future.
    #[cfg(any(feature = "http2", feature = "http3"))]
    Mux {
        /// Owns the sender clone or pending-generation participation.
        future: MuxCheckout,
        /// Redundant negotiated transports released on the first poll or drop.
        discarded: Option<DeferredDrop>,
        /// Drops after the singleton participant so cleanup sees its final state.
        usage: Option<EntryUse>,
        /// Whether the resulting sender belongs to a shared pool.
        pool_enabled: bool,
    },
    /// Composed cache or negotiation work, retaining its own scheduling state.
    Service(BoxFuture<'static, Result<Pooled, BoxError>>),
}

/// Type-erased connection state held until the outer map lock is released.
///
/// One value may aggregate several concrete senders from the same entry. This
/// keeps cleanup type-erased without allocating one box per removed connection.
pub(super) type DeferredDrop = Box<dyn Send>;

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
    cleanup_on_drop: bool,
}

/// Deferred cleanup for a successful checkout that later discards its sender.
///
/// This field is declared after [`Pooled::inner`], so Rust drops the negotiated
/// sender and updates cache checkout accounting before this guard inspects the
/// mapped entry. A disarmed guard takes no lock on drop; successful return paths
/// perform their own maintenance before this guard is dropped.
pub(super) struct EntryCleanupGuard {
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
pub(super) struct EntryState {
    /// Number of checkout futures keeping the entry active.
    pub(super) uses: AtomicUsize,
    /// Reconciles this exact entry with cleanup and idle-group limits.
    pub(super) maintain: EntryMaintenance,
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

// ===== impl Http1Entry =====

impl<L> Entry for Http1Entry<L>
where
    L: Http1Cache,
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
    ) -> (Checkout, Option<ConnectRequest>) {
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

    #[cfg(any(feature = "http2", feature = "http3"))]
    fn checkout_made(&self) -> Option<(MuxPooled, Arc<EntryState>)> {
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

// ===== impl MuxEntry =====

#[cfg(any(feature = "http2", feature = "http3"))]
impl<M> Entry for MuxEntry<Singleton<M, PoolTarget>>
where
    M: Service<PoolTarget, Response = mux::Connection, Error = BoxError, Future = MuxMake>
        + Clone
        + Send
        + 'static,
{
    /// Joins the current generation or starts one when the entry is empty.
    ///
    /// The target keeps `wait_for_reuse` unset, so a cold start never waits for
    /// HTTP/1-style reuse. Every participant carries [`EntryUse`] until singleton
    /// checkout finishes.
    fn checkout(
        &mut self,
        target: PoolTarget,
        pool_enabled: bool,
    ) -> (Checkout, Option<ConnectRequest>) {
        let usage = EntryUse::new(self.state.clone());
        if let Some(future) = self.service.checkout() {
            let future = Checkout::Mux {
                future,
                discarded: None,
                usage: Some(usage),
                pool_enabled,
            };
            return (future, Some(target.req));
        }
        let service = self.service.clone();
        let future = Checkout::Service(Box::pin(async move {
            let service = Oneshot::new(service, target).await?;
            Ok(Pooled::new_mux(service, pool_enabled, usage))
        }));
        (future, None)
    }

    fn checkout_made(&self) -> Option<(MuxPooled, Arc<EntryState>)> {
        Some((self.service.checkout_made()?, self.state.clone()))
    }

    /// Removes a completed sender when poisoned, closed, or expired idle.
    ///
    /// Pending singleton creation is left untouched. Connections in use are
    /// kept by [`mux::Connection::is_reusable`].
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Option<DeferredDrop> {
        // Pending checkouts defer idle expiry, never poison or closure checks.
        let timeout = timeout.filter(|_| self.state.uses.load(Ordering::Acquire) == 0);
        self.service
            .retain(|connection| connection.is_reusable(now, timeout))
            .map(defer_drop)
    }

    /// Returns whether the singleton owns an open, unpoisoned sender.
    ///
    /// A peer can close an idle connection before the next sweep; a dead sender
    /// must not keep its idle-group LRU slot and displace live groups.
    fn is_retained(&self) -> bool {
        self.service.has_service_and(|connection| {
            !connection.connected().poisoned() && !connection.is_closed()
        })
    }

    /// Keeps a sender in use out of eviction, which would split its origin's traffic.
    fn is_evictable(&self) -> bool {
        self.is_retained() && !self.service.has_service_and(mux::Connection::is_in_use)
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

    /// Identifies the fixed HTTP/2 or HTTP/3 topology in tests.
    #[cfg(test)]
    fn protocol(&self) -> Protocol {
        self.protocol
    }
}

// ===== impl NegotiatedEntry =====

#[cfg(feature = "http2")]
impl<L, M> Entry for NegotiatedEntry<L, Singleton<M, Established>, Established>
where
    L: Http1Cache,
    L::Future: Send,
    M: Service<Established, Response = mux::Connection, Error = BoxError, Future = MuxMake>
        + Clone
        + Send
        + 'static,
{
    /// Joins existing upgraded work or checks out through the composed service.
    fn checkout(
        &mut self,
        mut target: PoolTarget,
        pool_enabled: bool,
    ) -> (Checkout, Option<ConnectRequest>) {
        target.wait_for_reuse = pool_enabled && !self.is_empty();
        let usage = EntryUse::new(self.state.clone());
        if let Some((future, discarded)) = self.service.checkout_existing() {
            let future = Checkout::Mux {
                future,
                discarded: (!discarded.is_empty()).then(|| defer_drop(discarded)),
                usage: Some(usage),
                pool_enabled,
            };
            return (future, Some(target.req));
        }
        let service = self.service.clone();
        let future = Checkout::Service(Box::pin(async move {
            Oneshot::new(service, target)
                .await
                .map(|service| match service {
                    Negotiated::Left(service) => Pooled::new_h1(service, pool_enabled, usage),
                    Negotiated::Right(service) => Pooled::new_mux(service, pool_enabled, usage),
                })
        }));
        (future, None)
    }

    /// Uses only the upgraded side; HTTP/1 fallback and pending transports stay untouched.
    fn checkout_made(&self) -> Option<(MuxPooled, Arc<EntryState>)> {
        Some((self.service.upgrade().checkout_made()?, self.state.clone()))
    }

    /// Cleans pending negotiation results and both protocol pools.
    fn retain(&mut self, now: Instant, timeout: Option<Duration>) -> Option<DeferredDrop> {
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

        (!pending.is_empty() || !fallback.is_empty() || upgrade.is_some())
            .then(|| defer_drop((pending, fallback, upgrade)))
    }

    /// Reports reusable connections owned by any negotiated path.
    fn is_retained(&self) -> bool {
        !self.service.pending_is_empty()
            || self.service.fallback().has_idle()
            || self.service.upgrade().has_service_and(|_| true)
    }

    /// Keeps the group while its upgraded sender is in use.
    fn is_evictable(&self) -> bool {
        self.is_retained()
            && !self
                .service
                .upgrade()
                .has_service_and(mux::Connection::is_in_use)
    }

    /// Drains every reusable connection while preserving active HTTP/1 work.
    fn evict_retained(&mut self) -> Option<DeferredDrop> {
        let pending = self.service.drain_pending();
        let fallback = self.service.fallback_mut().drain_idle();
        let upgrade = self.service.upgrade_mut().take();

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
            #[cfg(any(feature = "http2", feature = "http3"))]
            Self::Mux {
                future,
                discarded,
                usage,
                pool_enabled,
            } => {
                drop(discarded.take());
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

impl<M, Ev> Http1Cache for Cache<M, PoolTarget, Ev>
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

// ===== impl EntryUse =====

impl EntryUse {
    /// Registers one checkout against a mapped pool entry.
    pub(super) fn new(state: Arc<EntryState>) -> Self {
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
    pub(super) fn into_cleanup(mut self) -> EntryCleanupGuard {
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
    pub(super) fn maintain(&self) {
        if let Some(state) = &self.state {
            (state.maintain)(state);
        }
    }

    /// Requests one identity-aware empty-entry check after sender destruction.
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
