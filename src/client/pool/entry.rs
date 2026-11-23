//! Checkout and cleanup bookkeeping for mapped pool entries.
//!
//! The pool's protocol adapters implement [`Entry`]. This module owns entry
//! identity, checkout accounting, and deferred cleanup, not sender state.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tower::BoxError;

/// Checkout and maintenance interface shared by the protocol service stacks.
pub(super) trait Entry<T>: Send + Sync {
    /// Sender returned by a successful checkout.
    type Sender;

    /// Deferred checkout polled after the map unlocks.
    type Checkout: Future<Output = Result<Self::Sender, BoxError>>;

    /// Detached state dropped after the map unlocks.
    type Discarded;

    /// Takes a reusable sender without parking a waiter or calling the connector.
    #[must_use]
    fn checkout_ready(&self, now: Instant, timeout: Option<Duration>) -> Option<Self::Sender>;

    /// Checks out an established sender that supports extended CONNECT.
    ///
    /// A miss does not create, join, or discard work.
    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    #[must_use]
    fn checkout_extended_connect(
        &self,
        _now: Instant,
        _timeout: Option<Duration>,
    ) -> Option<Self::Sender> {
        None
    }

    /// Selects a checkout, cloning `target` only if the chosen path needs it.
    ///
    /// Release the map lock before dropping detached transports or polling the future.
    fn checkout(&self, target: &T, pool_enabled: bool)
    -> (Self::Checkout, Option<Self::Discarded>);

    /// Prunes stale state and returns it for drop after unlocking.
    ///
    /// Pending or active multiplexed checkouts defer idle expiry.
    #[must_use]
    fn prune(&self, now: Instant, timeout: Option<Duration>) -> Option<Self::Discarded>;

    /// Returns whether the entry holds connection state for reuse.
    #[must_use]
    fn has_retained(&self) -> bool;

    /// Returns whether the entry can stay tracked as an eviction candidate.
    ///
    /// Entries with active shared senders may defer tracking until their last checkout ends.
    #[must_use]
    fn prepare_eviction(&self) -> bool {
        self.has_retained()
    }

    /// Detaches reusable state to enforce pool capacity.
    ///
    /// Drop the returned state after releasing the map lock.
    #[must_use]
    fn evict(&self) -> Option<Self::Discarded>;

    /// Returns whether this entry holds the given state instance.
    #[must_use]
    fn has_state(&self, state: &Arc<EntryState>) -> bool;

    /// Returns whether the entry has no active, pending, or idle work.
    #[must_use]
    fn is_empty(&self) -> bool;
}

/// Maintenance operation requested by a checkout guard or background connection.
pub(super) enum Maintenance {
    /// Reconciles entry state and promotes retained entries to MRU.
    Touch,
    /// Reconciles entry state and tracks retained entries only if not already tracked.
    Reconcile,
    /// Discards a completed mux generation without locking the outer map.
    #[cfg(any(feature = "http2", feature = "http3"))]
    Discard(u64),
}

/// Callback reconciling an entry in the map or discarding a completed mux generation.
type EntryMaintenance = Box<dyn Fn(&Arc<EntryState>, Maintenance) + Send + Sync>;

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

/// Deferred entry maintenance guard owned by a checked-out sender.
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
    /// Successful returns update the LRU when the pool caps retained groups.
    pub(super) has_group_limit: bool,
    /// Expiration watcher status, present only when proactive expiration is enabled.
    pub(super) idle_watch_running: Option<Arc<AtomicBool>>,
    /// Performs the requested maintenance for this exact entry.
    pub(super) maintain: EntryMaintenance,
}

// ===== impl EntryUse =====

impl EntryUse {
    /// Registers an active checkout against a map entry.
    #[must_use]
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
    #[must_use]
    pub(super) fn into_cleanup(mut self, pool_enabled: bool) -> EntryCleanupGuard {
        self.armed = false;
        let state = self.state.take();
        if let Some(state) = &state {
            state
                .uses
                .update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    count.saturating_sub(1)
                });
        }
        EntryCleanupGuard::new(state.filter(|_| pool_enabled))
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
            (state.maintain)(state, Maintenance::Reconcile);
        }
    }
}

// ===== impl EntryCleanupGuard =====

impl EntryCleanupGuard {
    /// Creates an unarmed guard for a mapped (`Some`) or unpooled (`None`) checkout.
    #[must_use]
    pub(super) fn new(state: Option<Arc<EntryState>>) -> Self {
        Self {
            state,
            armed: false,
        }
    }

    /// Returns whether this checkout belongs to a mapped entry.
    #[must_use]
    pub(super) fn is_mapped(&self) -> bool {
        self.state.is_some()
    }

    /// Reconciles entry state, skipping the map lock when `known_live` needs neither LRU
    /// nor expiration-watcher updates.
    pub(super) fn maintain(&self, known_live: bool) {
        if let Some(state) = &self.state
            && (!known_live
                || state.has_group_limit
                || state
                    .idle_watch_running
                    .as_ref()
                    .is_some_and(|flag| !flag.load(Ordering::Acquire)))
        {
            (state.maintain)(state, Maintenance::Touch);
        }
    }

    /// Clears the completed generation without looking up the entry in the map.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) fn discard(&self, generation: u64) {
        if let Some(state) = &self.state {
            (state.maintain)(state, Maintenance::Discard(generation));
        }
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
            (state.maintain)(state, Maintenance::Reconcile);
        }
    }
}
