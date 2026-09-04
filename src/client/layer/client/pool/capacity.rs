//! Enforces connection limits across every mapped pool entry.
//!
//! A [`ConnectionPermit`] represents one physical connection from dialing until
//! its protocol driver exits. Clones held by the sender and driver share the same
//! reservation, so a slot is released only after the actual connection is gone.
//!
//! Waiters are considered in arrival order, but a waiter blocked by its own
//! scope does not prevent an eligible waiter for another scope from proceeding.
//! Idle connections can be reclaimed when releasing one would satisfy queued
//! work.

use std::{
    collections::{HashMap, VecDeque},
    error::Error as StdError,
    fmt,
    future::Future,
    mem,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use http::Uri;
use tokio::sync::oneshot;

use super::Ver;
use crate::{
    conn::descriptor::ConnectionId,
    pool::{PoolLimitScope, PoolLimits},
    sync::Mutex,
};

/// Key used for per-scope connection accounting.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(in crate::client::layer::client) enum LimitKey {
    /// Groups every compatible connection for one URI origin.
    Origin(Uri),
    /// Separates an origin by its requested protocol mode.
    OriginAndProtocol(Uri, Ver),
    /// Uses the complete connection compatibility group.
    Group(ConnectionId),
}

impl LimitKey {
    /// Builds an accounting key from the configured limit scope.
    pub(super) fn new(
        scope: PoolLimitScope,
        origin: &Uri,
        protocol: Ver,
        group: &ConnectionId,
    ) -> Self {
        match scope {
            PoolLimitScope::Origin => Self::Origin(origin.clone()),
            PoolLimitScope::OriginAndProtocol => Self::OriginAndProtocol(origin.clone(), protocol),
            PoolLimitScope::Group => Self::Group(group.clone()),
        }
    }
}

/// Shared connection-capacity manager.
#[derive(Clone)]
pub(super) struct Capacity {
    /// Counters and waiters shared by all connection groups.
    inner: Arc<Mutex<Inner>>,
}

/// Mutable connection counters and pending acquisitions.
struct Inner {
    /// Configured global and per-scope limits.
    limits: PoolLimits,
    /// Number of currently reserved physical connections.
    total: usize,
    /// Reserved connections indexed by scope key.
    per_scope: HashMap<LimitKey, usize>,
    /// Acquisitions waiting for capacity.
    waiters: VecDeque<Waiter>,
}

/// One queued capacity acquisition.
struct Waiter {
    /// Scope requested by the connection attempt.
    key: LimitKey,
    /// Delivers the reserved permit when capacity becomes available.
    tx: oneshot::Sender<ConnectionPermit>,
}

/// Shared reservation for one physical connection.
#[derive(Clone, Default)]
pub(in crate::client::layer::client) struct ConnectionPermit(Option<Arc<PermitInner>>);

/// Releases capacity after the final permit clone is dropped.
struct PermitInner {
    /// Capacity manager, held weakly to avoid extending pool lifetime.
    capacity: Weak<Mutex<Inner>>,
    /// Scope released exactly once by `Drop` or failed dispatch recovery.
    key: Option<LimitKey>,
}

/// Future that acquires one connection permit.
pub(in crate::client::layer::client) struct Acquire {
    /// Current acquisition phase.
    state: AcquireState,
}

/// Lifecycle of a capacity acquisition.
enum AcquireState {
    /// Capacity has not been inspected yet.
    Init {
        /// Capacity manager handling the request.
        capacity: Capacity,
        /// Requested accounting scope.
        key: LimitKey,
    },
    /// The acquisition is queued for a future grant.
    Waiting {
        /// Capacity manager used to cancel the queued waiter.
        capacity: Capacity,
        /// Receives the granted permit.
        rx: oneshot::Receiver<ConnectionPermit>,
    },
    /// The future has already completed.
    Done,
}

/// Indicates that a queued capacity acquisition was canceled.
#[derive(Debug)]
pub(in crate::client::layer::client) struct AcquireError;

/// Identifies the limit preventing a connection reservation.
#[derive(Clone, Copy)]
pub(super) enum BlockedBy {
    /// The client-wide connection limit is full.
    Total,
    /// The requested scope's connection limit is full.
    Scope,
}

impl Capacity {
    /// Creates a capacity manager, or `None` when every limit is disabled.
    pub(super) fn new(limits: PoolLimits) -> Option<Self> {
        (!limits.is_unlimited()).then(|| Self {
            inner: Arc::new(Mutex::new(Inner {
                limits,
                total: 0,
                per_scope: HashMap::new(),
                waiters: VecDeque::new(),
            })),
        })
    }

    /// Creates a lazy acquisition for `key`.
    pub(super) fn acquire(&self, key: LimitKey) -> Acquire {
        Acquire {
            state: AcquireState::Init {
                capacity: self.clone(),
                key,
            },
        }
    }

    /// Returns the limit currently blocking `key`, if any.
    pub(super) fn blocked_by(&self, key: &LimitKey) -> Option<BlockedBy> {
        self.inner.lock().blocked_by(key)
    }

    /// Returns whether releasing this idle permit could satisfy queued work.
    pub(super) fn should_release_idle(&self, permit: &ConnectionPermit) -> bool {
        let Some(key) = permit.key() else {
            return false;
        };

        let mut inner = self.inner.lock();
        inner.clean_waiters();
        inner
            .waiters
            .iter()
            .any(|waiter| inner.can_reserve_after_release(&waiter.key, key))
    }
}

impl Future for Acquire {
    type Output = Result<ConnectionPermit, AcquireError>;

    /// Reserves capacity immediately or registers a cancel-safe waiter.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            match mem::replace(&mut this.state, AcquireState::Done) {
                AcquireState::Init { capacity, key } => {
                    let acquired = {
                        let mut inner = capacity.inner.lock();
                        inner.clean_waiters();

                        if inner.waiters.is_empty() && inner.can_reserve(&key) {
                            inner.reserve(&key);
                            Ok(ConnectionPermit::new(&capacity.inner, key))
                        } else {
                            let (tx, rx) = oneshot::channel();
                            inner.waiters.push_back(Waiter { key, tx });
                            Err((rx, inner.collect_grants()))
                        }
                    };

                    match acquired {
                        Ok(permit) => {
                            return Poll::Ready(Ok(permit));
                        }
                        Err((rx, grants)) => {
                            dispatch_grants(&capacity.inner, grants);
                            this.state = AcquireState::Waiting { capacity, rx };
                        }
                    }
                }
                AcquireState::Waiting { capacity, mut rx } => match Pin::new(&mut rx).poll(cx) {
                    Poll::Ready(Ok(permit)) => return Poll::Ready(Ok(permit)),
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(AcquireError)),
                    Poll::Pending => {
                        this.state = AcquireState::Waiting { capacity, rx };
                        return Poll::Pending;
                    }
                },
                AcquireState::Done => return Poll::Ready(Err(AcquireError)),
            }
        }
    }
}

impl Drop for Acquire {
    /// Closes and removes a waiter when its future is canceled.
    fn drop(&mut self) {
        if let AcquireState::Waiting { capacity, rx } = &mut self.state {
            rx.close();
            capacity.inner.lock().clean_waiters();
        }
    }
}

impl ConnectionPermit {
    /// Creates a shared permit for one already-reserved scope.
    fn new(capacity: &Arc<Mutex<Inner>>, key: LimitKey) -> Self {
        Self(Some(Arc::new(PermitInner {
            capacity: Arc::downgrade(capacity),
            key: Some(key),
        })))
    }

    /// Returns whether this permit participates in capacity accounting.
    pub(super) fn is_limited(&self) -> bool {
        self.0.is_some()
    }

    /// Returns whether this permit belongs to `key`.
    pub(super) fn matches(&self, key: &LimitKey) -> bool {
        self.0
            .as_ref()
            .is_some_and(|permit| permit.key.as_ref() == Some(key))
    }

    /// Borrows the permit's accounting key.
    fn key(&self) -> Option<&LimitKey> {
        self.0.as_ref()?.key.as_ref()
    }

    /// Releases a failed grant and collects newly eligible waiters.
    ///
    /// If another permit clone exists, its eventual drop performs the release.
    fn release_into(mut self, capacity: &Arc<Mutex<Inner>>) -> Vec<Waiter> {
        let Some(permit) = self.0.take() else {
            return Vec::new();
        };
        let Ok(mut permit) = Arc::try_unwrap(permit) else {
            return Vec::new();
        };
        let Some(key) = permit.key.take() else {
            return Vec::new();
        };

        let mut inner = capacity.lock();
        inner.release(&key);
        inner.collect_grants()
    }
}

impl Drop for PermitInner {
    /// Releases the reservation and dispatches all newly eligible grants.
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let Some(capacity) = self.capacity.upgrade() else {
            return;
        };

        let grants = {
            let mut inner = capacity.lock();
            inner.release(&key);
            inner.collect_grants()
        };
        dispatch_grants(&capacity, grants);
    }
}

impl Inner {
    /// Returns whether the scope or total limit currently blocks `key`.
    fn blocked_by(&self, key: &LimitKey) -> Option<BlockedBy> {
        let scope_full = self
            .limits
            .max_connections_per_scope
            .is_some_and(|max| self.per_scope.get(key).copied().unwrap_or(0) >= max.get());
        let total_full = self
            .limits
            .max_connections
            .is_some_and(|max| self.total >= max.get());

        match (scope_full, total_full) {
            (true, _) => Some(BlockedBy::Scope),
            (false, true) => Some(BlockedBy::Total),
            (false, false) => None,
        }
    }

    /// Returns whether a new connection can be reserved for `key`.
    fn can_reserve(&self, key: &LimitKey) -> bool {
        self.blocked_by(key).is_none()
    }

    /// Simulates releasing `released` before testing a waiting key.
    fn can_reserve_after_release(&self, key: &LimitKey, released: &LimitKey) -> bool {
        let below_total = self
            .limits
            .max_connections
            .is_none_or(|max| self.total.saturating_sub(1) < max.get());
        let scope_count = self.per_scope.get(key).copied().unwrap_or(0);
        let scope_count = scope_count.saturating_sub(usize::from(key == released));
        let below_scope = self
            .limits
            .max_connections_per_scope
            .is_none_or(|max| scope_count < max.get());

        below_total && below_scope
    }

    /// Increments global and per-scope counters for `key`.
    fn reserve(&mut self, key: &LimitKey) {
        self.total = self.total.saturating_add(1);
        let count = self.per_scope.entry(key.clone()).or_default();
        *count = count.saturating_add(1);
    }

    /// Decrements counters and removes an empty scope entry.
    fn release(&mut self, key: &LimitKey) {
        self.total = self.total.saturating_sub(1);

        if let Some(count) = self.per_scope.get_mut(key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_scope.remove(key);
            }
        }
    }

    /// Removes waiters whose receivers have already been dropped.
    fn clean_waiters(&mut self) {
        self.waiters.retain(|waiter| !waiter.tx.is_closed());
    }

    /// Reserves every currently eligible waiter without head-of-line blocking.
    fn collect_grants(&mut self) -> Vec<Waiter> {
        self.clean_waiters();
        let mut grants = Vec::new();

        while let Some(index) = self
            .waiters
            .iter()
            .position(|waiter| self.can_reserve(&waiter.key))
        {
            let Some(waiter) = self.waiters.remove(index) else {
                break;
            };

            self.reserve(&waiter.key);
            grants.push(waiter);
        }

        grants
    }
}

/// Delivers reserved permits and recovers capacity from canceled receivers.
fn dispatch_grants(capacity: &Arc<Mutex<Inner>>, grants: Vec<Waiter>) {
    let mut grants = VecDeque::from(grants);

    while let Some(waiter) = grants.pop_front() {
        let permit = ConnectionPermit::new(capacity, waiter.key);
        if let Err(permit) = waiter.tx.send(permit) {
            grants.extend(permit.release_into(capacity));
        }
    }
}

impl fmt::Display for AcquireError {
    /// Writes the capacity cancellation reason.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("connection pool capacity wait was canceled")
    }
}

impl StdError for AcquireError {}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use tokio_test::task;

    use super::*;

    fn key(host: &'static str) -> LimitKey {
        LimitKey::Origin(Uri::from_static(host))
    }

    #[test]
    fn limits_are_scoped_and_wake_eligible_waiters_in_order() {
        let capacity = Capacity::new(
            PoolLimits::builder()
                .max_connections(2)
                .max_connections_per_scope(1)
                .build(),
        )
        .expect("limited capacity");

        let mut first_a = task::spawn(capacity.acquire(key("http://a.test/")));
        let mut first_b = task::spawn(capacity.acquire(key("http://b.test/")));
        let Poll::Ready(Ok(first_a)) = first_a.poll() else {
            panic!("first origin A permit should be ready");
        };
        let Poll::Ready(Ok(first_b)) = first_b.poll() else {
            panic!("first origin B permit should be ready");
        };

        let mut second_a = task::spawn(capacity.acquire(key("http://a.test/")));
        let mut third_a = task::spawn(capacity.acquire(key("http://a.test/")));
        let mut second_b = task::spawn(capacity.acquire(key("http://b.test/")));
        assert!(second_a.poll().is_pending());
        assert!(third_a.poll().is_pending());
        assert!(second_b.poll().is_pending());

        drop(first_b);
        let Poll::Ready(Ok(second_b)) = second_b.poll() else {
            panic!("eligible origin B waiter should be woken");
        };
        assert!(second_a.poll().is_pending());

        drop(first_a);
        let Poll::Ready(Ok(second_a)) = second_a.poll() else {
            panic!("oldest origin A waiter should be woken first");
        };
        assert!(third_a.poll().is_pending());

        drop(second_a);
        assert!(matches!(third_a.poll(), Poll::Ready(Ok(_))));
        drop(second_b);
    }
}
