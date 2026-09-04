//! Enforces physical connection limits across every mapped pool entry.
//!
//! A [`ConnectionPermit`] reserves one slot before dialing starts. The protocol
//! sender and connection driver hold clones of the same permit, so accounting is
//! released only after the physical connection has fully left the pool.
//!
//! # Scheduling
//!
//! Acquisitions enter one shared queue. Eligible waiters are granted in arrival
//! order, while a waiter blocked by its own scope does not prevent another scope
//! from using free global capacity. Before an acquisition sleeps, the outer pool
//! may reclaim an idle connection when releasing it would satisfy queued work.
//!
//! Permit delivery and destruction happen outside the state lock. This matters
//! because dropping a permit can grant capacity and wake another task.
//!
//! # Example
//!
//! The connection maker acquires once, then gives clones to the sender and the
//! protocol driver. The slot is returned only after both owners are gone:
//!
//! ```rust,ignore
//! let permit = capacity.acquire(limit_key).await?;
//! let driver_permit = permit.clone();
//! spawn(async move {
//!     drive_connection(io).await;
//!     drop(driver_permit);
//! });
//! let sender_permit = permit;
//! // `sender_permit` remains with the protocol sender until it is dropped.
//! ```

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

use http::{Uri, uri::Scheme};
use tokio::sync::oneshot;

use super::Ver;
use crate::{
    conn::descriptor::ConnectionId,
    pool::{PoolLimitScope, PoolLimits},
    sync::Mutex,
};

/// Key used for per-scope physical connection accounting.
///
/// The selected variant is fixed by [`PoolLimitScope`] for a client. It affects
/// only the per-scope limit; every permit also contributes to the global count.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum LimitKey {
    /// Groups every compatible connection for one URI origin.
    Origin(Origin),
    /// Separates an origin by its requested protocol mode.
    OriginAndProtocol(Origin, Ver),
    /// Uses the complete connection compatibility group.
    Group(ConnectionId),
}

/// Normalized URI origin used by per-scope accounting.
///
/// The host is lowercased once when limits are enabled, while clones share its
/// allocation. Storing the effective port makes implicit and explicit default
/// ports part of the same scope.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Origin {
    /// URI scheme participating in origin comparison.
    scheme: Option<Scheme>,
    /// ASCII case-insensitive host in normalized form.
    host: Arc<str>,
    /// Explicit or scheme-default port.
    port: u16,
}

// ===== impl Origin =====

impl Origin {
    /// Normalizes the origin components of an absolute request URI.
    fn new(uri: &Uri) -> Self {
        let host = uri.host().unwrap_or_default().to_ascii_lowercase().into();
        let port = uri.port_u16().unwrap_or_else(|| match uri.scheme_str() {
            Some("https" | "wss") => 443,
            _ => 80,
        });

        Self {
            scheme: uri.scheme().cloned(),
            host,
            port,
        }
    }
}

// ===== impl LimitKey =====

impl LimitKey {
    /// Builds an accounting key from the configured limit scope.
    pub(super) fn new(
        scope: PoolLimitScope,
        origin: &Uri,
        protocol: Ver,
        group: &ConnectionId,
    ) -> Self {
        match scope {
            PoolLimitScope::Origin => Self::Origin(Origin::new(origin)),
            PoolLimitScope::OriginAndProtocol => {
                Self::OriginAndProtocol(Origin::new(origin), protocol)
            }
            PoolLimitScope::Group => Self::Group(group.clone()),
        }
    }
}

/// Cloneable manager for global and per-scope connection capacity.
///
/// Every mapped pool entry shares the same [`Inner`] state. `Capacity::new`
/// returns `None` when both limits are disabled, keeping the unrestricted hot
/// path free of queue and permit bookkeeping. Cloning this handle shares one
/// scheduler; it does not reserve capacity until [`Capacity::acquire`] is
/// polled.
#[derive(Clone)]
pub struct Capacity {
    /// Counters and waiters shared by all connection groups.
    inner: Arc<Mutex<Inner>>,
}

/// Mutable counters and pending acquisitions protected by the capacity lock.
///
/// `total` equals the number of live reservations, and each `per_scope` value
/// counts the same reservations for one [`LimitKey`]. A waiter enters this state
/// before idle reclamation runs, which prevents a returned connection from
/// missing newly blocked work.
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
///
/// The queue owns only the sending half of the result channel. Closing the
/// receiver marks the waiter for removal, and a failed permit delivery restores
/// the reservation before another waiter is considered.
struct Waiter {
    /// Scope requested by the connection attempt.
    key: LimitKey,
    /// Delivers the reserved permit when capacity becomes available.
    tx: oneshot::Sender<ConnectionPermit>,
}

/// Shared reservation for one physical connection.
///
/// Cloning a permit does not consume another slot. The sender and protocol
/// driver use clones to tie accounting to the complete socket lifetime. The
/// default value is an untracked permit used when limits are disabled.
#[derive(Clone, Default)]
pub struct ConnectionPermit(Option<Arc<PermitInner>>);

/// Owns the accounting key shared by every clone of a connection permit.
///
/// Only the final `Arc` drop reaches this value. Its destructor removes one
/// global and one scoped reservation, then dispatches any newly eligible
/// waiters after releasing the capacity lock.
struct PermitInner {
    /// Capacity manager, held weakly to avoid extending pool lifetime.
    capacity: Weak<Mutex<Inner>>,
    /// Scope released exactly once by `Drop` or failed dispatch recovery.
    key: Option<LimitKey>,
}

/// Cancel-safe future that acquires one physical connection permit.
///
/// The first poll either reserves immediately or appends a waiter. Dropping a
/// waiting future closes its receiver and removes stale queue state. A permit
/// already sent into that receiver is dropped normally and returns its slot.
pub struct Acquire {
    /// Current acquisition phase.
    state: AcquireState,
}

/// Lifecycle of one capacity acquisition.
///
/// State transitions are explicit so cancellation can distinguish an unpolled
/// future from a registered waiter and a completed acquisition.
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

/// Indicates that a queued capacity acquisition no longer has a grant source.
///
/// This normally means the owning capacity manager or channel state disappeared
/// while the future was waiting.
#[derive(Debug)]
pub struct AcquireError;

/// Identifies which limit currently prevents a connection reservation.
///
/// The outer pool uses this distinction to reclaim either any idle connection
/// for a full global limit or a matching connection for a full scoped limit.
#[derive(Clone, Copy)]
pub enum BlockedBy {
    /// The client-wide connection limit is full.
    Total,
    /// The requested scope's connection limit is full.
    Scope,
}

// ===== impl Capacity =====

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
    pub fn should_release_idle(&self, permit: &ConnectionPermit) -> bool {
        let Some(key) = permit.key() else {
            return false;
        };

        let (should_release, canceled) = {
            let mut inner = self.inner.lock();
            let canceled = inner.take_canceled_waiters();
            let should_release = inner
                .waiters
                .iter()
                .any(|waiter| inner.can_reserve_after_release(&waiter.key, key));
            (should_release, canceled)
        };
        drop(canceled);
        should_release
    }
}

// ===== impl Acquire =====

impl Future for Acquire {
    type Output = Result<ConnectionPermit, AcquireError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            match mem::replace(&mut this.state, AcquireState::Done) {
                AcquireState::Init { capacity, key } => {
                    let (acquired, canceled) = {
                        let mut inner = capacity.inner.lock();
                        let canceled = inner.take_canceled_waiters();

                        let acquired = if inner.waiters.is_empty() && inner.can_reserve(&key) {
                            inner.reserve(&key);
                            Ok(ConnectionPermit::new(&capacity.inner, key))
                        } else {
                            let (tx, rx) = oneshot::channel();
                            inner.waiters.push_back(Waiter { key, tx });
                            Err((rx, inner.collect_grants()))
                        };
                        (acquired, canceled)
                    };
                    drop(canceled);

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
    fn drop(&mut self) {
        if let AcquireState::Waiting { capacity, rx } = &mut self.state {
            rx.close();
            let canceled = capacity.inner.lock().take_canceled_waiters();
            drop(canceled);
        }
    }
}

// ===== impl ConnectionPermit =====

impl ConnectionPermit {
    /// Creates a shared permit for one already-reserved scope.
    fn new(capacity: &Arc<Mutex<Inner>>, key: LimitKey) -> Self {
        Self(Some(Arc::new(PermitInner {
            capacity: Arc::downgrade(capacity),
            key: Some(key),
        })))
    }

    /// Returns whether this permit participates in capacity accounting.
    pub fn is_limited(&self) -> bool {
        self.0.is_some()
    }

    /// Returns whether this permit belongs to `key`.
    pub fn matches(&self, key: &LimitKey) -> bool {
        self.0
            .as_ref()
            .is_some_and(|permit| permit.key.as_ref() == Some(key))
    }

    /// Borrows the permit's accounting key.
    fn key(&self) -> Option<&LimitKey> {
        self.0.as_ref()?.key.as_ref()
    }

    /// Releases a failed grant and collects eligible and canceled waiters.
    ///
    /// If another permit clone exists, its eventual drop performs the release.
    fn release_into(mut self, capacity: &Arc<Mutex<Inner>>) -> (Vec<Waiter>, Vec<Waiter>) {
        let Some(permit) = self.0.take() else {
            return (Vec::new(), Vec::new());
        };
        let Ok(mut permit) = Arc::try_unwrap(permit) else {
            return (Vec::new(), Vec::new());
        };
        let Some(key) = permit.key.take() else {
            return (Vec::new(), Vec::new());
        };

        let mut inner = capacity.lock();
        inner.release(&key);
        let canceled = inner.take_canceled_waiters();
        (inner.collect_grants(), canceled)
    }
}

// ===== impl PermitInner =====

impl Drop for PermitInner {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let Some(capacity) = self.capacity.upgrade() else {
            return;
        };

        let (grants, canceled) = {
            let mut inner = capacity.lock();
            inner.release(&key);
            let canceled = inner.take_canceled_waiters();
            (inner.collect_grants(), canceled)
        };
        drop(canceled);
        dispatch_grants(&capacity, grants);
    }
}

// ===== impl Inner =====

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

    /// Removes canceled waiters for destruction after releasing the state lock.
    fn take_canceled_waiters(&mut self) -> Vec<Waiter> {
        let mut canceled = Vec::new();
        let waiting = self.waiters.len();

        for _ in 0..waiting {
            let Some(waiter) = self.waiters.pop_front() else {
                break;
            };
            if waiter.tx.is_closed() {
                canceled.push(waiter);
            } else {
                self.waiters.push_back(waiter);
            }
        }

        canceled
    }

    /// Reserves every currently eligible waiter without head-of-line blocking.
    fn collect_grants(&mut self) -> Vec<Waiter> {
        let mut grants = Vec::new();
        let waiting = self.waiters.len();

        for _ in 0..waiting {
            let Some(waiter) = self.waiters.pop_front() else {
                break;
            };
            if self.can_reserve(&waiter.key) {
                self.reserve(&waiter.key);
                grants.push(waiter);
            } else {
                self.waiters.push_back(waiter);
            }
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
            let (recovered, canceled) = permit.release_into(capacity);
            drop(canceled);
            grants.extend(recovered);
        }
    }
}

// ===== impl AcquireError =====

impl fmt::Display for AcquireError {
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
        LimitKey::Origin(Origin::new(&Uri::from_static(host)))
    }

    #[test]
    fn limits_are_scoped_and_wake_eligible_waiters_in_order() {
        assert_eq!(
            Origin::new(&Uri::from_static("http://EXAMPLE.test/")),
            Origin::new(&Uri::from_static("http://example.TEST:80/path"))
        );

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

        let mut held = task::spawn(capacity.acquire(key("http://cancel.test/")));
        let Poll::Ready(Ok(held)) = held.poll() else {
            panic!("initial cancellation-test permit should be ready");
        };
        let mut canceled = task::spawn(capacity.acquire(key("http://cancel.test/")));
        let mut survivor = task::spawn(capacity.acquire(key("http://cancel.test/")));
        assert!(canceled.poll().is_pending());
        assert!(survivor.poll().is_pending());

        drop(held);
        drop(canceled);
        assert!(matches!(survivor.poll(), Poll::Ready(Ok(_))));
    }
}
