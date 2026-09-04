//! Races reusable services against newly created services.
//!
//! This component manages services that can serve one checkout at a time, which
//! is how wreq uses HTTP/1 senders. Each [`Cache`] clone has an independent
//! readiness reservation. Idle services, FIFO waiters, and checkout accounting
//! are shared across clones.
//!
//! # Checkout lifecycle
//!
//! 1. `poll_ready` reserves an idle service when one is available. Otherwise it registers a waiter
//!    and polls the maker.
//! 2. `call` either returns the reserved service or races the waiter against a newly made service.
//! 3. [`Cached`] returns a healthy service when it is dropped. A failed or explicitly discarded
//!    service is destroyed instead.
//!
//! Returned services go to the oldest waiter before they enter the idle list.
//! If reuse wins after connection work has started, the configured event handler
//! may finish that work in the background and cache the result.
//!
//! # Example
//!
//! A cache wraps a maker service. Tower readiness reserves a returned service
//! for the next call on that same cache clone:
//!
//! ```rust,ignore
//! let mut cache = cache::builder()
//!     .max_idle(8)
//!     .executor(executor)
//!     .build(maker);
//!
//! poll_fn(|cx| cache.poll_ready(cx)).await?;
//! let sender = cache.call(destination).await?;
//! drop(sender); // returns a healthy exclusive service to the cache
//! ```

use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    task::{self, Poll, Waker, ready},
};

use futures_util::future::BoxFuture;
use tokio::sync::watch;
use tower::Service;

use crate::sync::Mutex;

/// Reports whether a raced maker future has begun work worth completing.
///
/// Cache policy waits can be canceled cheaply. Physical connection work may
/// already own resources, so the event handler uses this signal before deciding
/// whether to continue a lost race in the background.
pub(super) trait Started: Future {
    /// Returns `true` after canceling the future would waste started work.
    fn started(&self) -> bool;
}

/// Starts configuring a cache around a service maker.
pub(super) fn builder() -> Builder<events::Ignore> {
    Builder {
        events: events::Ignore,
        max_idle: usize::MAX,
    }
}

/// A cloneable cache of exclusive services produced by `M`.
///
/// A clone reserves at most one service during `poll_ready`, and only its next
/// `call` can consume that reservation. This preserves Tower's readiness
/// contract when several client tasks use cache clones concurrently.
///
/// [`Shared`] owns idle services and FIFO handoff state. Checked-out services
/// hold only a weak reference to it, so neither a checkout nor a background
/// maker keeps an otherwise unused cache alive. Dropping the final shared owner
/// also closes the shutdown channel used by background maker work.
#[derive(Debug)]
pub(super) struct Cache<M, Dst, Ev>
where
    M: Service<Dst>,
{
    /// Creates a service when no reusable service wins the race.
    connector: M,
    /// State shared by every cache clone and checked-out service.
    shared: Arc<Mutex<Shared<M::Response>>>,
    /// Decides what happens to a connection attempt that loses to reuse.
    events: Ev,
    /// Service reserved by this clone during `poll_ready`.
    ready: Ready<M::Response>,
    /// FIFO waiter registered by this clone during `poll_ready`.
    ready_waiter: Option<WaiterId>,
    /// Number of services currently checked out from this cache.
    active: Arc<AtomicUsize>,
    /// Carries the destination type without owning a destination.
    _dst: PhantomData<fn(Dst)>,
}

/// Configures idle capacity and handling for maker futures that lose to reuse.
///
/// Without an executor, a maker that loses the race is canceled. Supplying an
/// executor allows useful work to finish in the background, while `max_idle`
/// bounds results that have no waiting checkout.
#[derive(Debug)]
pub(super) struct Builder<Ev> {
    /// Handler for a maker future that loses the checkout race.
    events: Ev,
    /// Maximum number of services retained without a waiter.
    max_idle: usize,
}

/// RAII checkout for one exclusive cached service.
///
/// The wrapper delegates the `Service` implementation to the inner service and
/// records whether it came from the idle cache. On drop, a healthy service is
/// handed to the oldest waiter or retained as idle. Readiness failures and
/// explicit discard requests prevent reinsertion.
///
/// Its weak cache reference allows a connection to be destroyed normally after
/// the owning map entry has been evicted.
pub(super) struct Cached<S> {
    /// Prevents a failed or explicitly discarded service from returning.
    discard: bool,
    /// Records whether this checkout came from the cache.
    reused: bool,
    /// Owned service, removed only while `Drop` returns it.
    inner: Option<S>,
    /// Weak reference avoids keeping an otherwise unused cache alive.
    shared: Weak<Mutex<Shared<S>>>,
    /// Shared active-checkout counter used by idle cleanup.
    active: Arc<AtomicUsize>,
    /// Prevents the active checkout from being released more than once.
    active_checkout: bool,
}

/// Readiness reservation owned by one [`Cache`] clone.
///
/// Keeping this state outside [`Shared`] prevents another clone from consuming
/// a service after this clone has reported readiness.
#[derive(Debug)]
enum Ready<S> {
    /// No reusable service is reserved.
    None,
    /// A service is reserved for the next `call` on this clone.
    Cached(S),
}

/// Future returned by a cache checkout.
///
/// `Racing` polls a FIFO reservation before the maker on every wake. If reuse
/// wins, started maker work is passed to the event policy. `Cached` owns a
/// service reserved during readiness and completes without touching shared
/// state again.
///
/// Dropping a racing future removes its waiter and reassigns any service that
/// was already reserved for it.
pub(super) enum CacheFuture<M, Dst, Ev>
where
    M: Service<Dst>,
{
    Racing {
        /// Cache state inspected for a returned service.
        shared: Arc<Mutex<Shared<M::Response>>>,
        /// FIFO reservation assigned to this checkout.
        waiter: WaiterId,
        /// Maker future racing the reuse reservation.
        future: Option<M::Future>,
        /// Handler used when reuse wins after the maker started.
        events: Ev,
        /// Shared active-checkout counter.
        active: Arc<AtomicUsize>,
    },
    Cached {
        /// Immediately available checked-out service.
        service: Option<Cached<M::Response>>,
    },
}

/// Shared idle services and FIFO checkout handoff state.
///
/// A returned service is first moved into `reservations` under this lock, then
/// its waiter's task is woken after the lock is released. Keeping queued waiters
/// separate from assigned reservations makes cancellation safe: canceling a
/// waiter either removes its queue entry or passes its assigned service onward.
///
/// The watch sender also gives background makers an active shutdown signal when
/// the final shared cache owner is dropped.
#[derive(Debug)]
pub(super) struct Shared<S> {
    /// Idle services not reserved for a waiter.
    services: Vec<S>,
    /// Checkouts waiting for a returned service.
    waiters: VecDeque<Waiter>,
    /// Services assigned to a specific waiter but not yet collected.
    reservations: Vec<(WaiterId, S)>,
    /// Wrapping identifier source; only live IDs need to be distinct.
    next_waiter: usize,
    /// Maximum idle services retained when no waiter exists.
    max_idle: usize,
    /// Closes when the cache state is dropped, canceling background makers.
    shutdown: watch::Sender<()>,
}

/// Identifier pairing a queued checkout with its reserved service.
///
/// IDs wrap explicitly. They are used only inside one cache and are discarded
/// when their waiter or reservation leaves [`Shared`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WaiterId(usize);

/// One pending checkout in FIFO order.
///
/// The latest task waker is stored while the waiter is queued. Once a service is
/// assigned, the waiter is removed from the queue and the service is addressed
/// by [`WaiterId`] in the reservation list.
#[derive(Debug)]
struct Waiter {
    /// Identifier used to store and recover its reservation.
    id: WaiterId,
    /// Latest task interested in this waiter.
    waker: Option<Waker>,
}

/// Values removed while canceling one cache waiter.
///
/// The waiter and rejected service are destroyed after releasing the cache
/// lock. A waker produced by reassigning an existing reservation is also woken
/// outside the lock.
struct CancelResult<S> {
    /// Queued waiter removed before it received a service.
    canceled: Option<Waiter>,
    /// Next waiter to wake after reservation handoff.
    wake: Option<Waker>,
    /// Service rejected by the idle limit during handoff.
    discarded: Option<S>,
}

impl<Ev> Builder<Ev> {
    /// Completes useful maker work in the supplied executor after reuse wins.
    pub(super) fn executor<E>(self, executor: E) -> Builder<events::WithExecutor<E>> {
        Builder {
            events: events::WithExecutor(executor),
            max_idle: self.max_idle,
        }
    }

    /// Sets the maximum number of unreserved idle services.
    pub(super) fn max_idle(mut self, max_idle: usize) -> Self {
        self.max_idle = max_idle;
        self
    }

    /// Builds a cache around `connector`.
    pub(super) fn build<M, Dst>(self, connector: M) -> Cache<M, Dst, Ev>
    where
        M: Service<Dst>,
    {
        let (shutdown, _) = watch::channel(());
        Cache {
            connector,
            events: self.events,
            ready: Ready::None,
            ready_waiter: None,
            shared: Arc::new(Mutex::new(Shared {
                services: Vec::new(),
                waiters: VecDeque::new(),
                reservations: Vec::new(),
                next_waiter: 0,
                max_idle: self.max_idle,
                shutdown,
            })),
            active: Arc::new(AtomicUsize::new(0)),
            _dst: PhantomData,
        }
    }
}

impl<M, Dst, Ev> Cache<M, Dst, Ev>
where
    M: Service<Dst>,
{
    /// Removes idle services that do not satisfy `predicate`.
    ///
    /// Active checkouts and waiter reservations are left untouched.
    pub(super) fn retain<F>(&mut self, mut predicate: F) -> Vec<M::Response>
    where
        F: FnMut(&mut M::Response) -> bool,
    {
        let discard_ready = match &mut self.ready {
            Ready::Cached(service) => !predicate(service),
            Ready::None => false,
        };
        let mut discarded = Vec::new();
        if discard_ready {
            if let Ready::Cached(service) = std::mem::replace(&mut self.ready, Ready::None) {
                discarded.push(service);
            }
        }
        discarded.extend(self.shared.lock().retain_services(predicate));
        discarded
    }

    /// Returns whether no ready, idle, reserved, waiting, or active work remains.
    pub(super) fn is_empty(&self) -> bool {
        matches!(self.ready, Ready::None) && self.active.load(Ordering::Acquire) == 0 && {
            let shared = self.shared.lock();
            shared.services.is_empty()
                && shared.reservations.is_empty()
                && shared.waiters.is_empty()
        }
    }

    /// Removes one matching idle service without creating a replacement.
    ///
    /// Waiter fairness takes priority, so this returns `None` while a waiter
    /// could consume the same service.
    pub(super) fn try_pop_idle_if<F>(&mut self, predicate: F) -> Option<M::Response>
    where
        F: Fn(&M::Response) -> bool,
    {
        if matches!(&self.ready, Ready::Cached(service) if predicate(service)) {
            if let Ready::Cached(service) = std::mem::replace(&mut self.ready, Ready::None) {
                return Some(service);
            }
        }

        self.shared.lock().take_available_if(predicate)
    }
}

impl<M, Dst, Ev> Service<Dst> for Cache<M, Dst, Ev>
where
    M: Service<Dst>,
    M::Future: Unpin,
    M::Response: Unpin,
    Ev: events::Events<BackgroundConnect<M::Future, M::Response>> + Clone + Unpin,
{
    type Response = Cached<M::Response>;
    type Error = M::Error;
    type Future = CacheFuture<M, Dst, Ev>;

    /// Reserves a returned service or waits until the maker can be called.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        if matches!(self.ready, Ready::Cached(_)) {
            return Poll::Ready(Ok(()));
        }

        let reserved = {
            let mut shared = self.shared.lock();
            if let Some(id) = self.ready_waiter {
                shared.take_reserved(id)
            } else {
                shared.take_available()
            }
        };
        if let Some(service) = reserved {
            self.ready_waiter = None;
            self.ready = Ready::Cached(service);
            return Poll::Ready(Ok(()));
        }

        match self.connector.poll_ready(cx) {
            Poll::Ready(result) => {
                if let Some(id) = self.ready_waiter.take() {
                    let result = self.shared.lock().cancel_waiter(id);
                    finish_cancel(result);
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                let (reserved, replaced_waker) = {
                    let mut shared = self.shared.lock();
                    if let Some(id) = self.ready_waiter {
                        let service = shared.take_reserved(id);
                        let replaced = if service.is_none() {
                            shared.store_waker(id, cx.waker())
                        } else {
                            None
                        };
                        (service, replaced)
                    } else if let Some(service) = shared.take_available() {
                        (Some(service), None)
                    } else {
                        let id = shared.push_waiter();
                        let replaced = shared.store_waker(id, cx.waker());
                        self.ready_waiter = Some(id);
                        (None, replaced)
                    }
                };
                drop(replaced_waker);

                if let Some(service) = reserved {
                    self.ready_waiter = None;
                    self.ready = Ready::Cached(service);
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    /// Checks out a reserved service or races reuse against a new service.
    fn call(&mut self, target: Dst) -> Self::Future {
        match std::mem::replace(&mut self.ready, Ready::None) {
            Ready::Cached(service) => {
                return CacheFuture::Cached {
                    service: Some(Cached::new(
                        service,
                        Arc::downgrade(&self.shared),
                        self.active.clone(),
                        true,
                    )),
                };
            }
            Ready::None => {
                if let Some(id) = self.ready_waiter.take() {
                    let mut shared = self.shared.lock();
                    if let Some(service) = shared.take_reserved(id) {
                        return CacheFuture::Cached {
                            service: Some(Cached::new(
                                service,
                                Arc::downgrade(&self.shared),
                                self.active.clone(),
                                true,
                            )),
                        };
                    }
                    let result = shared.cancel_waiter(id);
                    drop(shared);
                    finish_cancel(result);
                }
            }
        }

        let waiter = {
            let mut shared = self.shared.lock();
            if let Some(service) = shared.take_available() {
                drop(shared);
                return CacheFuture::Cached {
                    service: Some(Cached::new(
                        service,
                        Arc::downgrade(&self.shared),
                        self.active.clone(),
                        true,
                    )),
                };
            }
            shared.push_waiter()
        };
        CacheFuture::Racing {
            shared: self.shared.clone(),
            waiter,
            future: Some(self.connector.call(target)),
            events: self.events.clone(),
            active: self.active.clone(),
        }
    }
}

impl<M, Dst, Ev> Clone for Cache<M, Dst, Ev>
where
    M: Service<Dst> + Clone,
    Ev: Clone,
{
    /// Creates a handle with independent readiness and shared cache state.
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            shared: self.shared.clone(),
            events: self.events.clone(),
            ready: Ready::None,
            ready_waiter: None,
            active: self.active.clone(),
            _dst: PhantomData,
        }
    }
}

impl<M, Dst, Ev> Drop for Cache<M, Dst, Ev>
where
    M: Service<Dst>,
{
    /// Returns this clone's reservation and removes its pending waiter.
    fn drop(&mut self) {
        if let Ready::Cached(service) = std::mem::replace(&mut self.ready, Ready::None) {
            let result = self.shared.lock().put(service);
            finish_put(result);
        }
        if let Some(id) = self.ready_waiter.take() {
            let result = self.shared.lock().cancel_waiter(id);
            finish_cancel(result);
        }
    }
}

impl<M, Dst, Ev> Drop for CacheFuture<M, Dst, Ev>
where
    M: Service<Dst>,
{
    /// Cancels the FIFO waiter when the checkout future is abandoned.
    fn drop(&mut self) {
        if let Self::Racing { shared, waiter, .. } = self {
            let result = shared.lock().cancel_waiter(*waiter);
            finish_cancel(result);
        }
    }
}

impl<M, Dst, Ev> Future for CacheFuture<M, Dst, Ev>
where
    M: Service<Dst>,
    M::Future: Unpin,
    M::Response: Unpin,
    Ev: events::Events<BackgroundConnect<M::Future, M::Response>> + Unpin,
{
    type Output = Result<Cached<M::Response>, M::Error>;

    /// Polls reuse first, then the maker, preserving useful lost-race work.
    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Racing {
                shared,
                waiter,
                future,
                events,
                active,
            } => {
                let (reused, replaced_waker) = {
                    let mut locked = shared.lock();
                    if let Some(service) = locked.take_reserved(*waiter) {
                        let shutdown = cache_shutdown(locked.shutdown.subscribe());
                        let background = future.take().map(|future| BackgroundConnect {
                            future,
                            shared: Arc::downgrade(shared),
                            shutdown,
                        });
                        (Some((service, background)), None)
                    } else {
                        let replaced = locked.store_waker(*waiter, cx.waker());
                        (None, replaced)
                    }
                };
                drop(replaced_waker);

                if let Some((service, background)) = reused {
                    if let Some(background) = background {
                        events.on_race_lost(background);
                    }
                    return Poll::Ready(Ok(Cached::new(
                        service,
                        Arc::downgrade(shared),
                        active.clone(),
                        true,
                    )));
                }

                let Some(connecting) = future.as_mut() else {
                    return Poll::Pending;
                };
                let connected = match ready!(Pin::new(connecting).poll(cx)) {
                    Ok(service) => service,
                    Err(error) => {
                        let (reused, canceled) = {
                            let mut locked = shared.lock();
                            match locked.take_reserved(*waiter) {
                                Some(service) => (Some(service), None),
                                None => (None, Some(locked.cancel_waiter(*waiter))),
                            }
                        };
                        if let Some(canceled) = canceled {
                            finish_cancel(canceled);
                        }
                        if let Some(service) = reused {
                            return Poll::Ready(Ok(Cached::new(
                                service,
                                Arc::downgrade(shared),
                                active.clone(),
                                true,
                            )));
                        }
                        return Poll::Ready(Err(error));
                    }
                };

                let result = shared.lock().cancel_waiter(*waiter);
                finish_cancel(result);
                future.take();
                Poll::Ready(Ok(Cached::new(
                    connected,
                    Arc::downgrade(shared),
                    active.clone(),
                    false,
                )))
            }
            Self::Cached { service } => match service.take() {
                Some(service) => Poll::Ready(Ok(service)),
                None => Poll::Pending,
            },
        }
    }
}

impl<S> Cached<S> {
    /// Wraps a service and records its active checkout.
    fn new(
        inner: S,
        shared: Weak<Mutex<Shared<S>>>,
        active: Arc<AtomicUsize>,
        reused: bool,
    ) -> Self {
        let _ = active.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            Some(count.saturating_add(1))
        });
        Self {
            discard: false,
            reused,
            inner: Some(inner),
            shared,
            active,
            active_checkout: true,
        }
    }

    /// Borrows the checked-out service.
    pub(super) fn inner(&self) -> &S {
        self.inner
            .as_ref()
            .expect("cached service is present until drop")
    }

    /// Mutably borrows the checked-out service.
    pub(super) fn inner_mut(&mut self) -> &mut S {
        self.inner
            .as_mut()
            .expect("cached service is present until drop")
    }

    /// Marks the service to be dropped instead of returned to the cache.
    pub(super) fn discard_on_drop(&mut self) {
        self.discard = true;
    }

    /// Returns whether this checkout reused a cached service.
    pub(super) fn is_reused(&self) -> bool {
        self.reused
    }

    /// Releases this wrapper's active checkout exactly once.
    fn release_active(&mut self) {
        if std::mem::take(&mut self.active_checkout) {
            let _ = self
                .active
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    Some(count.saturating_sub(1))
                });
        }
    }

    /// Returns this service to a waiter or retains it when `predicate` allows.
    ///
    /// Waiter handoff and the retention decision share one cache lock. This
    /// closes the gap where external capacity reclamation could run just before
    /// a service became visible as idle. The result reports whether the service
    /// was handed off or retained.
    pub(super) fn return_to_cache_if<F>(&mut self, predicate: F) -> bool
    where
        F: FnOnce(&S) -> bool,
    {
        if self.discard {
            return false;
        }
        let Some(service) = self.inner.take() else {
            return false;
        };
        let Some(shared) = self.shared.upgrade() else {
            return false;
        };

        let result = {
            let mut shared = shared.lock();
            let result = shared.put_if(service, predicate);
            self.release_active();
            result
        };
        let returned = result.1.is_none();
        finish_put(result);
        returned
    }
}

impl<S, Req> Service<Req> for Cached<S>
where
    S: Service<Req>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    /// Delegates readiness and discards the service if readiness fails.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_mut().poll_ready(cx).map_err(|error| {
            self.discard = true;
            error
        })
    }

    /// Sends a request through the checked-out service.
    fn call(&mut self, req: Req) -> Self::Future {
        self.inner_mut().call(req)
    }
}

impl<S> Drop for Cached<S> {
    /// Returns a healthy service and closes its active checkout atomically.
    ///
    /// Both transitions share the cache lock so cleanup cannot remove the
    /// returned service while still observing this checkout as active.
    fn drop(&mut self) {
        let discarded = match self.inner.take() {
            Some(service) if !self.discard => match self.shared.upgrade() {
                Some(shared) => {
                    let result = {
                        let mut shared = shared.lock();
                        let result = shared.put(service);
                        self.release_active();
                        result
                    };
                    finish_put(result);
                    None
                }
                None => Some(service),
            },
            service => service,
        };
        drop(discarded);
        self.release_active();
    }
}

impl<S: fmt::Debug> fmt::Debug for Cached<S> {
    /// Formats the wrapped service without exposing cache bookkeeping.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Cached").field(&self.inner).finish()
    }
}

impl<S> Shared<S> {
    /// Removes services rejected by `predicate` and returns them for unlocked drop.
    fn retain_services<F>(&mut self, mut predicate: F) -> Vec<S>
    where
        F: FnMut(&mut S) -> bool,
    {
        let mut discarded = Vec::new();
        let mut index = 0;

        while index < self.services.len() {
            if predicate(&mut self.services[index]) {
                index += 1;
            } else {
                discarded.push(self.services.remove(index));
            }
        }

        discarded
    }

    /// Gives a returned service to the oldest waiter or stores it as idle.
    fn put(&mut self, service: S) -> (Option<Waker>, Option<S>) {
        self.put_if(service, |_| true)
    }

    /// Gives a service to the oldest waiter or conditionally stores it as idle.
    fn put_if<F>(&mut self, service: S, retain: F) -> (Option<Waker>, Option<S>)
    where
        F: FnOnce(&S) -> bool,
    {
        if let Some(mut waiter) = self.waiters.pop_front() {
            self.reservations.push((waiter.id, service));
            (waiter.waker.take(), None)
        } else if retain(&service) && self.services.len() < self.max_idle {
            self.services.push(service);
            (None, None)
        } else {
            (None, Some(service))
        }
    }

    /// Takes the newest idle service when no waiter has priority.
    fn take_available(&mut self) -> Option<S> {
        if self.waiters.is_empty() {
            self.services.pop()
        } else {
            None
        }
    }

    /// Takes one matching idle service when no waiter has priority.
    fn take_available_if<F>(&mut self, predicate: F) -> Option<S>
    where
        F: Fn(&S) -> bool,
    {
        if !self.waiters.is_empty() {
            return None;
        }

        let index = self.services.iter().rposition(predicate)?;
        Some(self.services.remove(index))
    }

    /// Appends a checkout to the FIFO waiter queue.
    fn push_waiter(&mut self) -> WaiterId {
        let id = WaiterId(self.next_waiter);
        self.next_waiter = self.next_waiter.wrapping_add(1);
        self.waiters.push_back(Waiter { id, waker: None });
        id
    }

    /// Stores the latest waker and returns the replaced value for unlocked drop.
    fn store_waker(&mut self, id: WaiterId, waker: &Waker) -> Option<Waker> {
        if let Some(waiter) = self.waiters.iter_mut().find(|waiter| waiter.id == id) {
            if waiter
                .waker
                .as_ref()
                .is_none_or(|current| !current.will_wake(waker))
            {
                return waiter.waker.replace(waker.clone());
            }
        }
        None
    }

    /// Takes the service reserved for `id`.
    fn take_reserved(&mut self, id: WaiterId) -> Option<S> {
        let index = self
            .reservations
            .iter()
            .position(|(reserved, _)| *reserved == id)?;
        Some(self.reservations.swap_remove(index).1)
    }

    /// Removes a waiter and reassigns any service already reserved for it.
    fn cancel_waiter(&mut self, id: WaiterId) -> CancelResult<S> {
        if let Some(index) = self.waiters.iter().position(|waiter| waiter.id == id) {
            CancelResult {
                canceled: self.waiters.remove(index),
                wake: None,
                discarded: None,
            }
        } else if let Some(service) = self.take_reserved(id) {
            let (wake, discarded) = self.put(service);
            CancelResult {
                canceled: None,
                wake,
                discarded,
            }
        } else {
            CancelResult {
                canceled: None,
                wake: None,
                discarded: None,
            }
        }
    }
}

/// Drops a rejected service and wakes its waiter after the cache lock is gone.
fn finish_put<S>((waker, discarded): (Option<Waker>, Option<S>)) {
    drop(discarded);
    if let Some(waker) = waker {
        waker.wake();
    }
}

/// Finishes waiter cancellation after the cache lock has been released.
fn finish_cancel<S>(result: CancelResult<S>) {
    drop(result.canceled);
    finish_put((result.wake, result.discarded));
}

/// Completes useful maker work after connection reuse wins the checkout race.
///
/// The future does not keep the cache alive. It exits when the cache shutdown
/// signal fires, and otherwise returns a successful result to the cache if the
/// shared state still exists. Connection errors are intentionally ignored
/// because another service already satisfied the checkout.
pub(super) struct BackgroundConnect<F, S> {
    /// Maker future that already began useful work.
    future: F,
    /// Destination cache, if it still exists when work completes.
    shared: Weak<Mutex<Shared<S>>>,
    /// Wakes the task when the destination cache is dropped.
    shutdown: BoxFuture<'static, ()>,
}

impl<F, S, E> Started for BackgroundConnect<F, S>
where
    F: Started + Future<Output = Result<S, E>> + Unpin,
{
    /// Delegates the started-work decision to the maker future.
    fn started(&self) -> bool {
        self.future.started()
    }
}

impl<F, S, E> Future for BackgroundConnect<F, S>
where
    F: Future<Output = Result<S, E>> + Unpin,
{
    type Output = ();

    /// Returns a successful background result to the cache.
    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        if self.shutdown.as_mut().poll(cx).is_ready() {
            return Poll::Ready(());
        }

        match ready!(Pin::new(&mut self.future).poll(cx)) {
            Ok(service) => {
                if let Some(shared) = self.shared.upgrade() {
                    let result = shared.lock().put(service);
                    finish_put(result);
                }
                Poll::Ready(())
            }
            Err(_) => Poll::Ready(()),
        }
    }
}

/// Waits until the cache-owned watch sender is dropped.
fn cache_shutdown(mut receiver: watch::Receiver<()>) -> BoxFuture<'static, ()> {
    Box::pin(async move {
        let _ = receiver.changed().await;
    })
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Context,
    };

    use super::*;

    /// Pending connection future that records every poll.
    struct CountingPending(Arc<AtomicUsize>);

    impl Future for CountingPending {
        type Output = Result<(), ()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    #[test]
    fn background_connect_stops_after_cache_is_dropped() {
        let polls = Arc::new(AtomicUsize::new(0));
        let shared = Arc::new(Mutex::new(Shared {
            services: Vec::new(),
            waiters: VecDeque::new(),
            reservations: Vec::new(),
            next_waiter: 0,
            max_idle: usize::MAX,
            shutdown: watch::channel(()).0,
        }));
        let shutdown = cache_shutdown(shared.lock().shutdown.subscribe());
        let mut connect = Box::pin(BackgroundConnect {
            future: CountingPending(polls.clone()),
            shared: Arc::downgrade(&shared),
            shutdown,
        });

        let mut task = tokio_test::task::spawn(connect.as_mut());
        assert!(task.poll().is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 1);

        drop(shared);

        assert!(task.is_woken());
        assert!(task.poll().is_ready());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn returned_service_prefers_a_waiter_over_idle_rejection() {
        let active = Arc::new(AtomicUsize::new(0));
        let shared = Arc::new(Mutex::new(Shared {
            services: Vec::new(),
            waiters: VecDeque::new(),
            reservations: Vec::new(),
            next_waiter: 0,
            max_idle: usize::MAX,
            shutdown: watch::channel(()).0,
        }));
        let waiter = shared.lock().push_waiter();
        let mut service = Cached::new(7, Arc::downgrade(&shared), active, false);

        service.return_to_cache_if(|_| false);

        assert_eq!(shared.lock().take_reserved(waiter), Some(7));
    }
}

/// Policies for maker futures that lose the reuse race.
pub(super) mod events {
    use super::Started;

    /// Policy that cancels maker futures after another service wins the race.
    ///
    /// This is useful when finishing the work would provide no value or when no
    /// executor is available for detached connection work.
    #[derive(Clone, Debug)]
    pub(in crate::client::layer::client::pool) struct Ignore;

    /// Policy that completes useful lost maker futures on an executor.
    ///
    /// Futures that have only waited for reuse or capacity are still canceled.
    /// Once physical connection work starts, the executor can finish it and put
    /// a successful service into the cache for a later checkout.
    #[derive(Clone, Debug)]
    pub(in crate::client::layer::client::pool) struct WithExecutor<E>(pub(super) E);

    /// Handles a maker future after connection reuse wins.
    pub(in crate::client::layer::client::pool) trait Events<F> {
        /// Receives the maker future that lost the race.
        fn on_race_lost(&self, future: F);
    }

    impl<F> Events<F> for Ignore {
        /// Drops the maker future immediately.
        fn on_race_lost(&self, _future: F) {}
    }

    impl<E, F> Events<F> for WithExecutor<E>
    where
        F: Started + Send + 'static,
        E: wreq_proto::rt::Executor<F>,
    {
        /// Spawns the maker only when it has started useful work.
        fn on_race_lost(&self, future: F) {
            if future.started() {
                self.0.execute(future);
            }
        }
    }
}
