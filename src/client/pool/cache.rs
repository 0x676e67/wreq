//! Races reusable services against newly created services.
//!
//! Manages exclusive services that handle one checkout at a time, such as HTTP/1 senders.
//! Each [`Cache`] clone owns an independent readiness reservation, while idle services,
//! FIFO waiters, and active counts are shared.
//!
//! # Checkout lifecycle
//!
//! 1. `poll_ready` reserves an idle service when available. Otherwise it polls the maker and
//!    registers a waiter if the maker is pending.
//! 2. `call` either returns the reserved service or races the waiter against a newly made service.
//! 3. [`Cached`] returns the service on drop unless readiness failed or the caller marked it for
//!    discard. The caller is responsible for protocol-specific health checks before return.
//!
//! Returned services go to the oldest waiter before entering the idle list. If reuse wins
//! after connection work has started, the configured event handler may finish that work in
//! the background and cache the result.

use std::{
    collections::VecDeque,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Weak},
    task::{self, Poll, Waker, ready},
};

use futures_util::future::BoxFuture;
use tokio::sync::watch;
use tower::Service;

use crate::{rt::Executor, sync::Mutex};

/// Reports whether a raced maker future has begun work worth completing.
///
/// Cache policy waits can be canceled cheaply. Physical connection work may
/// already own resources, so the event handler uses this signal before deciding
/// whether to continue a lost race in the background.
pub trait Started: Future {
    /// Returns `true` after canceling the future would waste started work.
    #[must_use]
    fn started(&self) -> bool;
}

/// Starts configuring a cache around a service maker.
#[must_use]
pub(super) fn builder() -> Builder<events::Ignore> {
    Builder {
        events: events::Ignore,
        max_idle: usize::MAX,
    }
}

/// A cloneable cache of exclusive services produced by `M`.
///
/// Each clone reserves at most one service during `poll_ready`, and only its next `call`
/// consumes that reservation, preserving Tower's readiness contract under concurrent use.
///
/// [`Shared`] owns idle services and FIFO handoff state. Checked-out services and
/// background makers hold only weak references to it so they never keep an unused cache
/// alive; dropping the last shared owner also signals background makers to stop.
#[derive(Debug)]
pub(super) struct Cache<M, Dst, Ev, G>
where
    M: Service<Dst>,
    G: AsMut<Shared<M::Response>>,
{
    /// Underlying maker polled and called on a cache miss.
    maker: M,
    /// Shared per-group lock containing [`Shared`] idle connections, waiters, and active count.
    shared: Arc<Mutex<G>>,
    /// Policy handling maker futures that lose the reuse race.
    events: Ev,
    /// Idle service reserved for this clone's next `call`; drop releases the reservation.
    ready: Option<Cached<M::Response, G>>,
    /// Waiter registered while this clone's `poll_ready` is pending.
    ready_waiter: Option<WaiterId>,
    /// Destination type marker.
    _dst: PhantomData<fn(Dst)>,
}

/// Configures idle capacity and handling for maker futures that lose to reuse.
///
/// Without a runtime, a maker that loses the race is canceled. Supplying a
/// runtime allows useful work to finish in the background, while `max_idle`
/// bounds results that have no waiting checkout.
#[derive(Debug)]
pub(super) struct Builder<Ev> {
    /// Policy for maker futures that lose to reuse.
    events: Ev,
    /// Maximum unreserved idle services kept in the cache.
    max_idle: usize,
}

/// RAII handle for a checked-out exclusive service.
///
/// Returns the service to the oldest waiter or idle list on drop unless readiness failed
/// or [`Cached::discard_on_drop`] was called. Protocol health checks are left to the
/// caller; a weak cache reference lets the service outlive its pool entry.
#[derive(Debug)]
pub(super) struct Cached<S, G: AsMut<Shared<S>>> {
    /// Prevents returning the service after readiness failure or explicit discard.
    discard: bool,
    /// Whether this checkout reused an existing cached service.
    reused: bool,
    /// Owned service, taken on explicit return or drop.
    inner: Option<S>,
    /// Weak cache handle so an active checkout never keeps an unused cache alive.
    shared: Weak<Mutex<G>>,
}

/// Future returned by a cache checkout.
///
/// `Racing` polls a FIFO reservation before the maker on every wake, handing started maker
/// work to the event policy if reuse wins; dropping it cancels its waiter and reassigns
/// any reserved service. `Cached` yields a service already reserved during readiness.
pub(super) enum CacheFuture<M, Dst, Ev, G>
where
    M: Service<Dst>,
    G: AsMut<Shared<M::Response>>,
{
    Racing {
        /// Shared cache state checked for a reserved return on each poll.
        shared: Arc<Mutex<G>>,
        /// FIFO waiter ID assigned to this racing checkout.
        waiter: WaiterId,
        /// In-flight maker future racing against reuse.
        future: Option<M::Future>,
        /// Policy invoked if reuse wins after the maker started.
        events: Ev,
    },
    Cached {
        /// Service already reserved during `poll_ready`.
        service: Option<Cached<M::Response, G>>,
    },
}

/// Shared idle services and FIFO checkout handoff state.
///
/// Returned services move into `reservations` under this lock, and the waiter's task is
/// woken after unlocking. Keeping queued waiters separate from assigned reservations makes
/// cancellation safe: canceling a waiter removes its queue entry or hands off its service.
///
/// Dropping the final shared owner closes `shutdown`, canceling background maker work.
#[derive(Debug)]
pub(super) struct Shared<S> {
    /// Unreserved idle services reused in LIFO order.
    idle: Vec<S>,
    /// Pending checkouts waiting for a returned service in FIFO order.
    waiters: VecDeque<Waiter>,
    /// Returned services already assigned to a specific waiter.
    reservations: Vec<(WaiterId, S)>,
    /// Wrapping ID counter; only live waiter IDs need to be unique.
    next_waiter: usize,
    /// Maximum idle services retained when no waiter is queued.
    max_idle: usize,
    /// Reserved or checked-out services and background connects keeping the entry non-empty.
    active: usize,
    /// Initialized by [`Builder::build_in`] and closed on drop to stop background connects.
    shutdown: Option<watch::Sender<()>>,
}

/// Wrapping identifier pairing a queued checkout with its reserved service.
///
/// Scoped to a single [`Shared`] cache and discarded once its waiter or reservation leaves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WaiterId(usize);

/// Queued checkout waiting in FIFO order for a returned service.
///
/// Stores the latest task waker until a service is assigned, at which point the waiter
/// leaves the queue and its service is tracked by [`WaiterId`] in `reservations`.
#[derive(Debug)]
struct Waiter {
    /// Identifier matching this waiter's eventual reservation.
    id: WaiterId,
    /// Latest waker registered by the waiting task.
    waker: Option<Waker>,
}

/// Detached state returned when canceling a waiter so drops and wakeups run unlocked.
///
/// Holds the removed waiter, any next waiter to wake after reassigning a reservation,
/// and any service rejected by `max_idle`.
struct CancelResult<S> {
    /// Queued waiter removed before receiving a service.
    canceled: Option<Waiter>,
    /// Next waiter to wake after a reserved service was reassigned.
    wake: Option<Waker>,
    /// Service dropped if `max_idle` rejected the reassigned reservation.
    discarded: Option<S>,
}

// ===== impl Builder =====

impl<Ev> Builder<Ev> {
    /// Completes useful maker work on the supplied runtime after reuse wins.
    #[must_use]
    pub(super) fn runtime<R: Executor>(self, runtime: R) -> Builder<events::WithRuntime<R>> {
        Builder {
            events: events::WithRuntime {
                runtime,
                on_complete: None,
            },
            max_idle: self.max_idle,
        }
    }

    /// Sets the maximum number of unreserved idle services.
    #[must_use]
    pub(super) fn max_idle(mut self, max_idle: usize) -> Self {
        self.max_idle = max_idle;
        self
    }

    /// Builds a cache using the idle state owned by this pool group.
    #[must_use]
    pub(super) fn build_in<M, Dst, G>(self, maker: M, shared: Arc<Mutex<G>>) -> Cache<M, Dst, Ev, G>
    where
        M: Service<Dst>,
        G: AsMut<Shared<M::Response>>,
    {
        {
            let mut state = shared.lock();
            let cache = state.as_mut();
            cache.max_idle = self.max_idle;
            cache.shutdown = Some(watch::channel(()).0);
        }
        Cache {
            maker,
            events: self.events,
            ready: None,
            ready_waiter: None,
            shared,
            _dst: PhantomData,
        }
    }
}

impl<R> Builder<events::WithRuntime<R>> {
    /// Runs `callback` after useful lost maker work finishes.
    #[must_use]
    pub(super) fn on_background_complete<F>(mut self, callback: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.events.on_complete = Some(Arc::new(callback));
        self
    }
}

// ===== impl Cache =====

impl<M, Dst, Ev, G> Cache<M, Dst, Ev, G>
where
    M: Service<Dst>,
    G: AsMut<Shared<M::Response>>,
{
    /// Borrows the state lock shared by the pools for this entry.
    #[must_use]
    pub(super) fn shared(&self) -> &Mutex<G> {
        &self.shared
    }

    /// Takes the newest unreserved idle service while the caller holds the group lock.
    ///
    /// Inspects only the LIFO candidate at the back of `idle`; if it is not reusable,
    /// returns `None` so the regular checkout path prunes stale connections.
    #[must_use]
    pub(super) fn checkout_idle(
        &self,
        shared: &mut Shared<M::Response>,
        reusable: impl FnOnce(&M::Response) -> bool,
    ) -> Option<Cached<M::Response, G>> {
        if !shared.waiters.is_empty() || !shared.idle.last().is_some_and(reusable) {
            return None;
        }
        shared
            .idle
            .pop()
            .map(|service| Cached::new(service, &self.shared, shared, true))
    }

    /// Removes rejected unreserved services without touching clone-local readiness.
    #[must_use]
    pub(super) fn retain_idle(
        &self,
        predicate: impl FnMut(&mut M::Response) -> bool,
    ) -> Vec<M::Response> {
        self.shared.lock().as_mut().retain_idle(predicate)
    }

    /// Removes all unreserved idle services for unlocked drop.
    #[must_use]
    pub(super) fn drain_idle(&self) -> Vec<M::Response> {
        self.shared.lock().as_mut().drain_idle()
    }

    /// Returns whether shared idle state or this clone holds a ready service.
    #[must_use]
    pub(super) fn has_idle(&self) -> bool {
        self.ready.is_some() || self.shared.lock().as_mut().has_idle()
    }

    /// Returns whether no ready, idle, reserved, waiting, or active work remains.
    #[must_use]
    pub(super) fn is_empty(&self) -> bool {
        self.shared.lock().as_mut().is_empty()
    }
}

impl<M, Dst, Ev, G> Service<Dst> for Cache<M, Dst, Ev, G>
where
    M: Service<Dst>,
    G: AsMut<Shared<M::Response>>,
    M::Future: Unpin,
    M::Response: Unpin,
    Ev: events::Events<BackgroundConnect<M::Future, M::Response, G>> + Clone + Unpin,
{
    type Response = Cached<M::Response, G>;
    type Error = M::Error;
    type Future = CacheFuture<M, Dst, Ev, G>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.ready.is_some() {
            return Poll::Ready(Ok(()));
        }

        let reserved = {
            let mut guard = self.shared.lock();
            let shared = guard.as_mut();
            let service = if let Some(id) = self.ready_waiter {
                shared.take_reserved(id)
            } else {
                shared.take_available()
            };
            service.map(|service| Cached::new(service, &self.shared, shared, true))
        };
        if let Some(service) = reserved {
            self.ready_waiter = None;
            self.ready = Some(service);
            return Poll::Ready(Ok(()));
        }

        match self.maker.poll_ready(cx) {
            Poll::Ready(result) => {
                if let Some(id) = self.ready_waiter.take() {
                    let result = self.shared.lock().as_mut().cancel_waiter(id);
                    finish_cancel(result);
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                let mut guard = self.shared.lock();
                let shared = guard.as_mut();
                let (reserved, replaced_waker) = if let Some(id) = self.ready_waiter {
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
                };
                let reserved =
                    reserved.map(|service| Cached::new(service, &self.shared, shared, true));
                drop(guard);
                drop(replaced_waker);

                if let Some(service) = reserved {
                    self.ready_waiter = None;
                    self.ready = Some(service);
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn call(&mut self, target: Dst) -> Self::Future {
        if let Some(service) = self.ready.take() {
            return CacheFuture::Cached {
                service: Some(service),
            };
        }

        if let Some(id) = self.ready_waiter.take() {
            let reserved = {
                let mut guard = self.shared.lock();
                let shared = guard.as_mut();
                match shared.take_reserved(id) {
                    Some(service) => Ok(Cached::new(service, &self.shared, shared, true)),
                    None => Err(shared.cancel_waiter(id)),
                }
            };
            match reserved {
                Ok(service) => {
                    return CacheFuture::Cached {
                        service: Some(service),
                    };
                }
                Err(result) => finish_cancel(result),
            }
        }

        let available = {
            let mut guard = self.shared.lock();
            let shared = guard.as_mut();
            match shared.take_available() {
                Some(service) => Ok(Cached::new(service, &self.shared, shared, true)),
                None => Err(shared.push_waiter()),
            }
        };

        let waiter = match available {
            Ok(service) => {
                return CacheFuture::Cached {
                    service: Some(service),
                };
            }
            Err(waiter) => waiter,
        };
        CacheFuture::Racing {
            shared: self.shared.clone(),
            waiter,
            future: Some(self.maker.call(target)),
            events: self.events.clone(),
        }
    }
}

impl<M, Dst, Ev, G> Clone for Cache<M, Dst, Ev, G>
where
    M: Service<Dst> + Clone,
    G: AsMut<Shared<M::Response>>,
    Ev: Clone,
{
    fn clone(&self) -> Self {
        Self {
            maker: self.maker.clone(),
            shared: self.shared.clone(),
            events: self.events.clone(),
            ready: None,
            ready_waiter: None,
            _dst: PhantomData,
        }
    }
}

impl<M, Dst, Ev, G> Drop for Cache<M, Dst, Ev, G>
where
    M: Service<Dst>,
    G: AsMut<Shared<M::Response>>,
{
    fn drop(&mut self) {
        drop(self.ready.take());
        if let Some(id) = self.ready_waiter.take() {
            let result = self.shared.lock().as_mut().cancel_waiter(id);
            finish_cancel(result);
        }
    }
}

// ===== impl CacheFuture =====

impl<M, Dst, Ev, G> Drop for CacheFuture<M, Dst, Ev, G>
where
    M: Service<Dst>,
    G: AsMut<Shared<M::Response>>,
{
    fn drop(&mut self) {
        if let Self::Racing { shared, waiter, .. } = self {
            let result = shared.lock().as_mut().cancel_waiter(*waiter);
            finish_cancel(result);
        }
    }
}

impl<M, Dst, Ev, G> Future for CacheFuture<M, Dst, Ev, G>
where
    M: Service<Dst>,
    G: AsMut<Shared<M::Response>>,
    M::Future: Unpin,
    M::Response: Unpin,
    Ev: events::Events<BackgroundConnect<M::Future, M::Response, G>> + Unpin,
{
    type Output = Result<Cached<M::Response, G>, M::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Racing {
                shared,
                waiter,
                future,
                events,
            } => {
                let mut guard = shared.lock();
                let locked = guard.as_mut();
                let (reused, replaced_waker) = if let Some(service) = locked.take_reserved(*waiter)
                {
                    let background = locked.shutdown.as_ref().and_then(|shutdown| {
                        let future = future.take()?;
                        let shutdown = cache_shutdown(shutdown.subscribe());
                        locked.active += 1;
                        Some(BackgroundConnect {
                            future,
                            shared: Arc::downgrade(shared),
                            shutdown,
                            _service: PhantomData,
                        })
                    });
                    let service = Cached::new(service, shared, locked, true);
                    (Some((service, background)), None)
                } else {
                    let replaced = locked.store_waker(*waiter, cx.waker());
                    (None, replaced)
                };
                drop(guard);
                drop(replaced_waker);

                if let Some((service, background)) = reused {
                    if let Some(background) = background {
                        events.on_race_lost(background);
                    }
                    return Poll::Ready(Ok(service));
                }

                let Some(connecting) = future.as_mut() else {
                    return Poll::Pending;
                };

                let connected = match ready!(Pin::new(connecting).poll(cx)) {
                    Ok(service) => service,
                    Err(error) => {
                        // A returned service may have been reserved while the dial failed;
                        // prefer reuse over surfacing the dial error.
                        let reserved = {
                            let mut guard = shared.lock();
                            let locked = guard.as_mut();
                            match locked.take_reserved(*waiter) {
                                Some(service) => Ok(Cached::new(service, shared, locked, true)),
                                None => Err(locked.cancel_waiter(*waiter)),
                            }
                        };
                        return Poll::Ready(match reserved {
                            Ok(service) => Ok(service),
                            Err(canceled) => {
                                finish_cancel(canceled);
                                Err(error)
                            }
                        });
                    }
                };

                let (service, result) = {
                    let mut guard = shared.lock();
                    let locked = guard.as_mut();
                    let service = Cached::new(connected, shared, locked, false);
                    (service, locked.cancel_waiter(*waiter))
                };
                finish_cancel(result);
                future.take();
                Poll::Ready(Ok(service))
            }
            Self::Cached { service } => match service.take() {
                Some(service) => Poll::Ready(Ok(service)),
                None => Poll::Pending,
            },
        }
    }
}

// ===== impl Cached =====

impl<S, G: AsMut<Shared<S>>> Cached<S, G> {
    /// Wraps a service and records its active checkout.
    #[must_use]
    fn new(inner: S, shared: &Arc<Mutex<G>>, state: &mut Shared<S>, reused: bool) -> Self {
        state.active += 1;
        Self {
            discard: false,
            reused,
            inner: Some(inner),
            shared: Arc::downgrade(shared),
        }
    }

    /// Borrows the checked-out service.
    #[must_use]
    pub(super) fn inner(&self) -> &S {
        self.inner
            .as_ref()
            .expect("cached service is present until drop")
    }

    /// Mutably borrows the checked-out service.
    #[must_use]
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
    #[must_use]
    pub(super) fn is_reused(&self) -> bool {
        self.reused
    }

    /// Releases the checkout, returning a healthy service to a waiter or the idle list.
    ///
    /// The result reports whether the service was handed off or retained.
    #[must_use]
    pub(super) fn return_to_cache(&mut self) -> bool {
        let Some(service) = self.inner.take() else {
            return false;
        };
        let Some(shared) = self.shared.upgrade() else {
            return false;
        };

        let result = {
            let mut guard = shared.lock();
            let shared = guard.as_mut();
            shared.active -= 1;
            if self.discard {
                (None, Some(service))
            } else {
                shared.put(service)
            }
        };
        let returned = result.1.is_none();
        finish_put(result);
        returned
    }
}

impl<S, G, Req> Service<Req> for Cached<S, G>
where
    S: Service<Req>,
    G: AsMut<Shared<S>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    #[inline]
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_mut().poll_ready(cx).map_err(|error| {
            self.discard_on_drop();
            error
        })
    }

    #[inline]
    fn call(&mut self, req: Req) -> Self::Future {
        self.inner_mut().call(req)
    }
}

impl<S, G: AsMut<Shared<S>>> Drop for Cached<S, G> {
    fn drop(&mut self) {
        let _ = self.return_to_cache();
    }
}

// ===== impl Shared =====

impl<S> Default for Shared<S> {
    fn default() -> Self {
        Self {
            idle: Vec::new(),
            waiters: VecDeque::new(),
            reservations: Vec::new(),
            next_waiter: 0,
            max_idle: 0,
            active: 0,
            shutdown: None,
        }
    }
}

impl<S> Shared<S> {
    /// Returns whether the cache has no services, waiters, or active work.
    #[must_use]
    pub(super) fn is_empty(&self) -> bool {
        self.active == 0
            && self.idle.is_empty()
            && self.reservations.is_empty()
            && self.waiters.is_empty()
    }

    /// Returns whether an unreserved idle service remains.
    #[must_use]
    pub(super) fn has_idle(&self) -> bool {
        !self.idle.is_empty()
    }

    /// Removes services rejected by `predicate` and returns them for unlocked drop.
    #[must_use]
    pub(super) fn retain_idle<F>(&mut self, mut predicate: F) -> Vec<S>
    where
        F: FnMut(&mut S) -> bool,
    {
        self.idle
            .extract_if(.., |service| !predicate(service))
            .collect()
    }

    /// Removes every unreserved idle service.
    #[must_use]
    pub(super) fn drain_idle(&mut self) -> Vec<S> {
        std::mem::take(&mut self.idle)
    }

    /// Gives a returned service to the oldest waiter or stores it as idle.
    #[must_use]
    fn put(&mut self, service: S) -> (Option<Waker>, Option<S>) {
        if let Some(mut waiter) = self.waiters.pop_front() {
            self.reservations.push((waiter.id, service));
            (waiter.waker.take(), None)
        } else if self.idle.len() < self.max_idle {
            self.idle.push(service);
            (None, None)
        } else {
            (None, Some(service))
        }
    }

    /// Takes the newest idle service when no waiter has priority.
    #[must_use]
    fn take_available(&mut self) -> Option<S> {
        if self.waiters.is_empty() {
            self.idle.pop()
        } else {
            None
        }
    }

    /// Appends a checkout to the FIFO waiter queue.
    #[must_use]
    fn push_waiter(&mut self) -> WaiterId {
        let id = WaiterId(self.next_waiter);
        self.next_waiter = self.next_waiter.wrapping_add(1);
        self.waiters.push_back(Waiter { id, waker: None });
        id
    }

    /// Stores the latest waker and returns the replaced value for unlocked drop.
    #[must_use]
    fn store_waker(&mut self, id: WaiterId, waker: &Waker) -> Option<Waker> {
        if let Some(waiter) = self.waiters.iter_mut().find(|waiter| waiter.id == id)
            && waiter
                .waker
                .as_ref()
                .is_none_or(|current| !current.will_wake(waker))
        {
            return waiter.waker.replace(waker.clone());
        }
        None
    }

    /// Takes the service reserved for `id`.
    #[must_use]
    fn take_reserved(&mut self, id: WaiterId) -> Option<S> {
        let index = self
            .reservations
            .iter()
            .position(|(reserved, _)| *reserved == id)?;
        Some(self.reservations.swap_remove(index).1)
    }

    /// Removes a waiter and reassigns any service already reserved for it.
    #[must_use]
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
/// Holds only a weak cache reference and exits immediately on cache shutdown; otherwise
/// caches a successful service while ignoring errors since reuse already satisfied the
/// checkout. Counts against `active` until dropped so entry cleanup does not drop it.
pub(super) struct BackgroundConnect<F, S, G: AsMut<Shared<S>>> {
    /// Started maker future finishing in the background.
    future: F,
    /// Weak cache handle receiving the completed service if still alive.
    shared: Weak<Mutex<G>>,
    /// Resolves when the cache drops so background work stops promptly.
    shutdown: BoxFuture<'static, ()>,
    /// Produced service type for projecting the cache state from `G`.
    _service: PhantomData<fn() -> S>,
}

// ===== impl BackgroundConnect =====

impl<F, S, G: AsMut<Shared<S>>> Drop for BackgroundConnect<F, S, G> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            shared.lock().as_mut().active -= 1;
        }
    }
}

impl<F, S, E, G> Started for BackgroundConnect<F, S, G>
where
    F: Started + Future<Output = Result<S, E>> + Unpin,
    G: AsMut<Shared<S>>,
{
    fn started(&self) -> bool {
        self.future.started()
    }
}

impl<F, S, E, G> Future for BackgroundConnect<F, S, G>
where
    F: Future<Output = Result<S, E>> + Unpin,
    G: AsMut<Shared<S>>,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        if self.shutdown.as_mut().poll(cx).is_ready() {
            return Poll::Ready(());
        }

        if let Ok(service) = ready!(Pin::new(&mut self.future).poll(cx))
            && let Some(shared) = self.shared.upgrade()
        {
            let result = shared.lock().as_mut().put(service);
            finish_put(result);
        }
        Poll::Ready(())
    }
}

/// Waits until the cache-owned watch sender is dropped.
fn cache_shutdown(mut receiver: watch::Receiver<()>) -> BoxFuture<'static, ()> {
    Box::pin(async move {
        let _ = receiver.changed().await;
    })
}

/// Policies for maker futures that lose the reuse race.
pub(super) mod events {
    use std::sync::Arc;

    use super::{Executor, Started};

    /// Policy that cancels maker futures after another service wins the race.
    ///
    /// This is useful when finishing the work would provide no value or when no
    /// runtime is available for detached connection work.
    #[derive(Clone, Debug)]
    pub struct Ignore;

    /// Policy that completes started lost maker futures on a runtime.
    ///
    /// Futures that have only waited for reuse are still canceled; once physical
    /// connection work has started, the runtime finishes it and caches a successful
    /// service for a later checkout.
    #[derive(Clone)]
    pub struct WithRuntime<R> {
        /// Runtime executing detached background connects.
        pub(super) runtime: R,
        /// Optional entry maintenance callback run after the background task finishes.
        pub(super) on_complete: Option<Arc<dyn Fn() + Send + Sync>>,
    }

    /// Handles a maker future after connection reuse wins.
    pub trait Events<F> {
        /// Receives the maker future that lost the race.
        fn on_race_lost(&self, future: F);
    }

    // ===== impl Ignore =====

    impl<F> Events<F> for Ignore {
        fn on_race_lost(&self, _future: F) {}
    }

    // ===== impl WithRuntime =====

    // Neither the runtime nor the callback is ever pinned by the cache future.
    impl<R> Unpin for WithRuntime<R> {}

    impl<F, R> Events<F> for WithRuntime<R>
    where
        F: Started<Output = ()> + Send + 'static,
        R: Executor,
    {
        fn on_race_lost(&self, future: F) {
            if future.started() {
                let on_complete = self.on_complete.clone();
                self.runtime.execute(Box::pin(async move {
                    future.await;
                    if let Some(on_complete) = on_complete {
                        on_complete();
                    }
                }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
    };

    use super::*;

    impl<S> AsMut<Self> for Shared<S> {
        fn as_mut(&mut self) -> &mut Self {
            self
        }
    }

    impl<Ev> Builder<Ev> {
        #[must_use]
        fn build<M, Dst>(self, maker: M) -> Cache<M, Dst, Ev, Shared<M::Response>>
        where
            M: Service<Dst>,
        {
            self.build_in(maker, Arc::new(Mutex::new(Shared::default())))
        }
    }

    impl<M, Dst, Ev> Cache<M, Dst, Ev, Shared<M::Response>>
    where
        M: Service<Dst>,
    {
        /// Removes rejected idle services and this clone's readiness reservation.
        #[must_use]
        fn retain<F>(&mut self, mut predicate: F) -> Vec<M::Response>
        where
            F: FnMut(&mut M::Response) -> bool,
        {
            let discard_ready = self
                .ready
                .as_mut()
                .is_some_and(|service| !predicate(service.inner_mut()));
            let mut shared = self.shared.lock();
            let mut discarded = shared.retain_idle(predicate);
            if discard_ready
                && let Some(mut service) = self.ready.take()
                && let Some(inner) = service.inner.take()
            {
                shared.active -= 1;
                discarded.push(inner);
            }
            discarded
        }
    }

    /// Pending future that counts polls to verify shutdown stops polling.
    struct CountingPending(Arc<AtomicUsize>);

    impl Future for CountingPending {
        type Output = Result<(), ()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    /// Produces one service immediately, then leaves subsequent calls pending.
    #[derive(Clone, Default)]
    struct QueueConnector {
        calls: Arc<AtomicUsize>,
        allow_ready: Arc<AtomicBool>,
    }

    impl Service<usize> for QueueConnector {
        type Response = usize;
        type Error = !;
        type Future = futures_util::future::Either<
            std::future::Ready<Result<usize, Self::Error>>,
            std::future::Pending<Result<usize, Self::Error>>,
        >;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.allow_ready.load(Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn call(&mut self, _target: usize) -> Self::Future {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                futures_util::future::Either::Left(std::future::ready(Ok(0)))
            } else {
                futures_util::future::Either::Right(std::future::pending())
            }
        }
    }

    /// Records whether a task waker was triggered.
    struct WakeFlag(AtomicBool);

    impl Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Enforces `poll_ready` before every `call` on each clone independently.
    #[derive(Default)]
    struct StrictConnector {
        poll_ready_count: Arc<AtomicUsize>,
        next: Arc<AtomicUsize>,
        calls: Arc<std::sync::Mutex<Vec<usize>>>,
        ready: bool,
    }

    impl Clone for StrictConnector {
        fn clone(&self) -> Self {
            Self {
                poll_ready_count: self.poll_ready_count.clone(),
                next: self.next.clone(),
                calls: self.calls.clone(),
                ready: false,
            }
        }
    }

    impl Service<usize> for StrictConnector {
        type Response = usize;
        type Error = !;
        type Future = std::future::Ready<Result<usize, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.ready = true;
            self.poll_ready_count.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, target: usize) -> Self::Future {
            assert!(self.ready, "connector called without readiness");
            self.ready = false;
            self.calls.lock().unwrap().push(target);
            std::future::ready(Ok(self.next.fetch_add(1, Ordering::SeqCst)))
        }
    }

    #[test]
    fn background_connect_stops_after_cache_is_dropped() {
        let polls = Arc::new(AtomicUsize::new(0));
        let shared = Arc::new(Mutex::new(Shared {
            max_idle: usize::MAX,
            active: 1,
            shutdown: Some(watch::channel(()).0),
            ..Shared::default()
        }));
        let shutdown = cache_shutdown(shared.lock().shutdown.as_ref().unwrap().subscribe());
        let mut connect = std::pin::pin!(BackgroundConnect {
            future: CountingPending(polls.clone()),
            shared: Arc::downgrade(&shared),
            shutdown,
            _service: PhantomData,
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
    fn returned_service_prefers_a_waiter() {
        for max_idle in [0, 1, 2] {
            let shared = Arc::new(Mutex::new(Shared {
                max_idle,
                ..Shared::default()
            }));
            let waiter = shared.lock().push_waiter();
            let mut service = Cached::new(7, &shared, &mut shared.lock(), false);

            assert!(service.return_to_cache());
            assert_eq!(shared.lock().take_reserved(waiter), Some(7));
            drop(service);

            // Retention limits must not prevent waiter handoff or leak active counts.
            for value in 0..3 {
                let service = Cached::new(value, &shared, &mut shared.lock(), false);
                drop(service);
            }
            let mut service = Cached::new(99, &shared, &mut shared.lock(), false);
            service.discard_on_drop();
            drop(service);
            let state = shared.lock();
            assert_eq!(state.idle.len(), max_idle);
            assert_eq!(state.active, 0);
        }
    }

    #[tokio::test]
    async fn reuse_is_fifo_and_skips_canceled_waiters() {
        let connector = QueueConnector::default();
        connector.allow_ready.store(true, Ordering::SeqCst);
        let mut cache = builder().build(connector.clone());
        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        let held = cache.call(0).await.unwrap();

        connector.allow_ready.store(false, Ordering::SeqCst);
        let wake = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = Waker::from(wake.clone());
        let mut wake_cx = Context::from_waker(&waker);
        let mut ready = Box::pin(std::future::poll_fn(|cx| cache.poll_ready(cx)));
        assert!(ready.as_mut().poll(&mut wake_cx).is_pending());

        drop(held);
        assert!(wake.0.load(Ordering::SeqCst));
        std::assert_matches!(ready.as_mut().poll(&mut wake_cx), Poll::Ready(Ok(())));
        drop(ready);
        let held = cache.call(0).await.unwrap();

        connector.allow_ready.store(true, Ordering::SeqCst);
        let mut cx = Context::from_waker(Waker::noop());
        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        let mut first = std::pin::pin!(cache.call(1));
        assert!(first.as_mut().poll(&mut cx).is_pending());

        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        let mut canceled = Box::pin(cache.call(2));
        assert!(canceled.as_mut().poll(&mut cx).is_pending());

        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        let mut third = std::pin::pin!(cache.call(3));
        assert!(third.as_mut().poll(&mut cx).is_pending());
        drop(canceled);

        drop(held);
        let Poll::Ready(Ok(first_service)) = first.as_mut().poll(&mut cx) else {
            panic!("oldest live waiter should receive the returned service");
        };
        assert_eq!(*first_service.inner(), 0);
        assert!(third.as_mut().poll(&mut cx).is_pending());

        drop(first_service);
        let Poll::Ready(Ok(third_service)) = third.as_mut().poll(&mut cx) else {
            panic!("canceled waiter should not block the next live waiter");
        };
        assert_eq!(*third_service.inner(), 0);
        drop(third_service);

        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        assert!(cache.call(4).await.unwrap().is_reused());
    }

    #[tokio::test]
    async fn clone_readiness_reserves_returns_and_retains_services() {
        let connector = StrictConnector::default();
        let poll_ready_count = connector.poll_ready_count.clone();
        let calls = connector.calls.clone();
        let mut cache = builder().build(connector);

        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        let service = cache.call(1).await.unwrap();
        assert_eq!(*service.inner(), 0);
        drop(service);

        let mut first = cache.clone();
        let mut second = cache.clone();
        std::future::poll_fn(|cx| first.poll_ready(cx))
            .await
            .unwrap();
        assert_eq!(poll_ready_count.load(Ordering::SeqCst), 1);
        std::future::poll_fn(|cx| second.poll_ready(cx))
            .await
            .unwrap();
        assert_eq!(poll_ready_count.load(Ordering::SeqCst), 2);

        let first_service = first.call(10).await.unwrap();
        let second_service = second.call(20).await.unwrap();
        assert_eq!(*first_service.inner(), 0);
        assert_eq!(*second_service.inner(), 1);
        assert_eq!(*calls.lock().unwrap(), vec![1, 20]);
        drop(first_service);
        drop(second_service);

        let mut reserved = cache.clone();
        std::future::poll_fn(|cx| reserved.poll_ready(cx))
            .await
            .unwrap();
        drop(reserved);
        let before = poll_ready_count.load(Ordering::SeqCst);
        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        assert_eq!(poll_ready_count.load(Ordering::SeqCst), before);

        drop(cache.retain(|_| false));
        assert!(cache.is_empty());
        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        assert_eq!(poll_ready_count.load(Ordering::SeqCst), before + 1);

        // Bulk pruning must preserve the order used by subsequent LIFO reuse.
        let discarded = {
            let mut shared = cache.shared.lock();
            shared.idle.extend(0..64);
            let mut visited = Vec::new();
            let discarded = shared.retain_idle(|value| {
                visited.push(*value);
                value.is_multiple_of(3)
            });
            assert_eq!(visited, (0..64).collect::<Vec<_>>());
            assert_eq!(
                shared.idle,
                (0..64).filter(|value| value % 3 == 0).collect::<Vec<_>>()
            );
            discarded
        };
        assert_eq!(
            discarded,
            (0..64).filter(|value| value % 3 != 0).collect::<Vec<_>>()
        );
    }
}
