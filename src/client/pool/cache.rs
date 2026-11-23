//! Races reusable services against newly created services.
//!
//! Manages exclusive services that handle one checkout at a time, such as HTTP/1 senders.
//! Idle services, FIFO waiters, and active counts are shared under one group lock.
//!
//! # Checkout lifecycle
//!
//! 1. `poll_ready` always succeeds immediately so callers register in the FIFO queue before waiting
//!    on connector admission or reuse delays.
//! 2. `call` either returns an available idle service immediately or registers a FIFO waiter and
//!    races reuse against maker readiness and dialing inside [`CacheFuture`].
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
    time::Duration,
};

use futures_util::future::BoxFuture;
use pin_project_lite::pin_project;
use tokio::sync::watch;
use tower::Service;

use crate::{
    rt::{BoxSleep, Executor, Timer},
    sync::Mutex,
};

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
/// [`Shared`] owns idle services and FIFO handoff state. Checked-out services and
/// background makers hold only weak references to it so they never keep an unused cache
/// alive; dropping the last shared owner also signals background makers to stop.
#[derive(Debug)]
pub(super) struct Cache<M, Dst, Ev, G>
where
    M: Service<Dst>,
    G: AsMut<Shared<M::Response>>,
{
    /// Underlying maker polled and called inside [`CacheFuture`] on a cache miss.
    maker: M,
    /// Shared per-group lock containing [`Shared`] idle connections, waiters, and active count.
    shared: Arc<Mutex<G>>,
    /// Policy handling reuse-first delays and maker futures that lose the reuse race.
    events: Ev,
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

/// State of a racing maker attempt before and after physical connection work starts.
enum RaceMaker<M, Dst>
where
    M: Service<Dst>,
{
    /// Waiting out a reuse-first delay before polling the maker ready and calling it.
    Waiting {
        /// Reuse-first sleep future.
        sleep: BoxSleep,
        /// Cloned maker ready to dial once `sleep` completes.
        maker: M,
        /// Target forwarded to `maker` once ready.
        target: Option<Dst>,
    },
    /// Polling a cloned maker for readiness before starting the dial.
    Preparing {
        /// Cloned maker waiting to become ready.
        maker: M,
        /// Target forwarded to `maker` once ready.
        target: Option<Dst>,
    },
    /// Polling the in-flight maker future; `started` flips true on the first poll.
    Connecting {
        /// In-flight maker future racing against reuse.
        future: M::Future,
        /// Whether `future` has been polled at least once.
        started: bool,
    },
    /// Terminal state after completion, failure, or handoff to background completion.
    Done,
}

pin_project! {
    /// Future returned by a cache checkout.
    ///
    /// `Racing` polls a FIFO reservation before advancing the maker on every wake, handing
    /// started maker work to the event policy if reuse wins; dropping it cancels its waiter
    /// and reassigns any reserved service. `Cached` yields an idle service taken immediately
    /// in `call`.
    #[project = CacheFutureProj]
    pub(super) enum CacheFuture<M, Dst, Ev, G>
    where
        M: Service<Dst>,
        G: AsMut<Shared<M::Response>>,
    {
        Racing {
            // Shared cache state checked for a reserved return on each poll.
            shared: Arc<Mutex<G>>,
            // FIFO waiter ID assigned to this racing checkout.
            waiter: WaiterId,
            // Maker attempt, optionally waiting out a reuse-first delay before dialing.
            maker: RaceMaker<M, Dst>,
            // Policy providing reuse delays and handling lost started races.
            events: Ev,
        },
        Cached {
            // Idle service taken immediately in `call`.
            service: Option<Cached<M::Response, G>>,
        },
    }

    impl<M, Dst, Ev, G> PinnedDrop for CacheFuture<M, Dst, Ev, G>
    where
        M: Service<Dst>,
        G: AsMut<Shared<M::Response>>,
    {
        fn drop(this: Pin<&mut Self>) {
            if let CacheFutureProj::Racing { shared, waiter, .. } = this.project() {
                let result = shared.lock().as_mut().cancel_waiter(*waiter);
                finish_cancel(result);
            }
        }
    }
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
    pub(super) fn runtime<R: Executor + Timer>(
        self,
        runtime: R,
    ) -> Builder<events::WithRuntime<R>> {
        Builder {
            events: events::WithRuntime {
                runtime,
                reuse_delay: None,
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
            shared,
            _dst: PhantomData,
        }
    }
}

impl<R> Builder<events::WithRuntime<R>> {
    /// Delays new dials when the group already has active or waiting work.
    #[must_use]
    pub(super) fn reuse_delay(mut self, delay: Option<Duration>) -> Self {
        self.events.reuse_delay = delay;
        self
    }

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

    /// Returns whether shared idle state holds an unreserved service.
    #[must_use]
    pub(super) fn has_idle(&self) -> bool {
        self.shared.lock().as_mut().has_idle()
    }

    /// Returns whether no idle, reserved, waiting, or active work remains.
    #[must_use]
    pub(super) fn is_empty(&self) -> bool {
        self.shared.lock().as_mut().is_empty()
    }
}

impl<M, Dst, Ev, G> Service<Dst> for Cache<M, Dst, Ev, G>
where
    M: Service<Dst> + Clone,
    G: AsMut<Shared<M::Response>>,
    M::Future: Unpin,
    M::Response: Unpin,
    Ev: events::Events<BackgroundConnect<M::Future, M::Response, G>> + Clone,
{
    type Response = Cached<M::Response, G>;
    type Error = M::Error;
    type Future = CacheFuture<M, Dst, Ev, G>;

    #[inline(always)]
    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Checkouts enter `CacheFuture::Racing` before waiting on maker readiness so returning
        // senders still satisfy FIFO waiters even when connector admission is pending or errors.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: Dst) -> Self::Future {
        let (waiter, had_work) = {
            let mut guard = self.shared.lock();
            let shared = guard.as_mut();
            match shared.take_available() {
                Some(service) => {
                    return CacheFuture::Cached {
                        service: Some(Cached::new(service, &self.shared, shared, true)),
                    };
                }
                None => {
                    let had_work = !shared.is_empty();
                    (shared.push_waiter(), had_work)
                }
            }
        };

        let maker = if had_work && let Some(sleep) = self.events.reuse_delay() {
            RaceMaker::Waiting {
                sleep,
                maker: self.maker.clone(),
                target: Some(target),
            }
        } else {
            RaceMaker::Preparing {
                maker: self.maker.clone(),
                target: Some(target),
            }
        };
        CacheFuture::Racing {
            shared: self.shared.clone(),
            waiter,
            maker,
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
            _dst: PhantomData,
        }
    }
}

// ===== impl CacheFuture =====

impl<M, Dst, Ev, G> Future for CacheFuture<M, Dst, Ev, G>
where
    M: Service<Dst>,
    G: AsMut<Shared<M::Response>>,
    M::Future: Unpin,
    M::Response: Unpin,
    Ev: events::Events<BackgroundConnect<M::Future, M::Response, G>>,
{
    type Output = Result<Cached<M::Response, G>, M::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            CacheFutureProj::Racing {
                shared,
                waiter,
                maker,
                events,
            } => {
                let mut guard = shared.lock();
                let locked = guard.as_mut();
                let (reused, replaced_waker, dropped_maker) =
                    if let Some(service) = locked.take_reserved(*waiter) {
                        let taken = std::mem::replace(maker, RaceMaker::Done);
                        let (background, dropped) = match taken {
                            RaceMaker::Connecting {
                                future,
                                started: true,
                            } => match locked.shutdown.as_ref() {
                                Some(shutdown) => {
                                    let shutdown = cache_shutdown(shutdown.subscribe());
                                    locked.active += 1;
                                    (
                                        Some(BackgroundConnect {
                                            future,
                                            shared: Arc::downgrade(shared),
                                            shutdown,
                                            _service: PhantomData,
                                        }),
                                        None,
                                    )
                                }
                                None => (
                                    None,
                                    Some(RaceMaker::Connecting {
                                        future,
                                        started: true,
                                    }),
                                ),
                            },
                            other => (None, Some(other)),
                        };
                        let service = Cached::new(service, shared, locked, true);
                        (Some((service, background)), None, dropped)
                    } else {
                        let replaced = locked.store_waker(*waiter, cx.waker());
                        (None, replaced, None)
                    };
                drop(guard);
                drop(replaced_waker);
                drop(dropped_maker);

                if let Some((service, background)) = reused {
                    if let Some(background) = background {
                        events.on_race_lost(background);
                    }
                    return Poll::Ready(Ok(service));
                }

                let resolve_error = |error| {
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
                    Poll::Ready(match reserved {
                        Ok(service) => Ok(service),
                        Err(canceled) => {
                            finish_cancel(canceled);
                            Err(error)
                        }
                    })
                };

                loop {
                    match maker {
                        RaceMaker::Waiting { sleep, .. } => {
                            ready!(Pin::new(sleep).poll(cx));
                            if let RaceMaker::Waiting {
                                maker: service,
                                target,
                                ..
                            } = std::mem::replace(maker, RaceMaker::Done)
                            {
                                *maker = RaceMaker::Preparing {
                                    maker: service,
                                    target,
                                };
                            }
                        }
                        RaceMaker::Preparing {
                            maker: service,
                            target,
                        } => match ready!(service.poll_ready(cx)) {
                            Ok(()) => {
                                let Some(target) = target.take() else {
                                    *maker = RaceMaker::Done;
                                    return Poll::Pending;
                                };
                                let future = service.call(target);
                                *maker = RaceMaker::Connecting {
                                    future,
                                    started: false,
                                };
                            }
                            Err(error) => {
                                *maker = RaceMaker::Done;
                                return resolve_error(error);
                            }
                        },
                        RaceMaker::Connecting { future, started } => {
                            *started = true;
                            let connected = match ready!(Pin::new(future).poll(cx)) {
                                Ok(service) => service,
                                Err(error) => {
                                    *maker = RaceMaker::Done;
                                    return resolve_error(error);
                                }
                            };

                            let (service, result) = {
                                let mut guard = shared.lock();
                                let locked = guard.as_mut();
                                let service = Cached::new(connected, shared, locked, false);
                                (service, locked.cancel_waiter(*waiter))
                            };
                            finish_cancel(result);
                            *maker = RaceMaker::Done;
                            return Poll::Ready(Ok(service));
                        }
                        RaceMaker::Done => return Poll::Pending,
                    }
                }
            }
            CacheFutureProj::Cached { service } => match service.take() {
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
    use std::{future::Future, sync::Arc, time::Duration};

    use futures_util::FutureExt;

    use super::{BoxSleep, Executor, Timer};

    /// Policy that cancels maker futures after another service wins the race.
    ///
    /// This is useful when finishing the work would provide no value or when no
    /// runtime is available for detached connection work.
    #[derive(Clone, Debug)]
    pub struct Ignore;

    /// Policy that delays new dials when configured and completes started lost races on a runtime.
    #[derive(Clone)]
    pub struct WithRuntime<R> {
        /// Runtime executing detached background connects and reuse-first sleeps.
        pub(super) runtime: R,
        /// Optional delay before dialing when the cache already has active or waiting work.
        pub(super) reuse_delay: Option<Duration>,
        /// Optional entry maintenance callback run after the background task finishes.
        pub(super) on_complete: Option<Arc<dyn Fn() + Send + Sync>>,
    }

    /// Handles reuse-first delays and started maker futures that lose the reuse race.
    pub trait Events<F> {
        /// Returns an optional sleep delaying a new dial when other work is active.
        #[must_use]
        fn reuse_delay(&self) -> Option<BoxSleep> {
            None
        }

        /// Receives a started maker future that lost the race.
        fn on_race_lost(&self, future: F);
    }

    // ===== impl Ignore =====

    impl<F> Events<F> for Ignore {
        fn on_race_lost(&self, _future: F) {}
    }

    // ===== impl WithRuntime =====

    impl<F, R> Events<F> for WithRuntime<R>
    where
        F: Future<Output = ()> + Send + 'static,
        R: Executor + Timer,
    {
        fn reuse_delay(&self) -> Option<BoxSleep> {
            self.reuse_delay
                .map(|duration| self.runtime.sleep(duration))
        }

        fn on_race_lost(&self, future: F) {
            let on_complete = self.on_complete.clone();
            self.runtime.execute(
                future
                    .map(move |()| {
                        if let Some(on_complete) = on_complete {
                            on_complete();
                        }
                    })
                    .boxed(),
            );
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
        let held = cache.call(0).await.unwrap();

        connector.allow_ready.store(false, Ordering::SeqCst);
        let wake = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = Waker::from(wake.clone());
        let mut wake_cx = Context::from_waker(&waker);
        let mut waiting = Box::pin(cache.call(0));
        assert!(waiting.as_mut().poll(&mut wake_cx).is_pending());

        drop(held);
        assert!(wake.0.load(Ordering::SeqCst));
        let Poll::Ready(Ok(held)) = waiting.as_mut().poll(&mut wake_cx) else {
            panic!("waiter blocked on maker readiness should wake and reuse returned service");
        };
        assert!(held.is_reused());
        drop(waiting);

        connector.allow_ready.store(true, Ordering::SeqCst);
        let mut cx = Context::from_waker(Waker::noop());
        let mut first = std::pin::pin!(cache.call(1));
        assert!(first.as_mut().poll(&mut cx).is_pending());

        let mut canceled = Box::pin(cache.call(2));
        assert!(canceled.as_mut().poll(&mut cx).is_pending());

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

        assert!(cache.call(4).await.unwrap().is_reused());
    }

    #[tokio::test]
    async fn clone_readiness_reserves_returns_and_retains_services() {
        let connector = StrictConnector::default();
        let poll_ready_count = connector.poll_ready_count.clone();
        let calls = connector.calls.clone();
        let mut cache = builder().build(connector);

        let service = cache.call(1).await.unwrap();
        assert_eq!(*service.inner(), 0);
        assert_eq!(poll_ready_count.load(Ordering::SeqCst), 1);
        drop(service);

        let mut first = cache.clone();
        let mut second = cache.clone();
        let first_future = first.call(10);
        let second_future = second.call(20);
        let first_service = first_future.await.unwrap();
        let second_service = second_future.await.unwrap();
        assert_eq!(*first_service.inner(), 0);
        assert_eq!(*second_service.inner(), 1);
        assert_eq!(poll_ready_count.load(Ordering::SeqCst), 2);
        assert_eq!(*calls.lock().unwrap(), vec![1, 20]);
        drop(first_service);
        drop(second_service);

        // Dropping an unpolled cached future returns its reserved idle service.
        let mut reserved = cache.clone();
        drop(reserved.call(30));
        let before = poll_ready_count.load(Ordering::SeqCst);
        let reused = cache.call(31).await.unwrap();
        assert!(reused.is_reused());
        assert_eq!(poll_ready_count.load(Ordering::SeqCst), before);
        drop(reused);

        drop(cache.retain_idle(|_| false));
        assert!(cache.is_empty());
        let dialed = cache.call(32).await.unwrap();
        assert!(!dialed.is_reused());
        assert_eq!(poll_ready_count.load(Ordering::SeqCst), before + 1);
        drop(dialed);

        // Bulk pruning must preserve the order used by subsequent LIFO reuse.
        let discarded = {
            let mut shared = cache.shared.lock();
            shared.idle.clear();
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

    #[tokio::test]
    async fn reuse_delay_cancels_before_dial_and_finishes_started_races() {
        #[derive(Clone, Default)]
        struct TestRuntime {
            spawned: Arc<AtomicUsize>,
        }

        impl Executor for TestRuntime {
            fn execute(&self, future: BoxFuture<'static, ()>) {
                self.spawned.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(future);
            }
        }

        struct TestSleep(Pin<Box<tokio::time::Sleep>>);

        impl Future for TestSleep {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                self.0.as_mut().poll(cx)
            }
        }

        impl crate::rt::Sleep for TestSleep {
            fn reset(mut self: Pin<&mut Self>, deadline: std::time::Instant) {
                self.0.as_mut().reset(deadline.into());
            }
        }

        impl Timer for TestRuntime {
            fn now(&self) -> std::time::Instant {
                tokio::time::Instant::now().into_std()
            }

            fn sleep(&self, duration: Duration) -> BoxSleep {
                BoxSleep::new(TestSleep(Box::pin(tokio::time::sleep(duration))))
            }

            fn sleep_until(&self, deadline: std::time::Instant) -> BoxSleep {
                BoxSleep::new(TestSleep(Box::pin(tokio::time::sleep_until(
                    deadline.into(),
                ))))
            }
        }

        #[derive(Clone)]
        struct GatedConnector {
            calls: Arc<AtomicUsize>,
            gate: Arc<tokio::sync::Notify>,
            fail_ready: Arc<AtomicBool>,
        }

        struct UnlockedDrop {
            shared: Weak<Mutex<Shared<usize>>>,
            dropped_unlocked: Arc<AtomicBool>,
        }

        impl Drop for UnlockedDrop {
            fn drop(&mut self) {
                if let Some(shared) = self.shared.upgrade() {
                    // Re-acquiring the group mutex proves the loser dropped unlocked.
                    let _guard = shared.lock();
                    self.dropped_unlocked.store(true, Ordering::SeqCst);
                }
            }
        }

        impl Service<Option<UnlockedDrop>> for GatedConnector {
            type Response = usize;
            type Error = &'static str;
            type Future = BoxFuture<'static, Result<usize, Self::Error>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                if self.fail_ready.load(Ordering::SeqCst) {
                    Poll::Ready(Err("readiness failed"))
                } else {
                    Poll::Ready(Ok(()))
                }
            }

            fn call(&mut self, _target: Option<UnlockedDrop>) -> Self::Future {
                let id = self.calls.fetch_add(1, Ordering::SeqCst);
                let gate = self.gate.clone();
                Box::pin(async move {
                    if id > 0 {
                        gate.notified().await;
                    }
                    Ok(id)
                })
            }
        }

        tokio::time::pause();
        let runtime = TestRuntime::default();
        let connector = GatedConnector {
            calls: Arc::new(AtomicUsize::new(0)),
            gate: Arc::new(tokio::sync::Notify::new()),
            fail_ready: Arc::new(AtomicBool::new(false)),
        };
        let mut cache = builder()
            .runtime(runtime.clone())
            .reuse_delay(Some(Duration::from_millis(50)))
            .build(connector.clone());

        // First checkout on an empty cache dials immediately without waiting.
        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        let held = cache.call(None).await.unwrap();
        assert_eq!(*held.inner(), 0);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);

        // Reuse winning during the delay must not fail early on dialer readiness,
        // must cancel before dialing, and must drop the losing target unlocked.
        connector.fail_ready.store(true, Ordering::SeqCst);
        let dropped_unlocked = Arc::new(AtomicBool::new(false));
        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        let mut delayed = tokio_test::task::spawn(cache.call(Some(UnlockedDrop {
            shared: Arc::downgrade(&cache.shared),
            dropped_unlocked: dropped_unlocked.clone(),
        })));
        assert!(delayed.poll().is_pending());
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        drop(held);
        let Poll::Ready(Ok(reused)) = delayed.poll() else {
            panic!("waiter should reuse returned service before delay expires");
        };
        assert!(reused.is_reused());
        assert!(dropped_unlocked.load(Ordering::SeqCst));
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.spawned.load(Ordering::SeqCst), 0);
        connector.fail_ready.store(false, Ordering::SeqCst);

        // Once the delay elapses and dialing starts, a lost race finishes in the background.
        std::future::poll_fn(|cx| cache.poll_ready(cx))
            .await
            .unwrap();
        let mut raced = tokio_test::task::spawn(cache.call(None));
        assert!(raced.poll().is_pending());
        tokio::time::advance(Duration::from_millis(51)).await;
        assert!(raced.is_woken());
        assert!(raced.poll().is_pending());
        assert_eq!(connector.calls.load(Ordering::SeqCst), 2);
        drop(reused);
        let Poll::Ready(Ok(reused)) = raced.poll() else {
            panic!("waiter should still prefer returned service over pending dial");
        };
        assert!(reused.is_reused());
        assert_eq!(runtime.spawned.load(Ordering::SeqCst), 1);

        connector.gate.notify_one();
        tokio::task::yield_now().await;
        assert!(cache.has_idle());
        drop(reused);

        // In default Race mode, a sender returned while maker.poll_ready fails must still win.
        type TestCached = Cached<usize, Shared<usize>>;

        #[derive(Clone)]
        struct ReturnOnFailReady {
            held: Arc<Mutex<Option<TestCached>>>,
        }

        impl Service<()> for ReturnOnFailReady {
            type Response = usize;
            type Error = &'static str;
            type Future = std::future::Ready<Result<usize, Self::Error>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                if let Some(held) = self.held.lock().take() {
                    drop(held);
                    return Poll::Ready(Err("readiness failed after return"));
                }
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _target: ()) -> Self::Future {
                std::future::ready(Ok(42))
            }
        }

        let held_slot = Arc::new(Mutex::new(None));
        let mut race_cache = builder().build(ReturnOnFailReady {
            held: held_slot.clone(),
        });
        let held = race_cache.call(()).await.unwrap();
        assert_eq!(*held.inner(), 42);
        *held_slot.lock() = Some(held);

        let reused = race_cache
            .call(())
            .await
            .expect("returned sender must win over maker.poll_ready error");
        assert!(reused.is_reused());
        assert_eq!(*reused.inner(), 42);
    }
}
