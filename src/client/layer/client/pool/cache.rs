//! Races reusable services against newly created services.
//!
//! `Cache` is used for connections that can serve one checkout at a time,
//! notably HTTP/1. A checkout first reserves a returned service while
//! also allowing the maker to start a replacement. If reuse wins, a connection
//! attempt that has begun useful work may finish in the background and enter the
//! cache. Returned services are handed to FIFO waiters before becoming idle.
//!
//! Each clone has its own readiness reservation, while idle services, waiters,
//! and active-checkout accounting are shared. Dropping a checkout returns its
//! service unless it was explicitly marked for disposal.

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

use tower::Service;

use crate::sync::Mutex;

/// Reports whether a raced operation has begun work worth completing.
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

/// A cloneable cache of reusable services produced by `M`.
///
/// Readiness is local to each clone so concurrent callers cannot consume the
/// same reservation. Idle services and waiters live in [`Shared`].
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

/// Configures cache capacity and lost-race handling.
#[derive(Debug)]
pub(super) struct Builder<Ev> {
    /// Handler for a maker future that loses the checkout race.
    events: Ev,
    /// Maximum number of services retained without a waiter.
    max_idle: usize,
}

/// A checked-out service that normally returns to its cache on drop.
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
}

/// Readiness reserved by one `Cache` clone.
#[derive(Debug)]
enum Ready<S> {
    /// No reusable service is reserved.
    None,
    /// A service is reserved for the next `call` on this clone.
    Cached(S),
}

/// Future returned by a cache checkout.
///
/// `Racing` waits for either a FIFO reuse reservation or the maker. `Cached`
/// completes immediately with a service already reserved during readiness.
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

/// Shared idle services, FIFO waiters, and waiter-specific reservations.
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
}

/// Identifier used to pair a waiter with its reserved service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WaiterId(usize);

/// One pending checkout in FIFO order.
#[derive(Debug)]
struct Waiter {
    /// Identifier used to store and recover its reservation.
    id: WaiterId,
    /// Latest task interested in this waiter.
    waker: Option<Waker>,
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
    pub(super) fn retain<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&mut M::Response) -> bool,
    {
        if let Ready::Cached(service) = &mut self.ready {
            if !predicate(service) {
                self.ready = Ready::None;
            }
        }
        self.shared.lock().services.retain_mut(predicate);
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

        {
            let mut shared = self.shared.lock();
            if let Some(id) = self.ready_waiter {
                if let Some(service) = shared.take_reserved(id) {
                    self.ready_waiter = None;
                    self.ready = Ready::Cached(service);
                    return Poll::Ready(Ok(()));
                }
            } else if let Some(service) = shared.take_available() {
                self.ready = Ready::Cached(service);
                return Poll::Ready(Ok(()));
            }

            let id = *self
                .ready_waiter
                .get_or_insert_with(|| shared.push_waiter());
            shared.store_waker(id, cx.waker());
        }

        match self.connector.poll_ready(cx) {
            Poll::Ready(result) => {
                if let Some(id) = self.ready_waiter.take() {
                    self.shared.lock().cancel_waiter(id);
                }
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
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
                    shared.cancel_waiter(id);
                }
                if let Some(service) = self.shared.lock().take_available() {
                    return CacheFuture::Cached {
                        service: Some(Cached::new(
                            service,
                            Arc::downgrade(&self.shared),
                            self.active.clone(),
                            true,
                        )),
                    };
                }
            }
        }

        let waiter = self.shared.lock().push_waiter();
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
            self.shared.lock().put(service);
        }
        if let Some(id) = self.ready_waiter.take() {
            self.shared.lock().cancel_waiter(id);
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
            shared.lock().cancel_waiter(*waiter);
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
                {
                    let mut locked = shared.lock();
                    if let Some(service) = locked.take_reserved(*waiter) {
                        if let Some(future) = future.take() {
                            events.on_race_lost(BackgroundConnect {
                                future,
                                shared: Arc::downgrade(shared),
                            });
                        }
                        return Poll::Ready(Ok(Cached::new(
                            service,
                            Arc::downgrade(shared),
                            active.clone(),
                            true,
                        )));
                    }
                    locked.store_waker(*waiter, cx.waker());
                }

                let Some(connecting) = future.as_mut() else {
                    return Poll::Pending;
                };
                let connected = match ready!(Pin::new(connecting).poll(cx)) {
                    Ok(service) => service,
                    Err(error) => {
                        shared.lock().cancel_waiter(*waiter);
                        return Poll::Ready(Err(error));
                    }
                };

                shared.lock().cancel_waiter(*waiter);
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
        active.fetch_add(1, Ordering::AcqRel);
        Self {
            discard: false,
            reused,
            inner: Some(inner),
            shared,
            active,
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

    /// Returns whether another checkout is waiting for this service.
    pub(super) fn has_waiters(&self) -> bool {
        self.shared
            .upgrade()
            .is_some_and(|shared| !shared.lock().waiters.is_empty())
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
    /// Returns a healthy service before decrementing the active count.
    ///
    /// This order prevents idle cleanup from observing an empty cache between
    /// the checkout becoming inactive and its service becoming reusable.
    fn drop(&mut self) {
        if !self.discard {
            if let Some(service) = self.inner.take() {
                if let Some(shared) = self.shared.upgrade() {
                    shared.lock().put(service);
                }
            }
        }
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl<S: fmt::Debug> fmt::Debug for Cached<S> {
    /// Formats the wrapped service without exposing cache bookkeeping.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Cached").field(&self.inner).finish()
    }
}

impl<S> Shared<S> {
    /// Gives a returned service to the oldest waiter or stores it as idle.
    fn put(&mut self, service: S) {
        if let Some(mut waiter) = self.waiters.pop_front() {
            self.reservations.push((waiter.id, service));
            if let Some(waker) = waiter.waker.take() {
                waker.wake();
            }
        } else if self.services.len() < self.max_idle {
            self.services.push(service);
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
        Some(self.services.swap_remove(index))
    }

    /// Appends a checkout to the FIFO waiter queue.
    fn push_waiter(&mut self) -> WaiterId {
        let id = WaiterId(self.next_waiter);
        self.next_waiter = self.next_waiter.wrapping_add(1);
        self.waiters.push_back(Waiter { id, waker: None });
        id
    }

    /// Stores the latest waker for a queued waiter.
    fn store_waker(&mut self, id: WaiterId, waker: &Waker) {
        if let Some(waiter) = self.waiters.iter_mut().find(|waiter| waiter.id == id) {
            if waiter
                .waker
                .as_ref()
                .is_none_or(|current| !current.will_wake(waker))
            {
                waiter.waker = Some(waker.clone());
            }
        }
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
    fn cancel_waiter(&mut self, id: WaiterId) {
        if let Some(index) = self.waiters.iter().position(|waiter| waiter.id == id) {
            self.waiters.remove(index);
        } else if let Some(service) = self.take_reserved(id) {
            self.put(service);
        }
    }
}

/// Completes a maker future that lost to connection reuse.
pub(super) struct BackgroundConnect<F, S> {
    /// Maker future that already began useful work.
    future: F,
    /// Destination cache, if it still exists when work completes.
    shared: Weak<Mutex<Shared<S>>>,
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
        match ready!(Pin::new(&mut self.future).poll(cx)) {
            Ok(service) => {
                if let Some(shared) = self.shared.upgrade() {
                    shared.lock().put(service);
                }
                Poll::Ready(())
            }
            Err(_) => Poll::Ready(()),
        }
    }
}

/// Policies for maker futures that lose the reuse race.
pub(super) mod events {
    use super::Started;

    /// Drops lost maker futures without completing them.
    #[derive(Clone, Debug)]
    pub(in crate::client::layer::client::pool) struct Ignore;

    /// Completes useful lost maker futures on an executor.
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
