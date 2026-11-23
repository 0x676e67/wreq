//! Selects a fallback or upgraded pool after inspecting a newly established connection.
//!
//! Instead of routing before dialing, wreq establishes a transport on the fallback path and
//! inspects its ALPN result: HTTP/1 stays in the fallback cache, while HTTP/2 is handed off
//! to the upgraded singleton.
//!
//! Upgraded transports enter the pending queue before [`UpgradeSignal`] wakes concurrent
//! fallback attempts. Selection checks the singleton and detaches redundant queued
//! transports under the shared group lock; maker calls and polling run unlocked, and a
//! stale wake falls back to a fresh attempt if no upgraded work remains.

use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Weak},
    task::{self, Poll, ready},
};

use futures_util::future::{BoxFuture, Either};
use pin_project_lite::pin_project;
use tokio::sync::watch;
use tower::{
    BoxError, Layer, Service,
    util::{Either as ServiceEither, Oneshot},
};

use super::{
    cache::Started,
    singleton::{self, Ready, Singled, Singleton, SingletonFuture},
};
use crate::sync::Mutex;

/// Selects a fallback or upgraded pool from an inspected connection.
///
/// `fallback` owns the connector and inspector, while `upgrade` wraps transports diverted
/// into the group's [`Shared`] pending queue so it never reconnects. Clones share both
/// child pools and the group lock, checking for an existing upgraded service or queued
/// transport before starting a fallback attempt; redundant transports drop unlocked.
pub(super) struct Negotiate<L, R, S> {
    /// Pool handling non-upgraded connections.
    fallback: L,
    /// Pool handling connections diverted by inspection.
    upgrade: R,
    /// Intermediate transport type bridged between `fallback` and `upgrade`.
    transport: PhantomData<fn(S)>,
}

/// A checked-out service selected by [`Negotiate`].
///
/// `Left` is the fallback service and `Right` is the upgraded service.
pub(super) type Negotiated<L, R> = ServiceEither<L, R>;

pin_project! {
    /// Future driving the active fallback or upgrade checkout branch.
    ///
    /// While in the fallback branch, retains a fallback pool clone and destination only for
    /// retrying with fresh readiness after a stale upgrade notification. Once handed off,
    /// polls the upgraded singleton future directly.
    pub(super) struct Negotiating<Dst, L, R, S>
    where
        L: Service<Dst>,
        R: Service<S>,
    {
        // Active fallback or upgrade future.
        #[pin]
        state: State<Dst, L, Either<L::Future, Oneshot<L, Dst>>, R::Future>,
        // Upgraded pool clone used to join or start the singleton on handoff.
        upgrade: R,
        // Intermediate transport type passed into `upgrade`.
        transport: PhantomData<fn(S)>,
    }
}

pin_project! {
    #[project = StateProj]
    /// Active branch of [`Negotiating`].
    ///
    /// Starts in `Fallback` unless upgraded work is already available. A [`UseOther`]
    /// signal switches to `Upgrade`, or restarts `Fallback` if the notification was stale.
    enum State<Dst, L, FL, FR> {
        /// Establishes and inspects a connection through the fallback path.
        Fallback {
            #[pin]
            future: FL,
            // Retained only for retrying with fresh readiness after a stale signal.
            fallback: L,
            // Destination cloned for a stale-signal retry.
            destination: Dst,
        },
        /// Builds or joins the upgraded service.
        Upgrade {
            #[pin]
            future: FR,
        },
    }
}

/// Future joining a completed or in-progress upgraded singleton generation.
type UpgradeFuture<M, S, G> =
    SingletonFuture<<M as Service<S>>::Future, <M as Service<S>>::Response, G>;

/// Checked-out service from a completed upgrade.
type Upgraded<M, S> = Singled<<M as Service<S>>::Response>;

/// Upgraded transport queue and singleton state synchronized under the group lock.
///
/// Embedded in the entry's shared state alongside the fallback cache so `checkout_ready`,
/// pruning, and eviction inspect both sides atomically.
#[derive(Debug)]
pub(super) struct Shared<S, F, U> {
    /// Inspected upgraded transports waiting to enter the singleton.
    pending: VecDeque<S>,
    /// Shared lifecycle state of the upgraded singleton.
    upgrade: singleton::State<F, U>,
}

// ===== impl Shared =====

impl<S, F, U> Default for Shared<S, F, U> {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
            upgrade: singleton::State::Empty,
        }
    }
}

impl<S, F, U> Shared<S, F, U> {
    /// Returns whether an upgraded transport is waiting for handoff.
    #[must_use]
    pub(super) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Detaches queued upgraded transports rejected by the predicate.
    #[must_use]
    pub(super) fn retain_pending(&mut self, mut predicate: impl FnMut(&S) -> bool) -> VecDeque<S> {
        let mut discarded = VecDeque::new();
        for _ in 0..self.pending.len() {
            match self.pending.pop_front() {
                Some(service) if predicate(&service) => self.pending.push_back(service),
                Some(service) => discarded.push_back(service),
                None => break,
            }
        }
        discarded
    }

    /// Detaches every queued upgraded transport.
    #[must_use]
    pub(super) fn drain_pending(&mut self) -> VecDeque<S> {
        std::mem::take(&mut self.pending)
    }
}

impl<S, F, U> AsMut<VecDeque<S>> for Shared<S, F, U> {
    fn as_mut(&mut self) -> &mut VecDeque<S> {
        &mut self.pending
    }
}

impl<S, F, U> AsMut<singleton::State<F, U>> for Shared<S, F, U> {
    fn as_mut(&mut self) -> &mut singleton::State<F, U> {
        &mut self.upgrade
    }
}

/// Existing upgraded work selected before falling back to a new connection.
enum Selection<F, S> {
    /// Future joining a completed or in-progress upgraded service.
    Existing(F),
    /// Queued upgraded transport ready to enter the upgraded pool.
    Pending(S),
    /// No upgraded work is currently available.
    Fallback,
}

// ===== impl Negotiate =====

impl<L: Clone, R: Clone, S> Clone for Negotiate<L, R, S> {
    fn clone(&self) -> Self {
        Self {
            fallback: self.fallback.clone(),
            upgrade: self.upgrade.clone(),
            transport: PhantomData,
        }
    }
}

impl<L, R, S> Negotiate<L, R, S> {
    /// Borrows the upgraded pool.
    #[must_use]
    pub(super) fn upgrade(&self) -> &R {
        &self.upgrade
    }
}

impl<L, M, S, G> Negotiate<L, Singleton<M, S, G>, S>
where
    M: Service<S>,
    M::Response: Clone,
    G: AsMut<singleton::State<M::Future, M::Response>> + AsMut<Shared<S, M::Future, M::Response>>,
{
    /// Composes the fallback and upgrade pools around an inspected connector.
    #[must_use]
    pub(super) fn new<C, I, LL, RR>(connect: C, inspect: I, fallback: LL, upgrade: RR) -> Self
    where
        I: Fn(&S) -> bool,
        LL: Layer<Inspector<C, S, I, G>, Service = L>,
        RR: Layer<Provided<S>, Service = Singleton<M, S, G>>,
    {
        let upgrade = upgrade.layer(Provided(PhantomData));
        let fallback = fallback.layer(Inspector {
            service: connect,
            inspect,
            state: Arc::downgrade(upgrade.shared()),
            signal: UpgradeSignal::new(),
            transport: PhantomData,
        });
        Self {
            fallback,
            upgrade,
            transport: PhantomData,
        }
    }

    /// Checks both branches before an empty group is removed from the map.
    #[must_use]
    pub(super) fn is_empty(&self, fallback_empty: impl FnOnce(&G) -> bool) -> bool
    where
        G: AsRef<Shared<S, M::Future, M::Response>>,
    {
        let group = self.upgrade.shared().lock();
        let state = (*group).as_ref();
        state.pending.is_empty()
            && matches!(state.upgrade, singleton::State::Empty)
            && fallback_empty(&group)
    }

    /// Takes a ready service under the group lock and maps it after unlocking.
    ///
    /// Prefers a reusable upgraded service, refuses when upgraded transports are pending
    /// handoff, and checks `fallback` only when the upgraded singleton is `Empty`.
    #[must_use]
    pub(super) fn checkout_ready<F, T>(
        &self,
        upgrade: impl FnOnce(&M::Response, &G) -> bool,
        fallback: impl FnOnce(&L, &mut G) -> Option<F>,
        map_upgrade: impl FnOnce(Upgraded<M, S>) -> T,
        map_fallback: impl FnOnce(F) -> T,
    ) -> Option<T>
    where
        G: AsRef<Shared<S, M::Future, M::Response>>,
    {
        let mut group = self.upgrade.shared().lock();
        let state = (*group).as_ref();
        // A newly queued transport must not be bypassed by a fallback checkout.
        if !state.pending.is_empty() {
            return None;
        }
        match self
            .upgrade
            .checkout_ready(Some(&state.upgrade), |service| upgrade(service, &group))
        {
            Ready::Made(service) => {
                drop(group);
                Some(map_upgrade(service))
            }
            Ready::Empty => {
                let service = fallback(&self.fallback, &mut group)?;
                drop(group);
                Some(map_fallback(service))
            }
            Ready::Unavailable => None,
        }
    }

    /// Joins existing upgraded work without invoking the fallback service.
    ///
    /// Returns redundant queued transports for drop outside any caller-held lock.
    #[must_use]
    pub(super) fn checkout_existing(&self) -> Option<(UpgradeFuture<M, S, G>, VecDeque<S>)> {
        checkout_existing(&self.upgrade, self.upgrade.shared().lock().as_mut())
    }
}

impl<L, M, S, Dst, G> Service<Dst> for Negotiate<L, Singleton<M, S, G>, S>
where
    L: Service<Dst> + Clone,
    L::Error: Into<BoxError>,
    M: Service<S> + Clone,
    M::Response: Clone,
    M::Error: Into<BoxError>,
    Dst: Clone,
    S: Send + 'static,
    G: AsMut<singleton::State<M::Future, M::Response>> + AsMut<Shared<S, M::Future, M::Response>>,
{
    type Response = Negotiated<L::Response, Upgraded<M, S>>;
    type Error = BoxError;
    type Future = Negotiating<Dst, L, Singleton<M, S, G>, S>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.fallback.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: Dst) -> Self::Future {
        let state = match select_upgrade(&self.upgrade) {
            Selection::Existing(future) => State::Upgrade { future },
            Selection::Pending(service) => State::Upgrade {
                future: self.upgrade.call(service),
            },
            Selection::Fallback => {
                let destination = dst.clone();
                State::Fallback {
                    future: Either::Left(self.fallback.call(dst)),
                    fallback: self.fallback.clone(),
                    destination,
                }
            }
        };

        Negotiating {
            state,
            upgrade: self.upgrade.clone(),
            transport: PhantomData,
        }
    }
}

// ===== impl Negotiating =====

impl<Dst, L, M, S, G> Future for Negotiating<Dst, L, Singleton<M, S, G>, S>
where
    L: Service<Dst> + Clone,
    L::Error: Into<BoxError>,
    M: Service<S>,
    M::Response: Clone,
    M::Error: Into<BoxError>,
    Dst: Clone,
    S: Send + 'static,
    G: AsMut<singleton::State<M::Future, M::Response>> + AsMut<Shared<S, M::Future, M::Response>>,
{
    type Output = Result<Negotiated<L::Response, Upgraded<M, S>>, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        loop {
            match this.state.as_mut().project() {
                StateProj::Fallback {
                    future,
                    fallback,
                    destination,
                } => match ready!(future.poll(cx)) {
                    Ok(service) => return Poll::Ready(Ok(Negotiated::Left(service))),
                    Err(error) => {
                        let error = error.into();
                        if !UseOther::is(&*error) {
                            return Poll::Ready(Err(error));
                        }

                        match select_upgrade(this.upgrade) {
                            Selection::Existing(future) => {
                                this.state.set(State::Upgrade { future });
                            }
                            Selection::Pending(service) => {
                                let future = this.upgrade.call(service);
                                this.state.set(State::Upgrade { future });
                            }
                            Selection::Fallback => {
                                let fallback = (*fallback).clone();
                                let destination = (*destination).clone();
                                let future = Oneshot::new(fallback.clone(), destination.clone());
                                this.state.set(State::Fallback {
                                    future: Either::Right(future),
                                    fallback,
                                    destination,
                                });
                            }
                        }
                    }
                },
                StateProj::Upgrade { future } => {
                    return Poll::Ready(
                        ready!(future.poll(cx))
                            .map(Negotiated::Right)
                            .map_err(Into::into),
                    );
                }
            }
        }
    }
}

/// Selects upgraded work atomically and destroys redundant transports unlocked.
#[must_use]
fn select_upgrade<M, S, G>(upgrade: &Singleton<M, S, G>) -> Selection<UpgradeFuture<M, S, G>, S>
where
    M: Service<S>,
    M::Response: Clone,
    G: AsMut<singleton::State<M::Future, M::Response>> + AsMut<Shared<S, M::Future, M::Response>>,
{
    let mut group = upgrade.shared().lock();
    let state: &mut Shared<S, M::Future, M::Response> = group.as_mut();
    let (selection, discarded) = match checkout_existing(upgrade, state) {
        Some((future, discarded)) => (Selection::Existing(future), discarded),
        None => {
            let Some(service) = state.pending.pop_front() else {
                return Selection::Fallback;
            };
            (
                Selection::Pending(service),
                std::mem::take(&mut state.pending),
            )
        }
    };
    drop(group);
    drop(discarded);
    selection
}

/// Selects an existing generation and detaches transports made redundant by it.
#[must_use]
fn checkout_existing<M, S, G>(
    upgrade: &Singleton<M, S, G>,
    state: &mut Shared<S, M::Future, M::Response>,
) -> Option<(UpgradeFuture<M, S, G>, VecDeque<S>)>
where
    M: Service<S>,
    M::Response: Clone,
    G: AsMut<singleton::State<M::Future, M::Response>>,
{
    upgrade
        .checkout(Some(&mut state.upgrade))
        .map(|future| (future, std::mem::take(&mut state.pending)))
}

/// Broadcasts that an upgraded connection has entered the pending queue.
///
/// Each fallback attempt subscribes before it starts connecting and remembers
/// the current wrapping generation. Publishing increments the generation after
/// queue insertion, so a wake always observes either a pending connection or a
/// later state change. The signal is a hint; consumers recover from stale wakes.
#[derive(Clone, Debug)]
pub(super) struct UpgradeSignal {
    /// Wrapping counter incremented whenever an upgraded transport is queued.
    generation: watch::Sender<usize>,
}

// ===== impl UpgradeSignal =====

impl UpgradeSignal {
    /// Creates a signal at generation zero.
    #[must_use]
    pub(super) fn new() -> Self {
        let (generation, _) = watch::channel(0);
        Self { generation }
    }

    /// Waits until a generation newer than this subscription is published.
    fn notified(&self) -> BoxFuture<'static, ()> {
        let mut generation = self.generation.subscribe();
        let current = *generation.borrow_and_update();
        Box::pin(async move {
            loop {
                if generation.changed().await.is_err() {
                    return;
                }
                if *generation.borrow_and_update() != current {
                    return;
                }
            }
        })
    }

    /// Advances the generation and wakes fallback attempts.
    pub(super) fn notify(&self) {
        self.generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

/// Wraps the connector and diverts upgraded results into the pending queue.
///
/// A fallback result passes through unchanged. An upgraded result is queued,
/// followed by a signal to sibling attempts, and the current future returns the
/// private [`UseOther`] marker so [`Negotiating`] switches to the singleton.
pub(super) struct Inspector<M, S, I, G> {
    /// Underlying connector producing raw transports.
    service: M,
    /// Predicate returning `true` for upgraded protocols.
    inspect: I,
    /// Weak handle to the group so a detached background dial never keeps the group alive.
    state: Weak<Mutex<G>>,
    /// Intermediate transport type queued in `state`.
    transport: PhantomData<fn(S)>,
    /// Signal waking sibling fallback attempts after an upgrade is queued.
    signal: UpgradeSignal,
}

pin_project! {
    /// Future that races connection completion against another observed upgrade.
    ///
    /// Checks for upgrades queued before subscription on the first poll, then polls the
    /// notification before the connection future. When its own connection finishes first,
    /// returns fallback transports directly or queues upgraded ones with [`UseOther`].
    pub(super) struct InspectFuture<F, S, I, G> {
        // Underlying connection future.
        #[pin]
        future: F,
        // One-shot check on first poll for upgrades queued before subscribing.
        check_pending: bool,
        // Resolves when a sibling attempt publishes an upgraded transport.
        notified: BoxFuture<'static, ()>,
        // Predicate selecting upgraded transports.
        inspect: I,
        // Weak handle to the group receiving upgraded transports.
        state: Weak<Mutex<G>>,
        // Intermediate transport type queued in `state`.
        transport: PhantomData<fn(S)>,
        // Signal advanced after pushing to `pending`.
        signal: UpgradeSignal,
    }
}

// ===== impl Inspector =====

impl<M: Clone, S, I: Clone, G> Clone for Inspector<M, S, I, G> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            inspect: self.inspect.clone(),
            state: self.state.clone(),
            transport: PhantomData,
            signal: self.signal.clone(),
        }
    }
}

impl<M, S, I, Dst, G> Service<Dst> for Inspector<M, S, I, G>
where
    M: Service<Dst, Response = S>,
    M::Error: Into<BoxError>,
    S: Send + 'static,
    I: Fn(&S) -> bool + Clone,
    G: AsMut<VecDeque<S>>,
{
    type Response = S;
    type Error = BoxError;
    type Future = InspectFuture<M::Future, S, I, G>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: Dst) -> Self::Future {
        InspectFuture {
            future: self.service.call(dst),
            check_pending: true,
            notified: self.signal.notified(),
            inspect: self.inspect.clone(),
            state: self.state.clone(),
            transport: PhantomData,
            signal: self.signal.clone(),
        }
    }
}

// ===== impl InspectFuture =====

impl<F, S, I, E, G> Future for InspectFuture<F, S, I, G>
where
    F: Future<Output = Result<S, E>>,
    E: Into<BoxError>,
    S: Send + 'static,
    I: Fn(&S) -> bool,
    G: AsMut<VecDeque<S>>,
{
    type Output = Result<S, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if std::mem::take(this.check_pending)
            && this
                .state
                .upgrade()
                .is_some_and(|group| !group.lock().as_mut().is_empty())
        {
            return Poll::Ready(Err(UseOther.into()));
        }
        if this.notified.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(UseOther.into()));
        }

        let service = ready!(this.future.poll(cx)).map_err(Into::into)?;
        if (this.inspect)(&service) {
            if let Some(group) = this.state.upgrade() {
                group.lock().as_mut().push_back(service);
                this.signal.notify();
            }
            Poll::Ready(Err(UseOther.into()))
        } else {
            Poll::Ready(Ok(service))
        }
    }
}

impl<F, S, I, E, G> Started for InspectFuture<F, S, I, G>
where
    F: Started + Future<Output = Result<S, E>>,
    E: Into<BoxError>,
    S: Send + 'static,
    I: Fn(&S) -> bool,
    G: AsMut<VecDeque<S>>,
{
    fn started(&self) -> bool {
        Started::started(&self.future)
    }
}

/// Identity maker for a connection already produced by [`Inspector`].
///
/// The upgraded pool expects a make-service interface, but negotiation already owns the
/// physical transport; this zero-sized adapter returns the supplied value immediately.
pub(super) struct Provided<S>(PhantomData<fn(S)>);

// ===== impl Provided =====

impl<S> Clone for Provided<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for Provided<S> {}

impl<S> Service<S> for Provided<S> {
    type Response = S;
    type Error = BoxError;
    type Future = std::future::Ready<Result<S, BoxError>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn call(&mut self, service: S) -> Self::Future {
        std::future::ready(Ok(service))
    }
}

/// Private control-flow marker requesting the upgraded branch.
///
/// It may be wrapped by intermediate service errors, so branch selection walks
/// the source chain rather than relying on the outer error type.
#[derive(Debug)]
struct UseOther;

// ===== impl UseOther =====

impl fmt::Display for UseOther {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("use the other negotiated service")
    }
}

impl std::error::Error for UseOther {}

impl UseOther {
    /// Finds this control-flow marker anywhere in an error source chain.
    #[must_use]
    fn is(error: &(dyn std::error::Error + 'static)) -> bool {
        let mut current = Some(error);
        while let Some(error) = current {
            if error.is::<Self>() {
                return true;
            }
            current = error.source();
        }
        false
    }
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

    impl<S, F, U> AsMut<Self> for Shared<S, F, U> {
        fn as_mut(&mut self) -> &mut Self {
            self
        }
    }

    impl<S, F, U> AsRef<Self> for Shared<S, F, U> {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    /// Returns a fixed protocol label immediately.
    #[derive(Clone, Copy)]
    struct ReadyConnector(&'static str);

    impl Service<()> for ReadyConnector {
        type Response = &'static str;
        type Error = BoxError;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _target: ()) -> Self::Future {
            std::future::ready(Ok(self.0))
        }
    }

    /// Closure-backed [`Layer`] adapter for composing test pools.
    #[derive(Clone, Copy)]
    struct LayerFn<F>(F);

    impl<F, S, Out> Layer<S> for LayerFn<F>
    where
        F: Fn(S) -> Out,
    {
        type Service = Out;

        fn layer(&self, inner: S) -> Self::Service {
            (self.0)(inner)
        }
    }

    /// Enforces `poll_ready` before `call`; returns `UseOther` once, then `"fallback"`.
    struct StrictFallback {
        calls: Arc<AtomicUsize>,
        ready: bool,
    }

    impl Clone for StrictFallback {
        fn clone(&self) -> Self {
            Self {
                calls: self.calls.clone(),
                ready: false,
            }
        }
    }

    impl Service<()> for StrictFallback {
        type Response = &'static str;
        type Error = BoxError;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.ready = true;
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _target: ()) -> Self::Future {
            assert!(self.ready, "fallback called without readiness");
            self.ready = false;

            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                std::future::ready(Err(UseOther.into()))
            } else {
                std::future::ready(Ok("fallback"))
            }
        }
    }

    #[tokio::test]
    async fn inspected_connections_select_the_expected_pool() {
        for (protocol, upgraded) in [("http/1.1", false), ("h2", true)] {
            let negotiate = Negotiate::new(
                ReadyConnector(protocol),
                |protocol: &&str| *protocol == "h2",
                LayerFn(|service| service),
                LayerFn(|maker| Singleton::new(maker, Arc::new(Mutex::new(Shared::default())))),
            );

            let selected = Oneshot::new(negotiate, ()).await.unwrap();
            match selected {
                Negotiated::Left(service) => {
                    assert!(!upgraded);
                    assert_eq!(service, "http/1.1");
                }
                Negotiated::Right(service) => {
                    assert!(upgraded);
                    assert_eq!(*service.inner(), "h2");
                }
            }
        }
    }

    #[tokio::test]
    async fn negotiation_recovers_stale_signal_and_discards_redundant_upgrade() {
        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = StrictFallback {
            calls: calls.clone(),
            ready: false,
        };
        let group = Arc::new(Mutex::new(Shared::default()));
        let upgrade = Singleton::new(Provided(PhantomData::<fn(&'static str)>), group.clone());
        let negotiate = Negotiate {
            fallback,
            upgrade,
            transport: PhantomData,
        };

        assert_eq!(
            negotiate.checkout_ready(
                |_, _| true,
                |_, _| Some("idle"),
                |service| *service.inner(),
                |service| service,
            ),
            Some("idle")
        );
        std::assert_matches!(
            Oneshot::new(negotiate, ()).await.unwrap(),
            Negotiated::Left("fallback")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = StrictFallback {
            calls: calls.clone(),
            ready: false,
        };
        let group = Arc::new(Mutex::new(Shared::default()));
        let upgrade = Singleton::new(Provided(PhantomData::<fn(&'static str)>), group.clone());
        let _ = Oneshot::new(upgrade.clone(), "existing").await.unwrap();
        group.lock().pending.extend(["redundant-a", "redundant-b"]);
        let negotiate = Negotiate {
            fallback,
            upgrade,
            transport: PhantomData,
        };

        let checkout_ready = || {
            negotiate.checkout_ready(
                |_, _| true,
                |_, _| Some("fallback"),
                |service| *service.inner(),
                |service| service,
            )
        };
        assert!(checkout_ready().is_none());
        let (existing, discarded) = negotiate.checkout_existing().unwrap();
        assert_eq!(discarded, ["redundant-a", "redundant-b"]);
        assert_eq!(*existing.await.unwrap().inner(), "existing");
        assert!(group.lock().pending.is_empty());
        assert_eq!(checkout_ready(), Some("existing"));
        group.lock().pending.extend(["redundant-a", "redundant-b"]);

        let Negotiated::Right(service) = Oneshot::new(negotiate, ()).await.unwrap() else {
            panic!("existing upgraded service should be preferred");
        };
        assert_eq!(*service.inner(), "existing");
        assert!(group.lock().pending.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let signal = UpgradeSignal::new();
        signal.notify();
        let group = Arc::new(Mutex::new(Shared::<_, (), ()>::default()));
        group.lock().pending.push_back("queued-before-subscribe");
        let error = InspectFuture {
            future: std::future::pending::<Result<&'static str, BoxError>>(),
            check_pending: true,
            notified: signal.notified(),
            inspect: |_: &&str| false,
            state: Arc::downgrade(&group),
            transport: PhantomData,
            signal,
        }
        .await
        .expect_err("the queued upgrade should win despite the missed notification");
        assert!(UseOther::is(&*error));
    }
}
