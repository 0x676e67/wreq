//! Selects a pool after inspecting a newly established connection.
//!
//! Unlike request routing, negotiation chooses from an intermediate connection
//! result. wreq uses the fallback path to establish a transport and inspect its
//! ALPN result. HTTP/1 stays in the fallback cache, while HTTP/2 is handed to the
//! upgraded singleton.
//!
//! An upgraded result enters the pending queue before [`UpgradeSignal`] wakes
//! concurrent fallback attempts. Selection checks the singleton and removes queued
//! transports under the pending lock; maker calls and future polling happen afterward.
//! A stale notification starts a fresh fallback attempt if no upgraded work remains.

use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
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
    singleton::{Singled, Singleton, SingletonFuture},
};
use crate::sync::Mutex;

/// Selects a fallback or upgraded pool from an intermediate connection result.
///
/// `fallback` owns the connection maker and inspector. `upgrade` accepts
/// connections already selected by that inspector. The pending queue bridges
/// the two service graphs without requiring the upgraded pool to reconnect.
///
/// Clones share the pending queue and the state inside both child pools. A
/// checkout first joins an existing upgraded service, then consumes a queued
/// connection, and only then starts the fallback path. This keeps redundant
/// pending transports out of an already active singleton. Pending transports
/// removed during a race are returned to the caller for destruction outside the
/// negotiation lock.
pub(super) struct Negotiate<L, R, S> {
    /// Pool used when inspection rejects the upgraded protocol.
    fallback: L,

    /// Pool used when inspection accepts the upgraded protocol.
    upgrade: R,

    /// Upgraded connections waiting to enter the singleton.
    pending: Arc<Mutex<VecDeque<S>>>,
}

/// A checked-out service selected by [`Negotiate`].
///
/// `Left` is the fallback service and `Right` is the upgraded service.
pub(super) type Negotiated<L, R> = ServiceEither<L, R>;

pin_project! {
    /// Future that completes the currently selected pool path.
    ///
    /// The fallback state retains a clone of the fallback service and its
    /// destination. They are used only when an upgrade notification is stale and
    /// a replacement connection must be started with a fresh readiness cycle.
    /// The upgrade state owns the singleton checkout future after handoff.
    pub(super) struct Negotiating<Dst, L, R, S>
    where
        L: Service<Dst>,
        R: Service<S>,
    {
        // Fallback or upgraded future currently being polled.
        #[pin]
        state: State<Dst, L, Either<L::Future, Oneshot<L, Dst>>, R::Future>,
        // Clone used to join or start the upgraded singleton after handoff.
        upgrade: R,
        // Upgraded connection queue shared with inspectors.
        pending: Arc<Mutex<VecDeque<S>>>,
    }
}

pin_project! {
    #[project = StateProj]
    /// Active branch of one negotiation future.
    ///
    /// A future starts in `Fallback` unless a queued or existing upgraded
    /// service was available. `UseOther` moves it to `Upgrade`; a stale signal
    /// creates a new fallback future in the same state.
    enum State<Dst, L, FL, FR> {
        /// Establishes and inspects a connection through the fallback path.
        Fallback {
            #[pin]
            future: FL,
            // Fallback pool retained only for a stale-signal retry.
            fallback: L,
            // Destination retained only for a stale-signal retry.
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
type UpgradeFuture<M, S> = SingletonFuture<<M as Service<S>>::Future, <M as Service<S>>::Response>;

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
            pending: self.pending.clone(),
        }
    }
}

impl<L, R, S> Negotiate<L, R, S> {
    /// Composes both pools around one inspected connection service.
    ///
    /// `fallback` wraps `connect`, whose results `inspect` may divert to the
    /// pending queue; `upgrade` wraps the identity maker those results enter.
    pub(super) fn new<C, I, LL, RR>(connect: C, inspect: I, fallback: LL, upgrade: RR) -> Self
    where
        I: Fn(&S) -> bool,
        LL: Layer<Inspector<C, S, I>, Service = L>,
        RR: Layer<Provided<S>, Service = R>,
    {
        let pending = Arc::new(Mutex::new(VecDeque::new()));
        let fallback = fallback.layer(Inspector {
            service: connect,
            inspect,
            pending: pending.clone(),
            signal: UpgradeSignal::new(),
        });
        Self {
            fallback,
            upgrade: upgrade.layer(Provided(PhantomData)),
            pending,
        }
    }

    /// Borrows the fallback pool.
    pub(super) fn fallback(&self) -> &L {
        &self.fallback
    }

    /// Mutably borrows the fallback pool.
    pub(super) fn fallback_mut(&mut self) -> &mut L {
        &mut self.fallback
    }

    /// Borrows the upgraded pool.
    pub(super) fn upgrade(&self) -> &R {
        &self.upgrade
    }

    /// Mutably borrows the upgraded pool.
    pub(super) fn upgrade_mut(&mut self) -> &mut R {
        &mut self.upgrade
    }

    /// Retains queued upgraded connections selected by `predicate`.
    pub(super) fn retain_pending<F>(&mut self, predicate: F) -> VecDeque<S>
    where
        F: FnMut(&S) -> bool,
    {
        let mut predicate = predicate;
        let mut pending = self.pending.lock();
        let mut discarded = VecDeque::new();

        for _ in 0..pending.len() {
            match pending.pop_front() {
                Some(service) if predicate(&service) => pending.push_back(service),
                Some(service) => discarded.push_back(service),
                None => break,
            }
        }

        discarded
    }

    /// Removes every queued upgraded connection for unlocked destruction.
    pub(super) fn drain_pending(&mut self) -> VecDeque<S> {
        std::mem::take(&mut *self.pending.lock())
    }

    /// Returns whether no upgraded connection is waiting for handoff.
    pub(super) fn pending_is_empty(&self) -> bool {
        self.pending.lock().is_empty()
    }
}

impl<L, M, S> Negotiate<L, Singleton<M, S>, S>
where
    M: Service<S>,
    M::Response: Clone,
{
    /// Joins existing upgraded work without invoking the fallback service.
    /// Returns redundant transports for destruction outside any caller-held lock.
    pub(super) fn checkout_existing(&self) -> Option<(UpgradeFuture<M, S>, VecDeque<S>)> {
        checkout_existing(&self.upgrade, &mut self.pending.lock())
    }
}

impl<L, M, S, Dst> Service<Dst> for Negotiate<L, Singleton<M, S>, S>
where
    L: Service<Dst> + Clone,
    L::Error: Into<BoxError>,
    M: Service<S> + Clone,
    M::Response: Clone,
    M::Error: Into<BoxError>,
    Dst: Clone,
    S: Send + 'static,
{
    type Response = Negotiated<L::Response, Singled<M::Future, M::Response>>;
    type Error = BoxError;
    type Future = Negotiating<Dst, L, Singleton<M, S>, S>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.fallback.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: Dst) -> Self::Future {
        let state = match select_upgrade(&self.upgrade, &self.pending) {
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
            pending: self.pending.clone(),
        }
    }
}

// ===== impl Negotiating =====

impl<Dst, L, M, S> Future for Negotiating<Dst, L, Singleton<M, S>, S>
where
    L: Service<Dst> + Clone,
    L::Error: Into<BoxError>,
    M: Service<S>,
    M::Response: Clone,
    M::Error: Into<BoxError>,
    Dst: Clone,
    S: Send + 'static,
{
    type Output = Result<Negotiated<L::Response, Singled<M::Future, M::Response>>, BoxError>;

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

                        match select_upgrade(this.upgrade, this.pending) {
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
fn select_upgrade<M, S>(
    upgrade: &Singleton<M, S>,
    pending: &Mutex<VecDeque<S>>,
) -> Selection<UpgradeFuture<M, S>, S>
where
    M: Service<S>,
    M::Response: Clone,
{
    let mut pending = pending.lock();
    let (selection, discarded) = match checkout_existing(upgrade, &mut pending) {
        Some((future, discarded)) => (Selection::Existing(future), discarded),
        None => {
            let Some(service) = pending.pop_front() else {
                return Selection::Fallback;
            };
            (Selection::Pending(service), std::mem::take(&mut *pending))
        }
    };
    drop(pending);
    drop(discarded);
    selection
}

/// Selects an existing generation and detaches transports made redundant by it.
fn checkout_existing<M, S>(
    upgrade: &Singleton<M, S>,
    pending: &mut VecDeque<S>,
) -> Option<(UpgradeFuture<M, S>, VecDeque<S>)>
where
    M: Service<S>,
    M::Response: Clone,
{
    upgrade
        .checkout()
        .map(|future| (future, std::mem::take(pending)))
}

/// Broadcasts that an upgraded connection has entered the pending queue.
///
/// Each fallback attempt subscribes before it starts connecting and remembers
/// the current wrapping generation. Publishing increments the generation after
/// queue insertion, so a wake always observes either a pending connection or a
/// later state change. The signal is a hint; consumers recover from stale wakes.
#[derive(Clone, Debug)]
pub(super) struct UpgradeSignal {
    generation: watch::Sender<usize>,
}

// ===== impl UpgradeSignal =====

impl UpgradeSignal {
    /// Creates a signal at generation zero.
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
pub(super) struct Inspector<M, S, I> {
    /// Intermediate connection service.
    service: M,

    /// Predicate selecting the upgraded protocol.
    inspect: I,

    /// Queue consumed by the upgraded pool.
    pending: Arc<Mutex<VecDeque<S>>>,

    /// Notification shared by concurrent fallback attempts.
    signal: UpgradeSignal,
}

pin_project! {
    /// Future that races connection completion against another observed upgrade.
    ///
    /// The notification is polled first. If another attempt has already queued
    /// an upgraded connection, this future yields to that shared result. When its
    /// own connection completes first, the inspector either returns it through
    /// the fallback path or publishes it for upgrade handoff.
    pub(super) struct InspectFuture<F, S, I> {
        // Intermediate connection future.
        #[pin]
        future: F,

        // Checks once for an upgrade queued before this subscription existed.
        check_pending: bool,

        // Notification that another attempt produced an upgraded connection.
        notified: BoxFuture<'static, ()>,

        // Predicate selecting the upgraded protocol.
        inspect: I,

        // Queue receiving this result when it upgrades.
        pending: Arc<Mutex<VecDeque<S>>>,

        // Signal advanced after the result is queued.
        signal: UpgradeSignal,
    }
}

// ===== impl Inspector =====

impl<M: Clone, S, I: Clone> Clone for Inspector<M, S, I> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            inspect: self.inspect.clone(),
            pending: self.pending.clone(),
            signal: self.signal.clone(),
        }
    }
}

impl<M, S, I, Dst> Service<Dst> for Inspector<M, S, I>
where
    M: Service<Dst, Response = S>,
    M::Error: Into<BoxError>,
    S: Send + 'static,
    I: Fn(&S) -> bool + Clone,
{
    type Response = S;
    type Error = BoxError;
    type Future = InspectFuture<M::Future, S, I>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: Dst) -> Self::Future {
        InspectFuture {
            future: self.service.call(dst),
            check_pending: true,
            notified: self.signal.notified(),
            inspect: self.inspect.clone(),
            pending: self.pending.clone(),
            signal: self.signal.clone(),
        }
    }
}

// ===== impl InspectFuture =====

impl<F, S, I, E> Future for InspectFuture<F, S, I>
where
    F: Future<Output = Result<S, E>>,
    E: Into<BoxError>,
    S: Send + 'static,
    I: Fn(&S) -> bool,
{
    type Output = Result<S, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if std::mem::take(this.check_pending) && !this.pending.lock().is_empty() {
            return Poll::Ready(Err(UseOther.into()));
        }
        if this.notified.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(UseOther.into()));
        }

        let service = ready!(this.future.poll(cx)).map_err(Into::into)?;
        if (this.inspect)(&service) {
            this.pending.lock().push_back(service);
            this.signal.notify();
            Poll::Ready(Err(UseOther.into()))
        } else {
            Poll::Ready(Ok(service))
        }
    }
}

impl<F, S, I, E> Started for InspectFuture<F, S, I>
where
    F: Started + Future<Output = Result<S, E>>,
    E: Into<BoxError>,
    S: Send + 'static,
    I: Fn(&S) -> bool,
{
    fn started(&self) -> bool {
        Started::started(&self.future)
    }
}

/// Identity maker for a connection already produced by the inspector.
///
/// The upgraded pool expects a make-service interface, but negotiation already
/// owns the physical connection. This zero-sized adapter returns that supplied
/// value unchanged and performs no readiness or allocation work.
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

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

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

    /// Immediately returns the protocol label supplied by the test.
    /// Substitutes for transport creation when testing protocol selection.
    /// The static label is shared without allocating a connection.
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

    /// Small layer adapter used to compose the two test pool paths.
    /// Applies its closure to the supplied inner service during construction.
    /// The returned service owns runtime state; this adapter owns only the closure.
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

    /// Fallback service that rejects calls not preceded by readiness.
    /// Its first call emits an upgrade signal; later calls return a fallback label.
    /// Clones share the call count but must acquire their own readiness.
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
                LayerFn(Singleton::new),
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
        let upgrade = Singleton::new(Provided(PhantomData::<fn(&'static str)>));
        let negotiate = Negotiate {
            fallback,
            upgrade,
            pending: Arc::new(Mutex::new(VecDeque::new())),
        };

        assert!(matches!(
            Oneshot::new(negotiate, ()).await.unwrap(),
            Negotiated::Left("fallback")
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = StrictFallback {
            calls: calls.clone(),
            ready: false,
        };
        let upgrade = Singleton::new(Provided(PhantomData::<fn(&'static str)>));
        drop(Oneshot::new(upgrade.clone(), "existing").await.unwrap());
        let pending = Arc::new(Mutex::new(VecDeque::from(["redundant-a", "redundant-b"])));
        let negotiate = Negotiate {
            fallback,
            upgrade,
            pending: pending.clone(),
        };

        let (existing, discarded) = negotiate.checkout_existing().unwrap();
        assert_eq!(discarded, ["redundant-a", "redundant-b"]);
        assert_eq!(*existing.await.unwrap().inner(), "existing");
        assert!(pending.lock().is_empty());
        pending.lock().extend(["redundant-a", "redundant-b"]);

        let Negotiated::Right(service) = Oneshot::new(negotiate, ()).await.unwrap() else {
            panic!("existing upgraded service should be preferred");
        };
        assert_eq!(*service.inner(), "existing");
        assert!(pending.lock().is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let signal = UpgradeSignal::new();
        signal.notify();
        let pending = Arc::new(Mutex::new(VecDeque::from(["queued-before-subscribe"])));
        let error = InspectFuture {
            future: std::future::pending::<Result<&'static str, BoxError>>(),
            check_pending: true,
            notified: signal.notified(),
            inspect: |_: &&str| false,
            pending,
            signal,
        }
        .await
        .expect_err("the queued upgrade should win despite the missed notification");
        assert!(UseOther::is(&*error));
    }
}
