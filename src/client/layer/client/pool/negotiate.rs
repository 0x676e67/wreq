//! Selects a pool after inspecting a newly established connection.
//!
//! Unlike request routing, negotiation chooses from an intermediate connection
//! result. wreq uses the fallback path to establish a transport and inspect its
//! ALPN result. HTTP/1 stays in the fallback cache, while HTTP/2 is handed to the
//! upgraded singleton:
//!
//! ```text
//! connect -> inspect -> HTTP/1 cache
//!                   -> pending HTTP/2 -> singleton
//! ```
//!
//! An upgraded result enters the pending queue before [`UpgradeSignal`] wakes
//! concurrent fallback attempts. Queue consumption and singleton handoff share
//! one lock. If a notification becomes stale because its connection was already
//! consumed or canceled, the affected checkout starts a fresh fallback attempt.
//!
//! # Example
//!
//! The builder composes a connector, an inspection predicate, and one layer for
//! each protocol path:
//!
//! ```rust,ignore
//! let pool = negotiate::builder()
//!     .connect(connector)
//!     .inspect(|established| established.negotiated_h2())
//!     .fallback(http1_cache_layer)
//!     .upgrade(http2_singleton_layer)
//!     .build();
//! ```

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
use tower::{BoxError, Layer, Service, util::Oneshot};

use crate::sync::Mutex;

/// Starts configuring a protocol-negotiating pool.
pub(super) fn builder() -> Builder<WantsConnect, WantsInspect, WantsFallback, WantsUpgrade> {
    Builder {
        connect: WantsConnect,
        inspect: WantsInspect,
        fallback: WantsFallback,
        upgrade: WantsUpgrade,
    }
}

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
/// The enum keeps the two concrete service types without boxing. Its `Service`
/// implementation delegates readiness and requests to the selected variant.
#[derive(Clone, Debug)]
pub(super) enum Negotiated<L, R> {
    /// Service produced by the fallback pool.
    Fallback(L),
    /// Service produced by the upgraded pool.
    Upgraded(R),
}

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

pin_project! {
    #[project = NegotiatedFutureProj]
    /// Request future delegated to the selected service type.
    ///
    /// This enum provides static dispatch for the different future types
    /// returned by fallback and upgraded services.
    pub(super) enum NegotiatedFuture<L, R> {
        /// Future returned by the fallback service.
        Fallback { #[pin] future: L },
        /// Future returned by the upgraded service.
        Upgraded { #[pin] future: R },
    }
}

/// Type-state builder for the connector, inspector, and two pool layers.
///
/// Each setter replaces one marker with its concrete component. `build` is
/// available only after the connector, inspection predicate, fallback layer,
/// and upgrade layer have compatible service types.
#[derive(Debug)]
pub(super) struct Builder<C, I, L, R> {
    /// Service that establishes the intermediate connection.
    connect: C,
    /// Predicate selecting the upgraded path.
    inspect: I,
    /// Layer applied to fallback connections.
    fallback: L,
    /// Layer applied to upgraded connections.
    upgrade: R,
}

/// Type-state marker indicating that the connector has not been supplied.
#[derive(Debug)]
pub(super) struct WantsConnect;
/// Type-state marker indicating that the inspection predicate is missing.
#[derive(Debug)]
pub(super) struct WantsInspect;
/// Type-state marker indicating that the fallback layer is missing.
#[derive(Debug)]
pub(super) struct WantsFallback;
/// Type-state marker indicating that the upgrade layer is missing.
#[derive(Debug)]
pub(super) struct WantsUpgrade;

/// Checks out a service only when one exists or is already being constructed.
///
/// Negotiation uses this operation before starting another physical connection.
/// Unlike `Service::call`, an empty implementation must return `None` and leave
/// its maker untouched.
pub(super) trait Existing<S>: Service<S> {
    /// Joins existing upgraded state without starting a new maker.
    fn checkout(&self) -> Option<Self::Future>;
}

impl<C, I, L, R> Builder<C, I, L, R> {
    /// Sets the service that creates intermediate connections.
    pub(super) fn connect<CC>(self, connect: CC) -> Builder<CC, I, L, R> {
        Builder {
            connect,
            inspect: self.inspect,
            fallback: self.fallback,
            upgrade: self.upgrade,
        }
    }

    /// Sets the predicate that identifies upgraded connections.
    pub(super) fn inspect<II>(self, inspect: II) -> Builder<C, II, L, R> {
        Builder {
            connect: self.connect,
            inspect,
            fallback: self.fallback,
            upgrade: self.upgrade,
        }
    }

    /// Sets the layer used for fallback connections.
    pub(super) fn fallback<LL>(self, fallback: LL) -> Builder<C, I, LL, R> {
        Builder {
            connect: self.connect,
            inspect: self.inspect,
            fallback,
            upgrade: self.upgrade,
        }
    }

    /// Sets the layer used for upgraded connections.
    pub(super) fn upgrade<RR>(self, upgrade: RR) -> Builder<C, I, L, RR> {
        Builder {
            connect: self.connect,
            inspect: self.inspect,
            fallback: self.fallback,
            upgrade,
        }
    }

    /// Builds the negotiating pool after all components are supplied.
    pub(super) fn build<Dst>(self) -> Negotiate<L::Service, R::Service, C::Response>
    where
        C: Service<Dst>,
        C::Error: Into<BoxError>,
        C::Response: Send + 'static,
        L: Layer<Inspector<C, C::Response, I>>,
        L::Service: Service<Dst> + Clone,
        <L::Service as Service<Dst>>::Error: Into<BoxError>,
        R: Layer<Provided<C::Response>>,
        R::Service: Existing<C::Response> + Clone,
        <R::Service as Service<C::Response>>::Error: Into<BoxError>,
        I: Fn(&C::Response) -> bool + Clone,
    {
        let pending = Arc::new(Mutex::new(VecDeque::new()));
        let signal = UpgradeSignal::new();
        let fallback = self.fallback.layer(Inspector {
            service: self.connect,
            inspect: self.inspect,
            pending: pending.clone(),
            signal,
        });
        let upgrade = self.upgrade.layer(Provided(PhantomData));
        Negotiate {
            fallback,
            upgrade,
            pending,
        }
    }
}

impl<L: Clone, R: Clone, S> Clone for Negotiate<L, R, S> {
    /// Clones both pool handles while sharing the pending upgrade queue.
    fn clone(&self) -> Self {
        Self {
            fallback: self.fallback.clone(),
            upgrade: self.upgrade.clone(),
            pending: self.pending.clone(),
        }
    }
}

impl<L, R, S> Negotiate<L, R, S> {
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
    pub(super) fn retain_pending<F>(&mut self, predicate: F) -> Vec<S>
    where
        F: FnMut(&S) -> bool,
    {
        {
            let mut predicate = predicate;
            let mut pending = self.pending.lock();
            let mut discarded = Vec::new();
            let mut index = 0;

            while index < pending.len() {
                if predicate(&pending[index]) {
                    index += 1;
                } else {
                    let Some(service) = pending.remove(index) else {
                        break;
                    };
                    discarded.push(service);
                }
            }

            discarded
        }
    }

    /// Removes the first queued upgraded connection matching `predicate`.
    pub(super) fn take_pending_if<F>(&mut self, predicate: F) -> Option<S>
    where
        F: Fn(&S) -> bool,
    {
        let mut pending = self.pending.lock();
        let index = pending.iter().position(predicate)?;
        pending.remove(index)
    }

    /// Returns whether no upgraded connection is waiting for handoff.
    pub(super) fn pending_is_empty(&self) -> bool {
        self.pending.lock().is_empty()
    }
}

impl<L, R, S, Dst> Service<Dst> for Negotiate<L, R, S>
where
    L: Service<Dst> + Clone,
    L::Error: Into<BoxError>,
    R: Existing<S> + Clone,
    R::Error: Into<BoxError>,
    Dst: Clone,
    S: Send + 'static,
{
    type Response = Negotiated<L::Response, R::Response>;
    type Error = BoxError;
    type Future = Negotiating<Dst, L, R, S>;

    /// Uses fallback readiness because it owns the connection maker.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.fallback.poll_ready(cx).map_err(Into::into)
    }

    /// Prefers an existing or queued upgraded service before starting fallback.
    ///
    /// The pending lock spans queue consumption and singleton handoff so a
    /// concurrent inspector cannot publish an upgrade between those steps.
    fn call(&mut self, dst: Dst) -> Self::Future {
        let mut pending = self.pending.lock();
        let (state, discarded) = if let Some(future) = self.upgrade.checkout() {
            (State::Upgrade { future }, std::mem::take(&mut *pending))
        } else if let Some(service) = pending.pop_front() {
            (
                State::Upgrade {
                    future: self.upgrade.call(service),
                },
                std::mem::take(&mut *pending),
            )
        } else {
            let destination = dst.clone();
            (
                State::Fallback {
                    future: Either::Left(self.fallback.call(dst)),
                    fallback: self.fallback.clone(),
                    destination,
                },
                VecDeque::new(),
            )
        };
        drop(pending);
        drop(discarded);
        Negotiating {
            state,
            upgrade: self.upgrade.clone(),
            pending: self.pending.clone(),
        }
    }
}

impl<Dst, L, R, S> Future for Negotiating<Dst, L, R, S>
where
    L: Service<Dst> + Clone,
    L::Error: Into<BoxError>,
    R: Existing<S>,
    R::Error: Into<BoxError>,
    Dst: Clone,
    S: Send + 'static,
{
    type Output = Result<Negotiated<L::Response, R::Response>, BoxError>;

    /// Completes fallback or switches to the upgraded pool after inspection.
    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        loop {
            match this.state.as_mut().project() {
                StateProj::Fallback {
                    future,
                    fallback,
                    destination,
                } => match ready!(future.poll(cx)) {
                    Ok(service) => return Poll::Ready(Ok(Negotiated::Fallback(service))),
                    Err(error) => {
                        let error = error.into();
                        if !UseOther::is(&*error) {
                            return Poll::Ready(Err(error));
                        }

                        let mut pending = this.pending.lock();
                        if let Some(future) = this.upgrade.checkout() {
                            let discarded = std::mem::take(&mut *pending);
                            drop(pending);
                            this.state.set(State::Upgrade { future });
                            drop(discarded);
                        } else if let Some(service) = pending.pop_front() {
                            let future = this.upgrade.call(service);
                            let discarded = std::mem::take(&mut *pending);
                            drop(pending);
                            this.state.set(State::Upgrade { future });
                            drop(discarded);
                        } else {
                            drop(pending);
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
                },
                StateProj::Upgrade { future } => {
                    return Poll::Ready(
                        ready!(future.poll(cx))
                            .map(Negotiated::Upgraded)
                            .map_err(Into::into),
                    );
                }
            }
        }
    }
}

impl<L, R, Req, Res, E> Service<Req> for Negotiated<L, R>
where
    L: Service<Req, Response = Res, Error = E>,
    R: Service<Req, Response = Res, Error = E>,
{
    type Response = Res;
    type Error = E;
    type Future = NegotiatedFuture<L::Future, R::Future>;

    /// Delegates readiness to the selected service.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::Fallback(service) => service.poll_ready(cx),
            Self::Upgraded(service) => service.poll_ready(cx),
        }
    }

    /// Sends a request through the selected service.
    fn call(&mut self, req: Req) -> Self::Future {
        match self {
            Self::Fallback(service) => NegotiatedFuture::Fallback {
                future: service.call(req),
            },
            Self::Upgraded(service) => NegotiatedFuture::Upgraded {
                future: service.call(req),
            },
        }
    }
}

impl<L, R, Out> Future for NegotiatedFuture<L, R>
where
    L: Future<Output = Out>,
    R: Future<Output = Out>,
{
    type Output = Out;

    /// Polls the request future returned by the selected service.
    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            NegotiatedFutureProj::Fallback { future } => future.poll(cx),
            NegotiatedFutureProj::Upgraded { future } => future.poll(cx),
        }
    }
}

/// Broadcasts that an upgraded connection has entered the pending queue.
///
/// Each fallback attempt subscribes before it starts connecting and remembers
/// the current wrapping generation. Publishing increments the generation after
/// queue insertion, so a wake always observes either a pending connection or a
/// later state change. The signal is a hint; consumers recover from stale wakes.
#[derive(Clone)]
struct UpgradeSignal {
    /// Wrapping generation observed by each fallback attempt.
    generation: watch::Sender<usize>,
}

impl UpgradeSignal {
    /// Creates a signal at generation zero.
    fn new() -> Self {
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
    fn notify(&self) {
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
        #[pin]
        notified: BoxFuture<'static, ()>,
        // Predicate selecting the upgraded protocol.
        inspect: I,
        // Queue receiving this result when it upgrades.
        pending: Arc<Mutex<VecDeque<S>>>,
        // Signal advanced after the result is queued.
        signal: UpgradeSignal,
    }
}

impl<M: Clone, S, I: Clone> Clone for Inspector<M, S, I> {
    /// Clones connector state while sharing the queue and signal.
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

    /// Delegates readiness to the intermediate connection service.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(Into::into)
    }

    /// Starts an inspected connection attempt with its own signal subscription.
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

impl<F, S, I, E> Future for InspectFuture<F, S, I>
where
    F: Future<Output = Result<S, E>>,
    E: Into<BoxError>,
    S: Send + 'static,
    I: Fn(&S) -> bool,
{
    type Output = Result<S, BoxError>;

    /// Returns fallback results directly and queues upgraded results for handoff.
    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if std::mem::take(this.check_pending) && !this.pending.lock().is_empty() {
            return Poll::Ready(Err(UseOther.into()));
        }
        if this.notified.poll(cx).is_ready() {
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

impl<F, S, I, E> super::cache::Started for InspectFuture<F, S, I>
where
    F: super::cache::Started + Future<Output = Result<S, E>>,
    E: Into<BoxError>,
    S: Send + 'static,
    I: Fn(&S) -> bool,
{
    /// Reports whether the underlying connection attempt began useful work.
    fn started(&self) -> bool {
        super::cache::Started::started(&self.future)
    }
}

/// Identity maker for a connection already produced by the inspector.
///
/// The upgraded pool expects a make-service interface, but negotiation already
/// owns the physical connection. This zero-sized adapter returns that supplied
/// value unchanged and performs no readiness or allocation work.
pub(super) struct Provided<S>(PhantomData<fn(S)>);

impl<S> Clone for Provided<S> {
    /// Copies the zero-sized identity maker.
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for Provided<S> {}

impl<S> Service<S> for Provided<S> {
    type Response = S;
    type Error = BoxError;
    type Future = std::future::Ready<Result<S, BoxError>>;

    /// Identity construction is always ready.
    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Returns the supplied connection unchanged.
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

impl fmt::Display for UseOther {
    /// Writes the internal branch-switch reason.
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
    use crate::client::layer::client::pool::singleton::Singleton;

    /// Fallback service that rejects calls not preceded by readiness.
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
            Negotiated::Fallback("fallback")
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

        let Negotiated::Upgraded(service) = Oneshot::new(negotiate, ()).await.unwrap() else {
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
