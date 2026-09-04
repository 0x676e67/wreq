//! Selects a pool after inspecting a newly established connection.
//!
//! Unlike request routing, negotiation chooses from an intermediate connection
//! result. wreq uses this for ALPN: HTTP/1 enters the fallback cache, while an
//! HTTP/2 connection enters the singleton pool shared by concurrent requests.
//!
//! The first upgraded result is queued before a generation signal wakes other
//! fallback attempts. The queue lock also covers the handoff into `Singleton`,
//! ensuring each waiter either consumes the result or observes the in-progress
//! singleton without a lost-notification window.

use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{self, Poll, ready},
};

use futures_util::future::BoxFuture;
use pin_project_lite::pin_project;
use tokio::sync::watch;
use tower::{BoxError, Layer, Service};

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
pub(super) struct Negotiate<L, R, S> {
    /// Pool used when inspection rejects the upgraded protocol.
    fallback: L,
    /// Pool used when inspection accepts the upgraded protocol.
    upgrade: R,
    /// Upgraded connections waiting to enter the singleton.
    pending: Arc<Mutex<VecDeque<S>>>,
}

/// A service selected by [`Negotiate`].
#[derive(Clone, Debug)]
pub(super) enum Negotiated<L, R> {
    /// Service produced by the fallback pool.
    Fallback(L),
    /// Service produced by the upgraded pool.
    Upgraded(R),
}

pin_project! {
    /// Future that completes the currently selected pool path.
    pub(super) struct Negotiating<Dst, L, R, S>
    where
        L: Service<Dst>,
        R: Service<S>,
    {
        // Fallback or upgraded future currently being polled.
        #[pin]
        state: State<L::Future, R::Future>,
        // Clone used to join or start the upgraded singleton after handoff.
        upgrade: R,
        // Upgraded connection queue shared with inspectors.
        pending: Arc<Mutex<VecDeque<S>>>,
    }
}

pin_project! {
    #[project = StateProj]
    /// Active branch of one negotiation future.
    enum State<FL, FR> {
        /// Establishes and inspects a connection through the fallback path.
        Fallback {
            #[pin]
            future: FL,
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
    pub(super) enum NegotiatedFuture<L, R> {
        /// Future returned by the fallback service.
        Fallback { #[pin] future: L },
        /// Future returned by the upgraded service.
        Upgraded { #[pin] future: R },
    }
}

/// Type-state builder for the connector, inspector, and two pool layers.
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

/// Builder marker requiring a connector.
#[derive(Debug)]
pub(super) struct WantsConnect;
/// Builder marker requiring an inspection predicate.
#[derive(Debug)]
pub(super) struct WantsInspect;
/// Builder marker requiring a fallback layer.
#[derive(Debug)]
pub(super) struct WantsFallback;
/// Builder marker requiring an upgrade layer.
#[derive(Debug)]
pub(super) struct WantsUpgrade;

/// Checks out a service only when one exists or is already being constructed.
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
    pub(super) fn retain_pending<F>(&mut self, predicate: F)
    where
        F: FnMut(&S) -> bool,
    {
        self.pending.lock().retain(predicate);
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
    L: Service<Dst>,
    L::Error: Into<BoxError>,
    R: Existing<S> + Clone,
    R::Error: Into<BoxError>,
    S: Send + 'static,
{
    type Response = Negotiated<L::Response, R::Response>;
    type Error = BoxError;
    type Future = Negotiating<Dst, L, R, S>;

    /// Uses fallback readiness because it owns the connection maker.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.fallback.poll_ready(cx).map_err(Into::into)
    }

    /// Prefers a queued or existing upgraded service before starting fallback.
    ///
    /// The pending lock spans queue consumption and singleton handoff so a
    /// concurrent inspector cannot publish an upgrade between those steps.
    fn call(&mut self, dst: Dst) -> Self::Future {
        let mut pending = self.pending.lock();
        let state = if let Some(service) = pending.pop_front() {
            State::Upgrade {
                future: self.upgrade.call(service),
            }
        } else if let Some(future) = self.upgrade.checkout() {
            State::Upgrade { future }
        } else {
            State::Fallback {
                future: self.fallback.call(dst),
            }
        };
        drop(pending);
        Negotiating {
            state,
            upgrade: self.upgrade.clone(),
            pending: self.pending.clone(),
        }
    }
}

impl<Dst, L, R, S> Future for Negotiating<Dst, L, R, S>
where
    L: Service<Dst>,
    L::Error: Into<BoxError>,
    R: Existing<S>,
    R::Error: Into<BoxError>,
    S: Send + 'static,
{
    type Output = Result<Negotiated<L::Response, R::Response>, BoxError>;

    /// Completes fallback or switches to the upgraded pool after inspection.
    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        loop {
            match this.state.as_mut().project() {
                StateProj::Fallback { future } => match ready!(future.poll(cx)) {
                    Ok(service) => return Poll::Ready(Ok(Negotiated::Fallback(service))),
                    Err(error) => {
                        let error = error.into();
                        if !UseOther::is(&*error) {
                            return Poll::Ready(Err(error));
                        }

                        let mut pending = this.pending.lock();
                        let future = if let Some(service) = pending.pop_front() {
                            this.upgrade.call(service)
                        } else if let Some(future) = this.upgrade.checkout() {
                            future
                        } else {
                            return Poll::Ready(Err(InvalidState.into()));
                        };
                        drop(pending);
                        this.state.set(State::Upgrade { future });
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
    pub(super) struct InspectFuture<F, S, I> {
        // Intermediate connection future.
        #[pin]
        future: F,
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

/// Internal control-flow error requesting the upgraded branch.
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

/// Indicates that an upgrade signal had no queued or shared service.
#[derive(Debug)]
struct InvalidState;

impl fmt::Display for InvalidState {
    /// Writes the inconsistent negotiation state message.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("protocol negotiation state is unavailable")
    }
}

impl std::error::Error for InvalidState {}
