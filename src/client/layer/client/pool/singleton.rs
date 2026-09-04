//! Shares one cloneable service across concurrent checkouts.
//!
//! `Singleton` fits multiplexed protocols such as HTTP/2: the first checkout
//! drives service creation and later checkouts wait for or clone that service.
//! If the driver is canceled, one waiter takes over the same maker future so
//! useful connection work is not lost.
//!
//! Every creation batch owns a generation marker. Checked-out clones may clear
//! only the generation they came from, preventing a stale failed sender from
//! removing a newer replacement connection.

use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Weak},
    task::{self, Poll, Waker},
};

use tokio::sync::oneshot;
use tower::{BoxError, Service};

use crate::sync::Mutex;

/// A pool that creates at most one shared cloneable service at a time.
#[derive(Debug)]
pub(super) struct Singleton<M, Dst>
where
    M: Service<Dst>,
{
    /// Creates the shared service when the singleton is empty.
    maker: M,
    /// Shared empty, creating, or created state.
    state: Arc<Mutex<State<M::Future, M::Response>>>,
    /// Carries the destination type without owning a destination.
    _dst: PhantomData<fn(Dst)>,
}

impl<M, Dst> Singleton<M, Dst>
where
    M: Service<Dst>,
    M::Response: Clone,
{
    /// Creates an empty singleton around `maker`.
    pub(super) fn new(maker: M) -> Self {
        Self {
            maker,
            state: Arc::new(Mutex::new(State::Empty)),
            _dst: PhantomData,
        }
    }

    /// Retains the created service when it satisfies `predicate`.
    ///
    /// An in-progress creation is not interrupted.
    pub(super) fn retain<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&mut M::Response) -> bool,
    {
        let mut state = self.state.lock();
        if let State::Made { service, .. } = &mut *state {
            if !predicate(service) {
                *state = State::Empty;
            }
        }
    }

    /// Returns whether no service exists and none is being created.
    pub(super) fn is_empty(&self) -> bool {
        matches!(*self.state.lock(), State::Empty)
    }

    /// Returns whether a completed shared service exists.
    pub(super) fn has_service(&self) -> bool {
        matches!(*self.state.lock(), State::Made { .. })
    }

    /// Joins an existing service or in-progress creation.
    ///
    /// Returns `None` instead of starting the maker when the singleton is empty.
    pub(super) fn checkout(&self) -> Option<SingletonFuture<M::Future, M::Response>> {
        let mut state = self.state.lock();
        match &mut *state {
            State::Empty => None,
            State::Making(batch) => {
                let (id, receiver) = batch.register_waiter();
                Some(SingletonFuture::Participating {
                    id,
                    generation: batch.generation.clone(),
                    state: self.state.clone(),
                    receiver: Some(receiver),
                    reused: true,
                })
            }
            State::Made {
                service,
                generation,
            } => Some(SingletonFuture::Made {
                service: Some(service.clone()),
                generation: generation.clone(),
                state: Arc::downgrade(&self.state),
            }),
        }
    }

    /// Removes the completed service when it satisfies `predicate`.
    ///
    /// This does not cancel an in-progress creation.
    pub(super) fn try_take_if<F>(&mut self, predicate: F) -> Option<M::Response>
    where
        F: FnOnce(&M::Response) -> bool,
    {
        let mut state = self.state.lock();
        let State::Made { service, .. } = &*state else {
            return None;
        };
        if !predicate(service) {
            return None;
        }

        match std::mem::replace(&mut *state, State::Empty) {
            State::Made { service, .. } => Some(service),
            _ => None,
        }
    }
}

impl<M, Dst> Service<Dst> for Singleton<M, Dst>
where
    M: Service<Dst>,
    M::Response: Clone,
    M::Error: Into<BoxError>,
{
    type Response = Singled<M::Future, M::Response>;
    type Error = SingletonError;
    type Future = SingletonFuture<M::Future, M::Response>;

    /// Polls the maker only while a new shared service is required.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        if matches!(*self.state.lock(), State::Empty) {
            self.maker
                .poll_ready(cx)
                .map_err(|error| SingletonError::new(error.into()))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    /// Starts, joins, or clones the current service creation batch.
    fn call(&mut self, dst: Dst) -> Self::Future {
        let mut state = self.state.lock();
        match &mut *state {
            State::Empty => {
                let mut batch = Batch::new(self.maker.call(dst));
                let id = batch.register_driver();
                let generation = batch.generation.clone();
                *state = State::Making(batch);
                SingletonFuture::Participating {
                    id,
                    generation,
                    state: self.state.clone(),
                    receiver: None,
                    reused: false,
                }
            }
            State::Making(batch) => {
                let (id, receiver) = batch.register_waiter();
                SingletonFuture::Participating {
                    id,
                    generation: batch.generation.clone(),
                    state: self.state.clone(),
                    receiver: Some(receiver),
                    reused: true,
                }
            }
            State::Made {
                service,
                generation,
            } => SingletonFuture::Made {
                service: Some(service.clone()),
                generation: generation.clone(),
                state: Arc::downgrade(&self.state),
            },
        }
    }
}

impl<M, Dst> Clone for Singleton<M, Dst>
where
    M: Service<Dst> + Clone,
{
    /// Creates a handle sharing the same singleton state.
    fn clone(&self) -> Self {
        Self {
            maker: self.maker.clone(),
            state: self.state.clone(),
            _dst: PhantomData,
        }
    }
}

/// Future for a singleton checkout.
///
/// A participant may drive the maker or wait over a oneshot channel. A made
/// future owns an immediately available clone.
pub(super) enum SingletonFuture<F, S> {
    /// Participates in the current creation batch.
    Participating {
        /// Identifier used for cancellation and driver handoff.
        id: WaiterId,
        /// Creation generation this participant belongs to.
        generation: Arc<()>,
        /// Shared singleton state.
        state: Arc<Mutex<State<F, S>>>,
        /// Result channel for a non-driver participant.
        receiver: Option<oneshot::Receiver<Result<S, SharedError>>>,
        /// Whether this checkout joined work started by another caller.
        reused: bool,
    },
    /// Owns a clone of an already-created service.
    Made {
        /// Service returned on the first poll.
        service: Option<S>,
        /// Generation that produced `service`.
        generation: Arc<()>,
        /// Weak state used to invalidate this generation on failure.
        state: Weak<Mutex<State<F, S>>>,
    },
}

/// Safe because the maker future is pinned separately inside [`Batch`].
impl<F, S> Unpin for SingletonFuture<F, S> {}

/// Lifecycle of the shared singleton service.
pub(super) enum State<F, S> {
    /// No service exists and no maker is running.
    Empty,
    /// One participant drives a maker shared by the batch.
    Making(Batch<F, S>),
    /// A completed service is available for cloning.
    Made {
        /// Shared cloneable service.
        service: S,
        /// Identity used to reject invalidation from stale clones.
        generation: Arc<()>,
    },
}

impl<F, S: fmt::Debug> fmt::Debug for State<F, S> {
    /// Formats lifecycle state without exposing maker or waiter internals.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Making(_) => f.write_str("Making"),
            Self::Made { service, .. } => f.debug_tuple("Made").field(service).finish(),
        }
    }
}

/// Coordinates one maker future and every checkout waiting for it.
pub(super) struct Batch<F, S> {
    /// Maker future owned by the current driver.
    future: Option<Pin<Box<F>>>,
    /// Identity shared by all participants and produced clones.
    generation: Arc<()>,
    /// Wrapping participant identifier source.
    next_id: WaiterId,
    /// Participant currently responsible for polling the maker.
    driver: Option<Driver>,
    /// Participants waiting for the driver's result.
    waiters: Vec<Waiter<S>>,
}

/// Identifier for one participant in a creation batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WaiterId(usize);

/// Participant currently polling the shared maker future.
struct Driver {
    /// Driver participant identifier.
    id: WaiterId,
    /// Latest task polling the driver.
    waker: Option<Waker>,
}

/// Non-driver participant waiting for the shared result.
struct Waiter<S> {
    /// Waiter participant identifier.
    id: WaiterId,
    /// Latest task polling this waiter.
    waker: Option<Waker>,
    /// Delivers the shared service or shared maker error.
    sender: oneshot::Sender<Result<S, SharedError>>,
}

/// A checked-out clone of the singleton service.
#[derive(Debug)]
pub(super) struct Singled<F, S> {
    /// Clone used by this checkout.
    inner: S,
    /// Whether another checkout started or created this service.
    reused: bool,
    /// Generation allowed to be invalidated by this checkout.
    generation: Arc<()>,
    /// Weak reference avoids keeping an unused singleton alive.
    state: Weak<Mutex<State<F, S>>>,
}

impl<F, S, E> Future for SingletonFuture<F, S>
where
    F: Future<Output = Result<S, E>>,
    E: Into<BoxError>,
    S: Clone,
{
    type Output = Result<Singled<F, S>, SingletonError>;

    /// Drives the assigned maker or receives the result from the current driver.
    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Participating {
                id,
                generation,
                state,
                receiver,
                reused,
            } => {
                if let Some(rx) = receiver.as_mut() {
                    match Pin::new(rx).poll(cx) {
                        Poll::Ready(Ok(Ok(service))) => {
                            return Poll::Ready(Ok(Singled::new(
                                service,
                                Arc::downgrade(state),
                                generation.clone(),
                                *reused,
                            )));
                        }
                        Poll::Ready(Ok(Err(error))) => {
                            return Poll::Ready(Err(SingletonError(error)));
                        }
                        Poll::Ready(Err(_)) => *receiver = None,
                        Poll::Pending => {}
                    }
                }

                let weak = Arc::downgrade(state);
                let mut locked = state.lock();
                match &mut *locked {
                    State::Making(batch) if Arc::ptr_eq(generation, &batch.generation) => {
                        match batch.poll(*id, cx) {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(Ok(service)) => {
                                batch.send_result(Ok(service.clone()));
                                *locked = State::Made {
                                    service: service.clone(),
                                    generation: generation.clone(),
                                };
                                Poll::Ready(Ok(Singled::new(
                                    service,
                                    weak,
                                    generation.clone(),
                                    *reused,
                                )))
                            }
                            Poll::Ready(Err(error)) => {
                                batch.send_result(Err(error.clone()));
                                *locked = State::Empty;
                                Poll::Ready(Err(SingletonError(error)))
                            }
                        }
                    }
                    State::Made {
                        service,
                        generation: current,
                    } if Arc::ptr_eq(generation, current) => Poll::Ready(Ok(Singled::new(
                        service.clone(),
                        weak,
                        current.clone(),
                        true,
                    ))),
                    State::Making(_) | State::Made { .. } | State::Empty => {
                        Poll::Ready(Err(SingletonError::canceled()))
                    }
                }
            }
            Self::Made {
                service,
                generation,
                state,
            } => match service.take() {
                Some(service) => Poll::Ready(Ok(Singled::new(
                    service,
                    state.clone(),
                    generation.clone(),
                    true,
                ))),
                None => Poll::Pending,
            },
        }
    }
}

impl<F, S> Drop for SingletonFuture<F, S> {
    /// Removes a canceled participant and hands driver ownership to a waiter.
    fn drop(&mut self) {
        if let Self::Participating {
            id,
            generation,
            state,
            ..
        } = self
        {
            let mut locked = state.lock();
            if let State::Making(batch) = &mut *locked {
                if Arc::ptr_eq(generation, &batch.generation) && batch.remove(*id) {
                    *locked = State::Empty;
                }
            }
        }
    }
}

impl<F, S> Singled<F, S> {
    /// Wraps a service clone with its generation and reuse status.
    fn new(inner: S, state: Weak<Mutex<State<F, S>>>, generation: Arc<()>, reused: bool) -> Self {
        Self {
            inner,
            reused,
            generation,
            state,
        }
    }

    /// Borrows the checked-out service clone.
    pub(super) fn inner(&self) -> &S {
        &self.inner
    }

    /// Mutably borrows the checked-out service clone.
    pub(super) fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Returns whether this checkout joined an existing singleton operation.
    pub(super) fn is_reused(&self) -> bool {
        self.reused
    }

    /// Clears the singleton only if it still contains this clone's generation.
    pub(super) fn discard_shared(&self) {
        if let Some(state) = self.state.upgrade() {
            let mut state = state.lock();
            if matches!(
                &*state,
                State::Made { generation, .. }
                    if Arc::ptr_eq(generation, &self.generation)
            ) {
                *state = State::Empty;
            }
        }
    }
}

impl<F, S, Req> Service<Req> for Singled<F, S>
where
    S: Service<Req>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    /// Delegates readiness and invalidates this generation on failure.
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(cx) {
            Poll::Ready(Err(error)) => {
                self.discard_shared();
                Poll::Ready(Err(error))
            }
            other => other,
        }
    }

    /// Sends a request through the shared service clone.
    fn call(&mut self, req: Req) -> Self::Future {
        self.inner.call(req)
    }
}

impl<F, S> Batch<F, S> {
    /// Creates a generation around one maker future.
    fn new(future: F) -> Self {
        Self {
            future: Some(Box::pin(future)),
            generation: Arc::new(()),
            next_id: WaiterId(0),
            driver: None,
            waiters: Vec::new(),
        }
    }

    /// Allocates the next participant identifier.
    fn next_id(&mut self) -> WaiterId {
        let id = self.next_id;
        self.next_id.0 = self.next_id.0.wrapping_add(1);
        id
    }

    /// Registers the first participant as the maker driver.
    fn register_driver(&mut self) -> WaiterId {
        let id = self.next_id();
        self.driver = Some(Driver { id, waker: None });
        id
    }

    /// Registers a participant waiting for the shared result.
    fn register_waiter(&mut self) -> (WaiterId, oneshot::Receiver<Result<S, SharedError>>) {
        let id = self.next_id();
        let (sender, receiver) = oneshot::channel();
        self.waiters.push(Waiter {
            id,
            waker: None,
            sender,
        });
        (id, receiver)
    }

    /// Removes a participant and returns whether the batch became empty.
    ///
    /// When the driver leaves first, the newest waiter takes its role and keeps
    /// polling the same maker future.
    fn remove(&mut self, id: WaiterId) -> bool {
        if let Some(index) = self.waiters.iter().position(|waiter| waiter.id == id) {
            self.waiters.swap_remove(index);
            return false;
        }

        if self.driver.as_ref().is_some_and(|driver| driver.id == id) {
            if let Some(waiter) = self.waiters.pop() {
                self.driver = Some(Driver {
                    id: waiter.id,
                    waker: waiter.waker,
                });
                self.wake_driver();
                false
            } else {
                self.driver = None;
                self.future = None;
                true
            }
        } else {
            false
        }
    }

    /// Polls the maker for the current driver or parks a non-driver participant.
    fn poll<E>(&mut self, id: WaiterId, cx: &mut task::Context<'_>) -> Poll<Result<S, SharedError>>
    where
        F: Future<Output = Result<S, E>>,
        E: Into<BoxError>,
        S: Clone,
    {
        if !self.driver.as_ref().is_some_and(|driver| driver.id == id) {
            self.store_waker(id, cx.waker());
            return Poll::Pending;
        }

        let Some(future) = self.future.as_mut() else {
            return Poll::Ready(Err(shared_error(Canceled)));
        };
        match future.as_mut().poll(cx) {
            Poll::Pending => {
                self.store_driver_waker(cx.waker());
                Poll::Pending
            }
            Poll::Ready(Ok(service)) => {
                self.future = None;
                Poll::Ready(Ok(service))
            }
            Poll::Ready(Err(error)) => {
                self.future = None;
                let error: BoxError = error.into();
                Poll::Ready(Err(error.into()))
            }
        }
    }

    /// Sends one cloned result to every remaining waiter.
    fn send_result(&mut self, result: Result<S, SharedError>)
    where
        S: Clone,
    {
        for waiter in std::mem::take(&mut self.waiters) {
            let _ = waiter.sender.send(result.clone());
        }
    }

    /// Stores the latest waker for a waiting participant.
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

    /// Stores the latest waker for the current driver.
    fn store_driver_waker(&mut self, waker: &Waker) {
        if let Some(driver) = &mut self.driver {
            if driver
                .waker
                .as_ref()
                .is_none_or(|current| !current.will_wake(waker))
            {
                driver.waker = Some(waker.clone());
            }
        }
    }

    /// Wakes the participant that inherited driver ownership.
    fn wake_driver(&mut self) {
        if let Some(driver) = &mut self.driver {
            if let Some(waker) = driver.waker.take() {
                waker.wake();
            }
        }
    }
}

/// Error shared by every participant in a failed creation batch.
#[derive(Debug)]
pub(super) struct SingletonError(SharedError);

impl SingletonError {
    /// Wraps an error produced before or while creating the service.
    fn new(error: BoxError) -> Self {
        Self(error.into())
    }

    /// Creates the error returned when the participant's batch disappeared.
    fn canceled() -> Self {
        Self(shared_error(Canceled))
    }
}

impl fmt::Display for SingletonError {
    /// Writes a stable high-level singleton error message.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("singleton connection error")
    }
}

impl std::error::Error for SingletonError {
    /// Returns the original shared creation error.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// Cloneable error representation distributed to all batch participants.
type SharedError = Arc<dyn std::error::Error + Send + Sync>;

/// Converts an owned error into the batch's cloneable representation.
fn shared_error(error: impl std::error::Error + Send + Sync + 'static) -> SharedError {
    Arc::new(error)
}

/// Indicates that a singleton creation batch no longer exists.
#[derive(Debug)]
struct Canceled;

impl fmt::Display for Canceled {
    /// Writes the cancellation reason.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("singleton connection canceled")
    }
}

impl std::error::Error for Canceled {}

#[cfg(test)]
mod tests {
    use std::{future::Ready, sync::Arc};

    use tower::BoxError;

    use super::{Singled, State};
    use crate::sync::Mutex;

    #[test]
    fn stale_checkout_cannot_discard_replacement() {
        type MakeFuture = Ready<Result<(), BoxError>>;

        let stale_generation = Arc::new(());
        let replacement_generation = Arc::new(());
        let state = Arc::new(Mutex::new(State::<MakeFuture, ()>::Made {
            service: (),
            generation: replacement_generation.clone(),
        }));
        let stale = Singled::new((), Arc::downgrade(&state), stale_generation, true);

        stale.discard_shared();

        assert!(matches!(
            &*state.lock(),
            State::Made { generation, .. }
                if Arc::ptr_eq(generation, &replacement_generation)
        ));
    }
}
