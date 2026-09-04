//! Shares one cloneable service across concurrent checkouts.
//!
//! [`Singleton`] fits multiplexed protocols such as HTTP/2. The first checkout
//! starts a maker future and becomes its driver. Concurrent checkouts join the
//! same [`Batch`], then receive clones of the completed service:
//!
//! ```text
//! Empty -> Making(driver + waiters) -> Made(shared service)
//! ```
//!
//! If the driver is canceled, one waiter takes over the same pinned maker
//! future. This avoids abandoning a connection attempt while another request is
//! still waiting for it. Every batch also owns a generation marker. A failed
//! maker reports its root cause only to the driver; waiters receive a retryable
//! cancellation and can form a new batch. A failed checkout may clear only the
//! generation that produced it, so a stale sender cannot remove a newer
//! replacement.
//!
//! # Example
//!
//! The first call creates the service. A concurrent checkout joins that same
//! creation batch, and later checkouts clone the completed service:
//!
//! ```rust,ignore
//! let mut singleton = Singleton::new(maker);
//! let first = singleton.call(destination.clone());
//! let second = singleton.checkout().expect("creation is in progress");
//! let (first, second) = futures_util::try_join!(first, second)?;
//! ```

use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Weak},
    task::{self, Poll},
};

use tokio::sync::oneshot;
use tower::{BoxError, Service};

use crate::sync::Mutex;

/// A pool that creates at most one shared cloneable service at a time.
///
/// All clones share one [`State`]. The empty state accepts one maker call, the
/// making state gathers concurrent participants, and the made state returns a
/// clone without calling the maker. `poll_ready` reaches the maker only while
/// the singleton is empty.
///
/// This type coordinates creation, but it does not decide service health.
/// [`Singled`] clears its own generation after a readiness failure or explicit
/// discard request. A dropped driver transfers its pinned maker to a waiter;
/// only cancellation of the final participant destroys the maker.
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
    pub(super) fn retain<F>(&mut self, mut predicate: F) -> Option<M::Response>
    where
        F: FnMut(&mut M::Response) -> bool,
    {
        let mut state = self.state.lock();
        let discarded = if let State::Made { service, .. } = &mut *state {
            if !predicate(service) {
                match std::mem::replace(&mut *state, State::Empty) {
                    State::Made { service, .. } => Some(service),
                    _ => None,
                }
            } else {
                None
            }
        } else {
            None
        };
        drop(state);
        discarded
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
                let mut batch = Batch::new();
                let id = batch.register_driver();
                let generation = batch.generation.clone();
                *state = State::Making(batch);
                drop(state);

                let future = Box::pin(self.maker.call(dst));
                let future = {
                    let mut state = self.state.lock();
                    match &mut *state {
                        State::Making(batch) if Arc::ptr_eq(&generation, &batch.generation) => {
                            batch.restore_future(id, future).err()
                        }
                        State::Empty | State::Making(_) | State::Made { .. } => Some(future),
                    }
                };
                drop(future);

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
/// A `Participating` future belongs to one creation generation. It either owns
/// the driver role or waits over a oneshot channel. If its receiver closes after
/// driver handoff, it checks shared state and can continue as the new driver.
/// A `Made` future owns an immediately available clone.
///
/// Cancellation removes the participant from its batch. Canceling the driver
/// promotes a waiter; canceling the final participant drops the maker outside
/// the state lock.
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
        receiver: Option<oneshot::Receiver<S>>,
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
///
/// `Making` owns exactly one pinned maker future and at most one driver.
/// `Made` stores the cloneable service with the generation allowed to invalidate
/// it. Transitions that destroy a future, service, or result sender move that
/// value out first so destruction and task wakeups happen outside the lock.
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
///
/// The maker remains pinned in the batch across driver changes. Polling removes
/// it temporarily so arbitrary future code runs without the singleton state
/// lock, then restores it if still pending and the same participant remains the
/// driver.
///
/// Participant identifiers and the generation separate cancellation from newer
/// batches that may already occupy the singleton.
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
///
/// The counter wraps explicitly and is scoped to a single [`Batch`]. It is used
/// to transfer the driver role and remove canceled waiters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WaiterId(usize);

/// Participant currently responsible for polling the shared maker future.
///
/// The driver stores no task handle. Ownership is represented by its
/// [`WaiterId`], which lets any matching checkout take the pinned future from
/// the batch for one poll.
struct Driver {
    /// Driver participant identifier.
    id: WaiterId,
}

/// Non-driver participant waiting for the shared result.
///
/// Dropping its sender wakes the receiver during driver promotion. Normal
/// completion sends a clone of the shared service. A maker failure closes the
/// channel so the participant can retry in a new generation.
struct Waiter<S> {
    /// Waiter participant identifier.
    id: WaiterId,
    /// Delivers the shared service or shared maker error.
    sender: oneshot::Sender<S>,
}

/// Values removed when one singleton participant is canceled.
///
/// The caller updates [`State`] while locked, then drops the returned waiter and
/// maker future afterward. `batch_empty` tells it whether the singleton can move
/// back to `Empty`.
struct ParticipantRemoval<F, S> {
    /// Whether no participant remains in the creation batch.
    batch_empty: bool,
    /// Removed waiter, dropped outside the state lock to wake its receiver.
    waiter: Option<Waiter<S>>,
    /// Maker canceled with the final participant, also dropped outside the lock.
    future: Option<Pin<Box<F>>>,
}

/// A checked-out clone of the singleton service.
///
/// The wrapper delegates requests to its inner clone and remembers the creation
/// generation. A readiness failure or explicit discard clears the shared
/// service only when the singleton still contains that generation. Its weak
/// state reference allows an evicted pool entry to be destroyed independently
/// of outstanding checkouts.
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
                        Poll::Ready(Ok(service)) => {
                            return Poll::Ready(Ok(Singled::new(
                                service,
                                Arc::downgrade(state),
                                generation.clone(),
                                *reused,
                            )));
                        }
                        Poll::Ready(Err(_)) => *receiver = None,
                        Poll::Pending => {}
                    }
                }

                let weak = Arc::downgrade(state);
                let mut future = {
                    let mut locked = state.lock();
                    match &mut *locked {
                        State::Making(batch) if Arc::ptr_eq(generation, &batch.generation) => {
                            let Some(future) = batch.take_future(*id) else {
                                return Poll::Pending;
                            };
                            future
                        }
                        State::Made {
                            service,
                            generation: current,
                        } if Arc::ptr_eq(generation, current) => {
                            return Poll::Ready(Ok(Singled::new(
                                service.clone(),
                                weak,
                                current.clone(),
                                true,
                            )));
                        }
                        State::Making(_) | State::Made { .. } | State::Empty => {
                            return Poll::Ready(Err(SingletonError::canceled()));
                        }
                    }
                };

                match future.as_mut().poll(cx) {
                    Poll::Pending => {
                        let restored = {
                            let mut locked = state.lock();
                            match &mut *locked {
                                State::Making(batch)
                                    if Arc::ptr_eq(generation, &batch.generation) =>
                                {
                                    batch.restore_future(*id, future)
                                }
                                State::Making(_) | State::Made { .. } | State::Empty => Err(future),
                            }
                        };
                        match restored {
                            Ok(()) => Poll::Pending,
                            Err(future) => {
                                drop(future);
                                Poll::Ready(Err(SingletonError::canceled()))
                            }
                        }
                    }
                    Poll::Ready(Ok(service)) => {
                        drop(future);
                        let waiters = {
                            let mut locked = state.lock();
                            match &mut *locked {
                                State::Making(batch)
                                    if Arc::ptr_eq(generation, &batch.generation) =>
                                {
                                    let waiters = batch.take_waiters();
                                    *locked = State::Made {
                                        service: service.clone(),
                                        generation: generation.clone(),
                                    };
                                    waiters
                                }
                                State::Making(_) | State::Made { .. } | State::Empty => {
                                    return Poll::Ready(Err(SingletonError::canceled()));
                                }
                            }
                        };
                        send_service(waiters, &service);
                        Poll::Ready(Ok(Singled::new(service, weak, generation.clone(), *reused)))
                    }
                    Poll::Ready(Err(error)) => {
                        drop(future);
                        let error: BoxError = error.into();
                        let waiters = {
                            let mut locked = state.lock();
                            match &mut *locked {
                                State::Making(batch)
                                    if Arc::ptr_eq(generation, &batch.generation) =>
                                {
                                    let waiters = batch.take_waiters();
                                    *locked = State::Empty;
                                    waiters
                                }
                                State::Making(_) | State::Made { .. } | State::Empty => {
                                    return Poll::Ready(Err(SingletonError::canceled()));
                                }
                            }
                        };
                        drop(waiters);
                        Poll::Ready(Err(SingletonError::new(error)))
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
            let (waiter, future) = {
                let mut locked = state.lock();
                if let State::Making(batch) = &mut *locked {
                    if Arc::ptr_eq(generation, &batch.generation) {
                        let removed = batch.remove(*id);
                        if removed.batch_empty {
                            *locked = State::Empty;
                        }
                        (removed.waiter, removed.future)
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            };

            // Closing a waiter's receiver and canceling the maker can
            // wake arbitrary tasks, so both values are dropped outside the lock.
            drop(waiter);
            drop(future);
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
        let discarded = self.state.upgrade().and_then(|state| {
            let mut locked = state.lock();
            if matches!(
                &*locked,
                State::Made { generation, .. }
                    if Arc::ptr_eq(generation, &self.generation)
            ) {
                match std::mem::replace(&mut *locked, State::Empty) {
                    State::Made { service, .. } => Some(service),
                    _ => None,
                }
            } else {
                None
            }
        });
        drop(discarded);
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
    /// Creates a generation before its maker is called outside the state lock.
    fn new() -> Self {
        Self {
            future: None,
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
        self.driver = Some(Driver { id });
        id
    }

    /// Registers a participant waiting for the shared result.
    fn register_waiter(&mut self) -> (WaiterId, oneshot::Receiver<S>) {
        let id = self.next_id();
        let (sender, receiver) = oneshot::channel();
        self.waiters.push(Waiter { id, sender });
        (id, receiver)
    }

    /// Removes a participant and returns whether the batch became empty.
    ///
    /// When the driver leaves first, the newest waiter takes its role and keeps
    /// polling the same maker future.
    fn remove(&mut self, id: WaiterId) -> ParticipantRemoval<F, S> {
        if let Some(index) = self.waiters.iter().position(|waiter| waiter.id == id) {
            return ParticipantRemoval {
                batch_empty: false,
                waiter: Some(self.waiters.swap_remove(index)),
                future: None,
            };
        }

        if self.driver.as_ref().is_some_and(|driver| driver.id == id) {
            if let Some(waiter) = self.waiters.pop() {
                self.driver = Some(Driver { id: waiter.id });
                ParticipantRemoval {
                    batch_empty: false,
                    waiter: Some(waiter),
                    future: None,
                }
            } else {
                self.driver = None;
                ParticipantRemoval {
                    batch_empty: true,
                    waiter: None,
                    future: self.future.take(),
                }
            }
        } else {
            ParticipantRemoval {
                batch_empty: false,
                waiter: None,
                future: None,
            }
        }
    }

    /// Takes the maker only for the participant currently acting as driver.
    fn take_future(&mut self, id: WaiterId) -> Option<Pin<Box<F>>> {
        self.driver
            .as_ref()
            .is_some_and(|driver| driver.id == id)
            .then(|| self.future.take())
            .flatten()
    }

    /// Restores a pending maker when the same participant remains the driver.
    fn restore_future(&mut self, id: WaiterId, future: Pin<Box<F>>) -> Result<(), Pin<Box<F>>> {
        if self.driver.as_ref().is_some_and(|driver| driver.id == id) && self.future.is_none() {
            self.future = Some(future);
            Ok(())
        } else {
            Err(future)
        }
    }

    /// Takes every non-driver participant before broadcasting outside the lock.
    fn take_waiters(&mut self) -> Vec<Waiter<S>> {
        std::mem::take(&mut self.waiters)
    }
}

/// Sends one service clone per waiter after the singleton state lock is released.
fn send_service<S>(waiters: Vec<Waiter<S>>, service: &S)
where
    S: Clone,
{
    for waiter in waiters {
        let _ = waiter.sender.send(service.clone());
    }
}

/// Error returned when a singleton service cannot be created or joined.
///
/// The driver receives the maker's original error. Other participants observe a
/// closed result channel and retry in a new generation.
#[derive(Debug)]
pub(super) struct SingletonError(BoxError);

impl SingletonError {
    /// Wraps an error produced before or while creating the service.
    fn new(error: BoxError) -> Self {
        Self(error)
    }

    /// Creates the error returned when the participant's batch disappeared.
    fn canceled() -> Self {
        Self(Box::new(Canceled))
    }

    /// Returns whether this error asks the caller to start a new batch.
    pub(super) fn is_canceled(error: &(dyn std::error::Error + 'static)) -> bool {
        let mut current = Some(error);
        while let Some(error) = current {
            if error.is::<Canceled>() {
                return true;
            }
            current = error.source();
        }
        false
    }
}

impl fmt::Display for SingletonError {
    /// Writes a stable high-level singleton error message.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("singleton connection error")
    }
}

impl std::error::Error for SingletonError {
    /// Returns the original creation or cancellation error.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// Indicates that a checkout's singleton creation batch no longer exists.
///
/// This can occur when all ownership of a batch is canceled or when the future
/// observes a different generation after being woken.
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

    use tower::{BoxError, Service, util::Oneshot};

    use super::{Singled, Singleton, State};
    use crate::sync::Mutex;

    /// Maker completed explicitly by a test-held sender.
    #[derive(Clone)]
    struct ControlledMaker {
        sender: Arc<Mutex<Option<tokio::sync::oneshot::Sender<&'static str>>>>,
    }

    impl Service<()> for ControlledMaker {
        type Response = &'static str;
        type Error = BoxError;
        type Future = futures_util::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _target: ()) -> Self::Future {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            *self.sender.lock() = Some(sender);
            Box::pin(async move { receiver.await.map_err(Into::into) })
        }
    }

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

    #[test]
    fn cancellation_and_failure_keep_waiters_progressing() {
        let sender = Arc::new(Mutex::new(None));
        let singleton = Singleton::new(ControlledMaker {
            sender: sender.clone(),
        });
        let mut driver = tokio_test::task::spawn(Oneshot::new(singleton.clone(), ()));
        assert!(driver.poll().is_pending());
        let sender = sender.lock().take().expect("maker started");

        let mut waiter = tokio_test::task::spawn(Oneshot::new(singleton, ()));
        assert!(waiter.poll().is_pending());
        drop(driver);
        sender.send("shared").expect("waiter still owns maker");

        let std::task::Poll::Ready(Ok(service)) = waiter.poll() else {
            panic!("promoted waiter should finish the original maker");
        };
        assert_eq!(*service.inner(), "shared");

        let sender = Arc::new(Mutex::new(None));
        let singleton = Singleton::new(ControlledMaker {
            sender: sender.clone(),
        });
        let mut driver = tokio_test::task::spawn(Oneshot::new(singleton.clone(), ()));
        assert!(driver.poll().is_pending());
        let sender = sender.lock().take().expect("maker started");
        let mut waiter = tokio_test::task::spawn(Oneshot::new(singleton, ()));
        assert!(waiter.poll().is_pending());

        drop(sender);

        let std::task::Poll::Ready(Err(driver_error)) = driver.poll() else {
            panic!("driver should receive the maker error");
        };
        assert!(!super::SingletonError::is_canceled(&driver_error));
        let std::task::Poll::Ready(Err(waiter_error)) = waiter.poll() else {
            panic!("waiter should be released for a new batch");
        };
        assert!(super::SingletonError::is_canceled(&waiter_error));
    }
}
