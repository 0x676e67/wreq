//! Shares a single cloneable service across concurrent checkouts.
//!
//! [`Singleton`] fits multiplexed protocols such as HTTP/2 and HTTP/3. The first checkout
//! starts a maker future and drives it; concurrent checkouts join the same [`Batch`] and
//! receive clones once it completes.
//!
//! If the driver is canceled, a waiting checkout takes over the pinned maker future instead
//! of abandoning the attempt. If the maker panics, the batch is canceled so waiters retry
//! rather than hanging. Each batch carries a generation marker: a maker error is shared
//! with every participant, and a failed checkout can invalidate only its own generation so
//! a stale sender never clears a newer replacement.

use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
    task::{self, Poll},
};

use tokio::sync::oneshot;
use tower::{BoxError, Service};

use crate::sync::Mutex;

/// Pool that maintains at most one shared cloneable service at a time.
///
/// All clones share a single [`State`]: `Empty` polls and calls `maker`, `Making` gathers
/// concurrent participants into a batch, and `Made` hands out clones directly. Dropping
/// the driver hands its pinned maker to a waiter; only canceling the last participant drops
/// the maker.
///
/// Health checks stay outside this type. Checkouts carry the generation for callers
/// that need to discard a failed service.
#[derive(Debug)]
pub(super) struct Singleton<M, Dst, G>
where
    M: Service<Dst>,
{
    /// Underlying maker called when the singleton is empty.
    maker: M,
    /// Shared per-group lock containing the singleton [`State`].
    state: Arc<Mutex<G>>,
    /// Destination type marker.
    _dst: PhantomData<fn(Dst)>,
}

/// Ready-checkout result, distinguishing an empty singleton from one with existing work.
pub(super) enum Ready<S> {
    /// No service or in-flight creation exists, so a negotiated entry may fall back.
    Empty,
    /// A creation batch is running or the completed service failed its reuse check.
    Unavailable,
    /// A reusable service clone was checked out immediately.
    Made(S),
}

// ===== impl Ready =====

impl<S> Ready<S> {
    /// Takes the sender when checkout succeeded.
    #[must_use]
    pub(super) fn into_made(self) -> Option<S> {
        match self {
            Self::Made(service) => Some(service),
            Self::Empty | Self::Unavailable => None,
        }
    }
}

// ===== impl Singleton =====

impl<M, Dst, G> Singleton<M, Dst, G>
where
    M: Service<Dst>,
    G: AsMut<State<M::Future, M::Response>>,
    M::Response: Clone,
{
    /// Uses this group's shared state for the singleton.
    #[must_use]
    pub(super) fn new(maker: M, state: Arc<Mutex<G>>) -> Self {
        Self {
            maker,
            state,
            _dst: PhantomData,
        }
    }

    /// Shares the group lock with the transport negotiation queue.
    #[cfg(feature = "http2")]
    #[must_use]
    pub(super) fn shared(&self) -> &Arc<Mutex<G>> {
        &self.state
    }

    /// Runs a state operation under the group lock.
    #[must_use]
    pub(super) fn with_state<T>(
        &self,
        f: impl FnOnce(&mut State<M::Future, M::Response>) -> T,
    ) -> T {
        f(self.state.lock().as_mut())
    }

    /// Checks and clones a completed service without joining or starting creation.
    ///
    /// Pass the state from a held group lock, or `None` to acquire the lock here.
    #[must_use]
    pub(super) fn checkout_ready(
        &self,
        locked: Option<&State<M::Future, M::Response>>,
        reusable: impl FnOnce(&M::Response) -> bool,
    ) -> Ready<Singled<M::Response>> {
        let mut guard;
        let state = match locked {
            Some(state) => state,
            None => {
                guard = self.state.lock();
                guard.as_mut()
            }
        };
        match state {
            State::Made {
                service,
                generation,
            } if reusable(service) => Ready::Made(Singled::new(service.clone(), *generation, true)),
            State::Empty => Ready::Empty,
            State::Making(_) | State::Made { .. } => Ready::Unavailable,
        }
    }

    /// Joins an existing service or in-progress creation.
    ///
    /// Returns `None` instead of starting the maker when the singleton is empty.
    /// Pass the state from a held group lock, or `None` to acquire the lock here.
    #[must_use]
    pub(super) fn checkout(
        &self,
        locked: Option<&mut State<M::Future, M::Response>>,
    ) -> Option<SingletonFuture<M::Future, M::Response, G>> {
        let mut guard;
        let state = match locked {
            Some(state) => state,
            None => {
                guard = self.state.lock();
                guard.as_mut()
            }
        };
        match state {
            State::Empty => None,
            State::Making(batch) => {
                let (id, receiver) = batch.register_waiter();
                Some(SingletonFuture::Participating {
                    id,
                    generation: batch.generation,
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
                generation: *generation,
                future: PhantomData,
            }),
        }
    }
}

impl<M, Dst, G> Service<Dst> for Singleton<M, Dst, G>
where
    M: Service<Dst>,
    G: AsMut<State<M::Future, M::Response>>,
    M::Response: Clone,
    M::Error: Into<BoxError>,
{
    type Response = Singled<M::Response>;
    type Error = SingletonError;
    type Future = SingletonFuture<M::Future, M::Response, G>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        if matches!(self.state.lock().as_mut(), State::Empty) {
            self.maker
                .poll_ready(cx)
                .map_err(|error| SingletonError::new(error.into()))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, dst: Dst) -> Self::Future {
        let mut guard = self.state.lock();
        let state = guard.as_mut();
        match &mut *state {
            State::Empty => {
                let mut batch = Batch::new();
                let id = batch.register_driver();
                let generation = batch.generation;
                *state = State::Making(batch);
                drop(guard);

                // Created before the maker call so a panic there still leaves the batch.
                let driver = SingletonFuture::Participating {
                    id,
                    generation,
                    state: self.state.clone(),
                    receiver: None,
                    reused: false,
                };
                let future = Box::pin(self.maker.call(dst));
                let mut guard = self.state.lock();
                let state = guard.as_mut();
                let unused = match &mut *state {
                    State::Making(batch) if generation == batch.generation => {
                        batch.restore_future(id, future)
                    }
                    State::Empty | State::Making(_) | State::Made { .. } => Err(future),
                };
                drop(guard);
                drop(unused);
                driver
            }
            State::Making(batch) => {
                let (id, receiver) = batch.register_waiter();
                SingletonFuture::Participating {
                    id,
                    generation: batch.generation,
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
                generation: *generation,
                future: PhantomData,
            },
        }
    }
}

impl<M, Dst, G> Clone for Singleton<M, Dst, G>
where
    M: Service<Dst> + Clone,
    G: AsMut<State<M::Future, M::Response>>,
{
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
/// `Participating` joins an in-flight batch as either the driver or a oneshot waiter;
/// if its receiver closes during driver handoff, it re-checks shared state and can take
/// over driving. `Made` yields a clone that was already available.
///
/// Dropping a participant removes it from its batch, promoting a waiter if it was the
/// driver or dropping the maker outside the lock if it was the last participant.
pub(super) enum SingletonFuture<F, S, G: AsMut<State<F, S>>> {
    /// Participates in an in-flight creation batch.
    Participating {
        /// Participant ID used for cancellation and driver handoff.
        id: ParticipantId,
        /// Generation token identifying this creation batch.
        generation: u64,
        /// Shared singleton state.
        state: Arc<Mutex<G>>,
        /// Oneshot receiver for waiters; `None` once acting as driver.
        receiver: Option<oneshot::Receiver<Result<S, SingletonError>>>,
        /// Whether this checkout joined an existing batch rather than starting it.
        reused: bool,
    },
    /// Owns a clone of an already-created service.
    Made {
        /// Cloned service returned on the first poll.
        service: Option<S>,
        /// Generation token paired with `service`.
        generation: u64,
        /// Retains the maker future type parameter `F`.
        future: PhantomData<fn() -> F>,
    },
}

// ===== impl SingletonFuture =====

// The maker future is pinned separately inside `Batch`, so moving this outer
// state machine never moves the maker itself.
impl<F, S, G: AsMut<State<F, S>>> Unpin for SingletonFuture<F, S, G> {}

/// Lifecycle of the shared singleton service.
///
/// `Making` tracks an in-flight generation with at most one driver polling it; `Made`
/// stores the cloneable service with the generation allowed to invalidate it. Values
/// being destroyed or woken are moved out first so drops and wakeups run unlocked.
#[derive(Default)]
pub(super) enum State<F, S> {
    /// No service exists and no maker is running.
    #[default]
    Empty,
    /// A batch is actively creating the shared service.
    Making(Batch<F, S>),
    /// A completed service is available for cloning.
    Made {
        /// Shared cloneable service.
        service: S,
        /// Generation token guarding against invalidation by stale clones.
        generation: u64,
    },
}

// ===== impl State =====

impl<F, S> State<F, S> {
    /// Borrows the current service when creation is complete.
    #[must_use]
    pub(super) fn service(&self) -> Option<&S> {
        match self {
            Self::Made { service, .. } => Some(service),
            Self::Empty | Self::Making(_) => None,
        }
    }

    /// Detaches a completed service rejected by the predicate.
    #[must_use]
    pub(super) fn retain(&mut self, mut predicate: impl FnMut(&mut S) -> bool) -> Option<S> {
        if let Self::Made { service, .. } = self
            && !predicate(service)
        {
            return self.take();
        }
        None
    }

    /// Detaches the completed service without interrupting creation.
    #[must_use]
    pub(super) fn take(&mut self) -> Option<S> {
        match std::mem::replace(self, Self::Empty) {
            Self::Made { service, .. } => Some(service),
            previous => {
                *self = previous;
                None
            }
        }
    }
}

impl<F, S: fmt::Debug> fmt::Debug for State<F, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Making(_) => f.write_str("Making"),
            Self::Made { service, .. } => f.debug_tuple("Made").field(service).finish(),
        }
    }
}

/// Coordinates an in-flight maker future and all checkouts waiting on it.
///
/// The maker stays pinned across driver handoffs; each poll temporarily takes it out so
/// arbitrary future code runs without holding the state lock, then restores it if still
/// pending and the same participant remains driver.
pub(super) struct Batch<F, S> {
    /// Pinned maker future, temporarily taken out while the driver polls it.
    future: Option<Pin<Box<F>>>,
    /// Generation token shared by all participants and resulting clones.
    generation: u64,
    /// Wrapping counter allocating participant IDs within this batch.
    next_id: ParticipantId,
    /// Participant currently driving `future`.
    driver: Option<Driver>,
    /// Non-driver participants awaiting the broadcast result.
    waiters: Vec<Waiter<S>>,
}

/// Wrapping participant identifier scoped to a single [`Batch`].
///
/// Used to transfer the driver role and remove canceled waiters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ParticipantId(usize);

/// Identifies the participant currently responsible for polling the maker future.
///
/// Ownership is tracked by [`ParticipantId`] alone so the matching checkout can take the
/// pinned maker from [`Batch`] for each poll.
struct Driver {
    /// Participant ID of the active driver.
    id: ParticipantId,
}

/// Non-driver participant waiting on the shared batch result.
///
/// Sending delivers a cloned service or shared error; dropping `sender` closes the channel
/// to wake the waiter during driver promotion.
struct Waiter<S> {
    /// Participant ID of this waiter.
    id: ParticipantId,
    /// Result channel; dropping it without sending signals driver promotion.
    sender: oneshot::Sender<Result<S, SingletonError>>,
}

/// Detached state returned when canceling a participant so drops run outside the lock.
///
/// `batch_empty` tells the caller whether to reset [`State`] to `Empty`; `waiter` and
/// `future` are dropped after unlocking so wakeups and maker cancellation run unlocked.
struct ParticipantRemoval<F, S> {
    /// Whether removing this participant left the batch empty.
    batch_empty: bool,
    /// Detached waiter, dropped unlocked to wake its receiver on promotion.
    waiter: Option<Waiter<S>>,
    /// Detached maker future, dropped unlocked when the last participant cancels.
    future: Option<Pin<Box<F>>>,
}

/// Checked-out clone of a singleton service.
///
/// The generation identifies the service without keeping any shared state alive.
#[derive(Debug)]
pub(super) struct Singled<S> {
    /// Cloned service owned by this checkout.
    inner: S,
    /// Whether this checkout reused an existing service or in-flight batch.
    reused: bool,
    /// Generation token checked before invalidating shared state.
    generation: u64,
}

impl<F, S, E, G> Future for SingletonFuture<F, S, G>
where
    G: AsMut<State<F, S>>,
    F: Future<Output = Result<S, E>>,
    E: Into<BoxError>,
    S: Clone,
{
    type Output = Result<Singled<S>, SingletonError>;

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
                            return Poll::Ready(Ok(Singled::new(service, *generation, *reused)));
                        }
                        Poll::Ready(Ok(Err(error))) => return Poll::Ready(Err(error)),
                        // Channel closed without a result means this waiter was promoted to driver.
                        Poll::Ready(Err(_)) => *receiver = None,
                        // The batch may already be empty while its result is sent unlocked.
                        // Only a closed channel hands this waiter the driver role.
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let mut future = {
                    let mut guard = state.lock();
                    let locked = guard.as_mut();
                    match &mut *locked {
                        State::Making(batch) if *generation == batch.generation => {
                            match batch.take_future(*id) {
                                Some(future) => future,
                                // Only the driver gets here. Its maker is missing only when
                                // an earlier driver panicked inside it, so restart the batch.
                                None => {
                                    let waiters = batch.take_waiters();
                                    *locked = State::Empty;
                                    drop(guard);
                                    let error = SingletonError::canceled();
                                    send_result(waiters, Err(&error));
                                    return Poll::Ready(Err(error));
                                }
                            }
                        }
                        State::Made {
                            service,
                            generation: current,
                        } if *generation == *current => {
                            return Poll::Ready(Ok(Singled::new(service.clone(), *current, true)));
                        }
                        State::Making(_) | State::Made { .. } | State::Empty => {
                            return Poll::Ready(Err(SingletonError::canceled()));
                        }
                    }
                };

                match future.as_mut().poll(cx) {
                    Poll::Pending => {
                        let restored = {
                            let mut guard = state.lock();
                            let locked = guard.as_mut();
                            match &mut *locked {
                                State::Making(batch) if *generation == batch.generation => {
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
                        let shared_service = service.clone();
                        let waiters = {
                            let mut guard = state.lock();
                            let locked = guard.as_mut();
                            match &mut *locked {
                                State::Making(batch) if *generation == batch.generation => {
                                    let waiters = batch.take_waiters();
                                    *locked = State::Made {
                                        service: shared_service,
                                        generation: *generation,
                                    };
                                    waiters
                                }
                                State::Making(_) | State::Made { .. } | State::Empty => {
                                    return Poll::Ready(Err(SingletonError::canceled()));
                                }
                            }
                        };
                        send_result(waiters, Ok(&service));
                        Poll::Ready(Ok(Singled::new(service, *generation, *reused)))
                    }
                    Poll::Ready(Err(error)) => {
                        drop(future);
                        let error = SingletonError::new(error.into());
                        let mut guard = state.lock();
                        let locked = guard.as_mut();
                        let waiters = match &mut *locked {
                            State::Making(batch) if *generation == batch.generation => {
                                let waiters = batch.take_waiters();
                                *locked = State::Empty;
                                waiters
                            }
                            State::Making(_) | State::Made { .. } | State::Empty => {
                                return Poll::Ready(Err(SingletonError::canceled()));
                            }
                        };
                        drop(guard);
                        send_result(waiters, Err(&error));
                        Poll::Ready(Err(error))
                    }
                }
            }
            Self::Made {
                service,
                generation,
                ..
            } => match service.take() {
                Some(service) => Poll::Ready(Ok(Singled::new(service, *generation, true))),
                None => Poll::Pending,
            },
        }
    }
}

impl<F, S, G: AsMut<State<F, S>>> Drop for SingletonFuture<F, S, G> {
    fn drop(&mut self) {
        let Self::Participating {
            id,
            generation,
            state,
            ..
        } = self
        else {
            return;
        };

        let mut guard = state.lock();
        let locked = guard.as_mut();
        let State::Making(batch) = &mut *locked else {
            return;
        };
        if *generation != batch.generation {
            return;
        }
        let removed = batch.remove(*id);
        if removed.batch_empty {
            *locked = State::Empty;
        }

        drop(guard);
        drop(removed.waiter);
        drop(removed.future);
    }
}

// ===== impl Singled =====

impl<S> Singled<S> {
    /// Wraps a service clone with its generation and reuse status.
    #[must_use]
    fn new(inner: S, generation: u64, reused: bool) -> Self {
        Self {
            inner,
            reused,
            generation,
        }
    }

    /// Borrows the checked-out service clone.
    #[must_use]
    pub(super) fn inner(&self) -> &S {
        &self.inner
    }

    /// Borrows the checked-out service for dispatch.
    #[must_use]
    pub(super) fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Returns whether this checkout joined an existing singleton operation.
    #[must_use]
    pub(super) fn is_reused(&self) -> bool {
        self.reused
    }

    /// Identifies the service generation carried by this checkout.
    #[must_use]
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
}

// ===== impl Batch =====

impl<F, S> Batch<F, S> {
    /// Creates a generation before its maker is called outside the state lock.
    #[must_use]
    fn new() -> Self {
        static NEXT_GENERATION: AtomicU64 = AtomicU64::new(0);
        Self {
            future: None,
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
            next_id: ParticipantId(0),
            driver: None,
            waiters: Vec::new(),
        }
    }

    /// Allocates the next participant identifier.
    #[must_use]
    fn next_id(&mut self) -> ParticipantId {
        let id = self.next_id;
        self.next_id.0 = self.next_id.0.wrapping_add(1);
        id
    }

    /// Registers the first participant as the maker driver.
    #[must_use]
    fn register_driver(&mut self) -> ParticipantId {
        let id = self.next_id();
        self.driver = Some(Driver { id });
        id
    }

    /// Registers a participant waiting for the shared result.
    #[must_use]
    fn register_waiter(&mut self) -> (ParticipantId, oneshot::Receiver<Result<S, SingletonError>>) {
        let id = self.next_id();
        let (sender, receiver) = oneshot::channel();
        self.waiters.push(Waiter { id, sender });
        (id, receiver)
    }

    /// Removes a participant and reports whether the batch became empty.
    ///
    /// If the driver leaves, a remaining waiter takes over the same maker.
    #[must_use]
    fn remove(&mut self, id: ParticipantId) -> ParticipantRemoval<F, S> {
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
    #[must_use]
    fn take_future(&mut self, id: ParticipantId) -> Option<Pin<Box<F>>> {
        self.future
            .take_if(|_| self.driver.as_ref().is_some_and(|driver| driver.id == id))
    }

    /// Restores a pending maker when the same participant remains the driver.
    fn restore_future(
        &mut self,
        id: ParticipantId,
        future: Pin<Box<F>>,
    ) -> Result<(), Pin<Box<F>>> {
        if self.driver.as_ref().is_some_and(|driver| driver.id == id) && self.future.is_none() {
            self.future = Some(future);
            Ok(())
        } else {
            Err(future)
        }
    }

    /// Takes every non-driver participant before broadcasting outside the lock.
    #[must_use]
    fn take_waiters(&mut self) -> Vec<Waiter<S>> {
        std::mem::take(&mut self.waiters)
    }
}

/// Broadcasts the shared result to all waiters after the state lock is released.
fn send_result<S>(waiters: Vec<Waiter<S>>, result: Result<&S, &SingletonError>)
where
    S: Clone,
{
    for waiter in waiters {
        let _ = waiter.sender.send(result.cloned().map_err(Clone::clone));
    }
}

/// Clears `State::Made` if its generation matches `generation`, dropping it outside the lock.
pub(super) fn discard_generation<F, S, G: AsMut<State<F, S>>>(
    state: &Weak<Mutex<G>>,
    generation: u64,
) {
    let Some(state) = state.upgrade() else {
        return;
    };
    let mut guard = state.lock();
    let locked = guard.as_mut();
    if !matches!(
        &*locked,
        State::Made {
            generation: current,
            ..
        } if *current == generation
    ) {
        return;
    }
    let discarded = std::mem::replace(&mut *locked, State::Empty);
    drop(guard);
    drop(state);
    drop(discarded);
}

/// Error returned when a singleton service cannot be created or joined.
///
/// Every participant of a failed batch shares the maker's error. Only a batch
/// that disappeared without a result reports a retryable cancellation.
#[derive(Clone, Debug)]
pub(super) struct SingletonError(Arc<dyn std::error::Error + Send + Sync>);

// ===== impl SingletonError =====

impl SingletonError {
    /// Wraps an error produced before or while creating the service.
    #[must_use]
    fn new(error: BoxError) -> Self {
        Self(Arc::from(error))
    }

    /// Creates the error returned when the participant's batch disappeared.
    #[must_use]
    fn canceled() -> Self {
        Self(Arc::new(Canceled))
    }

    /// Returns whether this error asks the caller to start a new batch.
    #[must_use]
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("singleton connection error")
    }
}

impl std::error::Error for SingletonError {
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

// ===== impl Canceled =====

impl fmt::Display for Canceled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("singleton connection canceled")
    }
}

impl std::error::Error for Canceled {}

#[cfg(test)]
mod tests {
    use std::{
        error::Error as _,
        future::Ready,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use tower::{BoxError, Service, util::Oneshot};

    use super::{Singleton, State, discard_generation};
    use crate::sync::Mutex;

    impl<F, S> AsMut<Self> for State<F, S> {
        fn as_mut(&mut self) -> &mut Self {
            self
        }
    }

    impl<M, Dst> Singleton<M, Dst, State<M::Future, M::Response>>
    where
        M: Service<Dst>,
        M::Response: Clone,
    {
        #[must_use]
        fn new_default(maker: M) -> Self {
            Self::new(maker, Arc::new(Mutex::new(State::Empty)))
        }
    }

    /// Maker completed or failed explicitly via a test-held oneshot sender.
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

    /// Cloneable service whose `poll_ready` fails when toggled by the test.
    #[derive(Clone)]
    struct ReadinessService {
        fail: Arc<AtomicBool>,
    }

    impl Service<()> for ReadinessService {
        type Response = ();
        type Error = std::io::Error;
        type Future = Ready<Result<(), Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.fail.load(Ordering::SeqCst) {
                Poll::Ready(Err(std::io::Error::other("readiness failed")))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn call(&mut self, _request: ()) -> Self::Future {
            std::future::ready(Ok(()))
        }
    }

    /// Creates a [`ReadinessService`] immediately while counting maker invocations.
    #[derive(Clone)]
    struct CountingMaker {
        calls: Arc<AtomicUsize>,
        fail: Arc<AtomicBool>,
    }

    impl Service<()> for CountingMaker {
        type Response = ReadinessService;
        type Error = BoxError;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _target: ()) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(ReadinessService {
                fail: self.fail.clone(),
            }))
        }
    }

    /// Maker that panics in `call` or while its future is polled.
    #[derive(Clone)]
    struct PanickingMaker {
        in_call: bool,
    }

    impl Service<()> for PanickingMaker {
        type Response = &'static str;
        type Error = BoxError;
        type Future = futures_util::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _target: ()) -> Self::Future {
            assert!(!self.in_call, "maker call panicked");
            Box::pin(async { panic!("maker future panicked") })
        }
    }

    #[test]
    fn maker_panic_cancels_batch() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let mut singleton = Singleton::new_default(PanickingMaker { in_call: true });
        assert!(catch_unwind(AssertUnwindSafe(|| singleton.call(()))).is_err());
        assert!(singleton.with_state(|state| matches!(state, State::Empty)));

        let singleton = Singleton::new_default(PanickingMaker { in_call: false });
        let mut driver = tokio_test::task::spawn(Oneshot::new(singleton.clone(), ()));
        let mut waiter = tokio_test::task::spawn(Oneshot::new(singleton.clone(), ()));
        assert!(catch_unwind(AssertUnwindSafe(|| driver.poll())).is_err());
        assert!(waiter.poll().is_pending());
        drop(driver);
        assert!(waiter.is_woken());
        let Poll::Ready(Err(error)) = waiter.poll() else {
            panic!("waiter should not wait for a maker lost to a panic");
        };
        assert!(super::SingletonError::is_canceled(&error));
        assert!(singleton.with_state(|state| matches!(state, State::Empty)));
    }

    #[test]
    fn stale_checkout_cannot_discard_replacement() {
        type MakeFuture = Ready<Result<(), BoxError>>;

        let stale_generation = 0;
        let replacement_generation = 1;
        let state = Arc::new(Mutex::new(State::<MakeFuture, ()>::Made {
            service: (),
            generation: replacement_generation,
        }));
        let weak = Arc::downgrade(&state);
        discard_generation(&weak, stale_generation);

        assert!(matches!(
            &*state.lock(),
            State::Made { generation, .. }
                if *generation == replacement_generation
        ));
    }

    #[tokio::test]
    async fn made_service_is_reused_until_discarded() {
        let calls = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(false));
        let singleton = Singleton::new_default(CountingMaker {
            calls: calls.clone(),
            fail: fail.clone(),
        });

        let first = Oneshot::new(singleton.clone(), ()).await.unwrap();
        assert!(!first.is_reused());
        let mut reused = Oneshot::new(singleton.clone(), ()).await.unwrap();
        assert!(reused.is_reused());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        fail.store(true, Ordering::SeqCst);
        assert!(
            std::future::poll_fn(|cx| reused.inner_mut().poll_ready(cx))
                .await
                .is_err()
        );
        discard_generation(&Arc::downgrade(&singleton.state), reused.generation());
        fail.store(false, Ordering::SeqCst);

        let replacement = Oneshot::new(singleton, ()).await.unwrap();
        assert!(!replacement.is_reused());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cancellation_and_failure_keep_waiters_progressing() {
        let sender = Arc::new(Mutex::new(None));
        let singleton = Singleton::new_default(ControlledMaker {
            sender: sender.clone(),
        });
        let mut driver = tokio_test::task::spawn(Oneshot::new(singleton.clone(), ()));
        assert!(driver.poll().is_pending());
        let sender = sender.lock().take().expect("maker started");

        let mut waiter = tokio_test::task::spawn(Oneshot::new(singleton, ()));
        assert!(waiter.poll().is_pending());
        drop(driver);
        assert!(waiter.is_woken());
        sender.send("shared").expect("waiter still owns maker");

        let std::task::Poll::Ready(Ok(service)) = waiter.poll() else {
            panic!("promoted waiter should finish the original maker");
        };
        assert_eq!(*service.inner(), "shared");

        let sender = Arc::new(Mutex::new(None));
        let singleton = Singleton::new_default(ControlledMaker {
            sender: sender.clone(),
        });
        let mut driver = tokio_test::task::spawn(Oneshot::new(singleton.clone(), ()));
        assert!(driver.poll().is_pending());
        let sender = sender.lock().take().expect("maker started");
        let mut canceled = tokio_test::task::spawn(Oneshot::new(singleton.clone(), ()));
        let mut waiter = tokio_test::task::spawn(Oneshot::new(singleton, ()));
        assert!(canceled.poll().is_pending());
        assert!(waiter.poll().is_pending());
        drop(canceled);
        sender.send("shared").expect("live participants remain");

        let std::task::Poll::Ready(Ok(driver_service)) = driver.poll() else {
            panic!("driver should complete after a non-driver cancellation");
        };
        let std::task::Poll::Ready(Ok(waiter_service)) = waiter.poll() else {
            panic!("remaining waiter should receive the shared service");
        };
        assert_eq!(*driver_service.inner(), "shared");
        assert_eq!(*waiter_service.inner(), "shared");

        let sender = Arc::new(Mutex::new(None));
        let singleton = Singleton::new_default(ControlledMaker {
            sender: sender.clone(),
        });
        let mut driver = tokio_test::task::spawn(Oneshot::new(singleton.clone(), ()));
        assert!(driver.poll().is_pending());
        let sender = sender.lock().take().expect("maker started");
        let mut waiter = tokio_test::task::spawn(Oneshot::new(singleton.clone(), ()));
        assert!(waiter.poll().is_pending());

        // Failure empties the batch before broadcasting unlocked; a waiter polled in
        // between must keep waiting for the shared error instead of retrying.
        let waiters = {
            let mut state = singleton.state.lock();
            let State::Making(batch) = &mut *state else {
                panic!("maker should still be running");
            };
            let waiters = batch.take_waiters();
            *state = State::Empty;
            waiters
        };
        assert!(waiter.poll().is_pending());
        let error = super::SingletonError::new("maker failed".into());
        super::send_result(waiters, Err(&error));
        let std::task::Poll::Ready(Err(waiter_error)) = waiter.poll() else {
            panic!("waiter should receive the broadcast error");
        };
        assert!(!super::SingletonError::is_canceled(&waiter_error));
        drop(driver);
        drop(sender);

        let sender = Arc::new(Mutex::new(None));
        let singleton = Singleton::new_default(ControlledMaker {
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
        assert!(waiter.is_woken());
        let std::task::Poll::Ready(Err(waiter_error)) = waiter.poll() else {
            panic!("waiter should share the maker error");
        };
        assert!(!super::SingletonError::is_canceled(&waiter_error));
        assert_eq!(
            waiter_error.source().map(ToString::to_string),
            driver_error.source().map(ToString::to_string)
        );

        let sender = Arc::new(Mutex::new(None));
        let singleton = Singleton::new_default(ControlledMaker {
            sender: sender.clone(),
        });
        let mut driver = tokio_test::task::spawn(Oneshot::new(singleton.clone(), ()));
        let mut waiter = tokio_test::task::spawn(Oneshot::new(singleton.clone(), ()));
        assert!(driver.poll().is_pending());
        assert!(waiter.poll().is_pending());
        drop(driver);
        drop(waiter);
        assert!(singleton.with_state(|state| matches!(state, State::Empty)));
        assert!(sender.lock().take().unwrap().is_closed());
    }
}
