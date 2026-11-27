//! Unsent and canceled-checkout retry state machine for [`super::Client`].

use std::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

#[cfg(feature = "cookies")]
use http::header::COOKIE;
use http::{Uri, Version};
use tower::BoxError;

use super::super::error;
use crate::Body;

/// Maximum unsent or canceled-checkout retries performed within a single poll.
const MAX_ATTEMPTS_PER_POLL: usize = 2;

/// Cold-path error and unsent request carried out of an [`Attempt`] for retry.
pub(super) struct Retryable {
    pub(super) error: error::Error,
    pub(super) request: http::Request<Body>,
}

/// Terminal or retryable outcome of a single dispatch attempt.
pub(super) enum AttemptOutcome<T> {
    /// Attempt completed with a response or terminal error.
    Done(Result<T, error::Error>),
    /// A shared checkout batch was canceled before connecting; retry intact.
    CheckoutCanceled(Box<Retryable>),
    /// Connection failed before encoding any bytes; retry only if `connection_reused`.
    Unsent {
        retry: Box<Retryable>,
        connection_reused: bool,
    },
}

/// Result of advancing an [`Attempt`]: either in-flight state `S` or a final outcome.
pub(super) enum Step<S, T> {
    Pending(S),
    Ready(AttemptOutcome<T>),
}

/// Single-attempt state machine driven by [`Retry`], borrowing shared context across polls.
pub(super) trait Attempt {
    type Output;
    type State;

    /// Starts a new attempt from `request` and polls it until it yields or finishes.
    fn start(
        &mut self,
        request: http::Request<Body>,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Step<Self::State, Self::Output>;

    /// Polls an in-flight attempt stored in `state`.
    fn poll(
        &mut self,
        state: &mut Self::State,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Poll<AttemptOutcome<Self::Output>>;
}

/// Retries a canceled checkout or an unsent request from a reused connection.
///
/// Restores the original URI, wire version, and auto-generated `Cookie` headers before
/// each retry, yielding after a bounded number of attempts per poll.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub(super) struct Retry<A: Attempt> {
    attempt: A,
    uri: Uri,
    version: Version,
    #[cfg(feature = "cookies")]
    had_cookie: bool,
    state: RetryState<A::State>,
}

// `S` is `SendState` (~168 B) in production; boxing `Start` would add a per-request allocation.
#[allow(clippy::large_enum_variant)]
enum RetryState<S> {
    Start(http::Request<Body>),
    Running(S),
    Done,
}

impl<A: Attempt> Retry<A> {
    /// Captures retry restoration metadata and defers the first attempt until polled.
    pub(super) fn new(request: http::Request<Body>, attempt: A) -> Self {
        let uri = request.uri().clone();
        let version = request.version();
        #[cfg(feature = "cookies")]
        let had_cookie = request.headers().contains_key(COOKIE);

        Self {
            attempt,
            uri,
            version,
            #[cfg(feature = "cookies")]
            had_cookie,
            state: RetryState::Start(request),
        }
    }
}

impl<A: Attempt> Future for Retry<A>
where
    A: Unpin,
    A::State: Unpin,
{
    type Output = Result<A::Output, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Retry recovery follows hyper-util's legacy client.
        // Poll budgeting follows Hyper's HTTP/1 dispatcher.
        for _ in 0..MAX_ATTEMPTS_PER_POLL {
            let outcome = match &mut this.state {
                RetryState::Start(_) => {
                    let RetryState::Start(request) =
                        mem::replace(&mut this.state, RetryState::Done)
                    else {
                        return Poll::Pending;
                    };
                    match this.attempt.start(request, &this.uri, cx) {
                        Step::Pending(state) => {
                            this.state = RetryState::Running(state);
                            return Poll::Pending;
                        }
                        Step::Ready(outcome) => outcome,
                    }
                }
                RetryState::Running(state) => {
                    let outcome = ready!(this.attempt.poll(state, &this.uri, cx));
                    this.state = RetryState::Done;
                    outcome
                }
                RetryState::Done => return Poll::Pending,
            };

            let mut request = match outcome {
                AttemptOutcome::Done(result) => return Poll::Ready(result.map_err(Into::into)),
                AttemptOutcome::CheckoutCanceled(retry) => {
                    let Retryable {
                        error: _error,
                        request,
                    } = *retry;
                    trace!("singleton connection batch canceled, trying again (reason={_error:?})");
                    request
                }
                AttemptOutcome::Unsent {
                    retry,
                    connection_reused: true,
                } => {
                    let Retryable {
                        error: _error,
                        request,
                    } = *retry;
                    trace!("unstarted request canceled, trying again (reason={_error:?})");
                    request
                }
                AttemptOutcome::Unsent {
                    retry,
                    connection_reused: false,
                } => return Poll::Ready(Err(retry.error.into())),
            };

            *request.uri_mut() = this.uri.clone();
            *request.version_mut() = this.version;
            // Regenerate automatic cookies for the next protocol; retain user headers.
            #[cfg(feature = "cookies")]
            if !this.had_cookie {
                request.headers_mut().remove(COOKIE);
            }
            this.state = RetryState::Start(request);
        }

        // The next attempt has not registered a waker; resume it after yielding.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
