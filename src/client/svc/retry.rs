//! Retry handling for requests that protocol dispatch did not encode.

use std::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures_util::future::Either;
use http::Uri;
use pin_project_lite::pin_project;
use tower::{BoxError, Layer, Service, layer::layer_fn, util::Oneshot};

use super::{ConfiguredRequest, dispatch::AttemptError};

/// Creates the internal retry layer for requests not accepted by the protocol.
///
/// The returned layer captures whether retries are enabled and wraps the
/// one-attempt dispatch service in [`RetryUnsent`]. A retry is allowed only when
/// dispatch returns the original [`ConfiguredRequest`] before encoding begins;
/// the request body is never cloned or reconstructed. Disabling retries keeps
/// the same service shape but forwards the first terminal error immediately.
///
/// This layer belongs between request configuration and dispatch so every
/// attempt uses the same prepared connection descriptor and request body.
pub fn layer<S>(enabled: bool) -> impl Layer<S, Service = RetryUnsent<S>> + Clone {
    layer_fn(move |inner| RetryUnsent::new(inner, enabled))
}

/// Retries requests returned before protocol encoding begins.
///
/// The middleware also retries a canceled singleton creation batch. It never
/// recreates a body: only the exact request returned by the inner service is
/// sent again. Protocol errors after encoding remain terminal here and are
/// left to the public retry policy.
#[derive(Clone)]
pub struct RetryUnsent<S> {
    inner: S,
    enabled: bool,
}

pin_project! {
    /// Response future for [`RetryUnsent`].
    ///
    /// The first attempt uses the readiness already obtained by the caller.
    /// Later attempts use [`Oneshot`] so every retry observes the inner
    /// service's readiness contract before it is called again.
    pub struct RetryFuture<S, B>
    where
        S: Service<ConfiguredRequest<B>>,
    {
        #[pin]
        future: Either<S::Future, Oneshot<S, ConfiguredRequest<B>>>,
        service: S,
        original_uri: Uri,
        enabled: bool,
    }
}

// ===== impl RetryUnsent =====

impl<S> RetryUnsent<S> {
    /// Wraps one-attempt request service with internal cancellation retries.
    fn new(inner: S, enabled: bool) -> Self {
        Self { inner, enabled }
    }
}

impl<S, B, R> Service<ConfiguredRequest<B>> for RetryUnsent<S>
where
    S: Service<ConfiguredRequest<B>, Response = R, Error = AttemptError<B>> + Clone,
{
    type Response = R;
    type Error = BoxError;
    type Future = RetryFuture<S, B>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(|error| match error {
            AttemptError::CheckoutCanceled { error, .. }
            | AttemptError::Unsent { error, .. }
            | AttemptError::Terminal(error) => error.into(),
        })
    }

    fn call(&mut self, request: ConfiguredRequest<B>) -> Self::Future {
        let original_uri = request.request.uri().clone();
        let replacement = self.inner.clone();
        let mut service = mem::replace(&mut self.inner, replacement);
        let future = service.call(request);

        RetryFuture {
            future: Either::Left(future),
            service,
            original_uri,
            enabled: self.enabled,
        }
    }
}

// ===== impl RetryFuture =====

impl<S, B, R> Future for RetryFuture<S, B>
where
    S: Service<ConfiguredRequest<B>, Response = R, Error = AttemptError<B>> + Clone,
{
    type Output = Result<R, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let result = ready!(this.future.as_mut().poll(cx));

        let mut request = match result {
            Ok(response) => return Poll::Ready(Ok(response)),
            Err(AttemptError::CheckoutCanceled {
                error: _error,
                request,
            }) if *this.enabled => {
                trace!("singleton connection batch canceled, trying again (reason={_error:?})");
                *request
            }
            Err(AttemptError::Unsent {
                error: _error,
                request,
                connection_reused: true,
            }) if *this.enabled => {
                trace!("unstarted request canceled, trying again (reason={_error:?})");
                *request
            }
            Err(AttemptError::CheckoutCanceled { error, .. })
            | Err(AttemptError::Unsent { error, .. })
            | Err(AttemptError::Terminal(error)) => return Poll::Ready(Err(error.into())),
        };

        *request.request.uri_mut() = this.original_uri.clone();
        this.future
            .set(Either::Right(Oneshot::new(this.service.clone(), request)));
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
