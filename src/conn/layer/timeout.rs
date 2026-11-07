//! Runtime-neutral deadline for one connector call.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use tower::BoxError;

use crate::{error::TimedOut, rt::BoxSleep};

pin_project! {
    /// Owns one in-flight connection and its optional timeout sleep.
    ///
    /// The connection is polled first; while it remains pending, the sleep can end the attempt.
    /// Dropping this future drops both operations.
    pub struct TimeoutFuture<F> {
        #[pin]
        future: F,
        sleep: Option<BoxSleep>,
    }
}

// ===== impl TimeoutFuture =====

impl<F> TimeoutFuture<F> {
    pub(in crate::conn) fn new(future: F, sleep: Option<BoxSleep>) -> Self {
        Self { future, sleep }
    }
}

impl<F, T, E> Future for TimeoutFuture<F>
where
    F: Future<Output = Result<T, E>>,
    E: Into<BoxError>,
{
    type Output = Result<T, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.future.poll(cx) {
            Poll::Ready(result) => return Poll::Ready(result.map_err(Into::into)),
            Poll::Pending => {}
        }

        if let Some(sleep) = this.sleep.as_mut()
            && Pin::new(&mut *sleep).poll(cx).is_ready()
        {
            return Poll::Ready(Err(Box::new(TimedOut)));
        }

        Poll::Pending
    }
}
