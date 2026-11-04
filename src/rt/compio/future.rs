//! A `Send + Future` wrapper for non-`Send` futures (e.g. compio futures).

use std::{
    pin::Pin,
    task::{Context, Poll},
};

/// A `Send + Future` wrapper for non-`Send` futures (e.g. compio futures).
///
/// `SendWrapper` provides `Send` and checks thread affinity at runtime.
/// Polling or dropping on another thread panics.
pub(super) struct SendFuture<F>(send_wrapper::SendWrapper<F>);

impl<F: Future> SendFuture<F> {
    /// Wraps a non-`Send` future in a `SendFuture`.
    pub(super) fn new(fut: F) -> Self {
        Self(send_wrapper::SendWrapper::new(fut))
    }
}

impl<F: Future> Future for SendFuture<F> {
    type Output = F::Output;

    #[allow(unsafe_code)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: the private wrapper never moves F after being pinned. Access
        // through SendWrapper checks the creating thread before projecting to F.
        let this = unsafe { self.get_unchecked_mut() };
        let inner: Pin<&mut F> = unsafe { Pin::new_unchecked(&mut *this.0) };
        inner.poll(cx)
    }
}
