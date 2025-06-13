use std::task::{Context, Poll};

/// A function to help "yield" a future, such that it is re-scheduled immediately.
///
/// Useful for spin counts, so a future doesn't hog too much time.
pub(crate) fn yield_now(cx: &mut Context<'_>) -> Poll<std::convert::Infallible> {
    cx.waker().wake_by_ref();
    Poll::Pending
}

/// Poll the future once and return `Some` if it is ready, else `None`.
///
/// If the future wasn't ready, the future likely can't be driven to completion any more: the
/// polling uses a no-op waker, so knowledge of what the pending future was waiting for is lost.
pub(crate) fn now_or_never<F: std::future::Future>(fut: F) -> Option<F::Output> {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let fut = std::pin::pin!(fut);
    match fut.poll(&mut cx) {
        Poll::Ready(res) => Some(res),
        Poll::Pending => None,
    }
}
