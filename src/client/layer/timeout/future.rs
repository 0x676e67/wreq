use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use http::Response;
use pin_project_lite::pin_project;

use super::body::TimeoutBody;
use crate::{
    error::{BoxError, Error, TimedOut},
    rt::{BoxSleep, Timer},
};

pin_project! {
    /// Waits for response headers, then moves the total timeout into the response body.
    pub struct ResponseFuture<Fut> {
        #[pin]
        pub(super) fut: Fut,
        pub(super) timer: Arc<dyn Timer>,
        pub(super) read_timeout: Option<Duration>,
        pub(super) read_timeout_fut: Option<BoxSleep>,
        pub(super) total_timeout_fut: Option<BoxSleep>,
    }
}

impl<Fut, ResBody, E> Future for ResponseFuture<Fut>
where
    Fut: Future<Output = Result<Response<ResBody>, E>>,
    E: Into<BoxError>,
{
    type Output = Result<Response<TimeoutBody<ResBody>>, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        // The total timer covers response headers and body. Poll it first so an
        // expired timeout wins, then move it into `TimeoutBody` below.
        if let Some(timeout) = this.total_timeout_fut.as_mut()
            && Pin::new(timeout).poll(cx).is_ready()
        {
            return Poll::Ready(Err(Error::request(TimedOut).into()));
        }

        // Before headers arrive, the read timer limits that wait. The body rearms
        // the timer when each frame read begins.
        if let Some(timeout) = this.read_timeout_fut.as_mut()
            && Pin::new(timeout).poll(cx).is_ready()
        {
            return Poll::Ready(Err(Error::request(TimedOut).into()));
        }

        // Poll the request after both timers so every pending future registers the
        // current waker before `ready!` returns.
        let response = ready!(this.fut.poll(cx)).map_err(Into::into)?;

        // Moving the running total timer preserves the original deadline.
        Poll::Ready(Ok(response.map(|body| {
            TimeoutBody::new(
                body,
                this.timer.clone(),
                *this.read_timeout,
                this.total_timeout_fut.take(),
            )
        })))
    }
}
