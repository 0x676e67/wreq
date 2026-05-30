use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};

use http::Response;
use pin_project_lite::pin_project;
use wreq_proto::rt::Sleep;

use super::body::TimeoutBody;
use crate::{
    error::{BoxError, Error, TimedOut},
    rt::Timer,
};

pin_project! {
    /// [`Timeout`] response future
    pub struct ResponseFuture<Fut> {
        #[pin]
        pub(crate) fut: Fut,
        pub(crate) total_timeout: Option<Pin<Box<dyn Sleep>>>,
        pub(crate) read_timeout: Option<Pin<Box<dyn Sleep>>>,
    }
}

impl<F, T, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<T, E>>,
    E: Into<BoxError>,
{
    type Output = Result<T, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        // First, try polling the future
        match this.fut.poll(cx) {
            Poll::Ready(v) => return Poll::Ready(v.map_err(Into::into)),
            Poll::Pending => {}
        }

        // Helper closure for polling a timeout and returning a TimedOut error
        let mut check_timeout = |sleep: Option<&mut Pin<Box<dyn Sleep>>>| {
            if let Some(sleep) = sleep {
                if sleep.as_mut().poll(cx).is_ready() {
                    return Some(Poll::Ready(Err(Error::request(TimedOut).into())));
                }
            }
            None
        };

        // Check total timeout first
        if let Some(poll) = check_timeout(this.total_timeout.as_mut()) {
            return poll;
        }

        // Check read timeout
        if let Some(poll) = check_timeout(this.read_timeout.as_mut()) {
            return poll;
        }

        Poll::Pending
    }
}

pin_project! {
    /// Response future for wrapping the response body in [`TimeoutBody`].
    pub struct ResponseBodyTimeoutFuture<Fut> {
        #[pin]
        pub(super) fut: Fut,
        pub(super) timer: Timer,
        pub(super) total_timeout: Option<Duration>,
        pub(super) read_timeout: Option<Duration>,

    }
}

impl<Fut, ResBody, E> Future for ResponseBodyTimeoutFuture<Fut>
where
    Fut: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = Result<Response<TimeoutBody<ResBody>>, E>;

    #[inline(always)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let timer = self.timer.clone();
        let total_timeout = self.total_timeout;
        let read_timeout = self.read_timeout;
        let res = ready!(self.project().fut.poll(cx))?
            .map(|body| TimeoutBody::new(timer, total_timeout, read_timeout, body));
        Poll::Ready(Ok(res))
    }
}
