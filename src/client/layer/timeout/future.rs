use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};

use bytes::Bytes;
use http::Response;
use http_body::Body as HttpBody;
use pin_project_lite::pin_project;
use wreq_proto::rt::Sleep;

use super::body::TimeoutBody;
use crate::{
    Body,
    error::{BoxError, Error, TimedOut},
    rt::Timer,
};

pin_project! {
    /// [`Timeout`] response future
    pub struct ResponseFuture<F> {
        #[pin]
        pub(crate) response: F,
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
        match this.response.poll(cx) {
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
    /// Response future for [`ResponseBodyTimeout`].
    pub struct ResponseBodyTimeoutFuture<Fut> {
        #[pin]
        pub(super) inner: Fut,
        pub(super) timer: Timer,
        pub(super) total_timeout: Option<Duration>,
        pub(super) read_timeout: Option<Duration>,

    }
}

impl<Fut, ResBody, E> Future for ResponseBodyTimeoutFuture<Fut>
where
    Fut: Future<Output = Result<Response<ResBody>, E>>,
    ResBody: HttpBody + Send + Sync + 'static,
    ResBody::Data: Into<Bytes>,
    ResBody::Error: Into<BoxError>,
{
    type Output = Result<Response<Body>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let timer = self.timer.clone();
        let total_timeout = self.total_timeout;
        let read_timeout = self.read_timeout;
        let res = ready!(self.project().inner.poll(cx))?
            .map(|body| Body::wrap(TimeoutBody::new(timer, total_timeout, read_timeout, body)));
        Poll::Ready(Ok(res))
    }
}
