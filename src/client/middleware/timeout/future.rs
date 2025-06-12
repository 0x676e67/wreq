use super::body::TimeoutBody;
use crate::error::{self, BoxError, TimedOut};
use http::{Response, Uri};
use pin_project_lite::pin_project;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::time::Sleep;
use url::Url;

pin_project! {
    /// [`Timeout`] response future
    ///
    /// [`Timeout`]: crate::timeout::Timeout
    #[derive(Debug)]
    pub struct ResponseFuture<T> {
        #[pin]
        pub(crate) response: T,
        #[pin]
        pub(crate) sleep: Option<Sleep>,
        pub(crate) uri: Uri,
    }
}

impl<F, T, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<T, E>>,
    E: Into<BoxError>,
{
    type Output = Result<T, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        // First, try polling the future
        match this.response.poll(cx) {
            Poll::Ready(v) => return Poll::Ready(v.map_err(Into::into)),
            Poll::Pending => {}
        }

        // Now check the sleep
        if let Some(sleep) = this.sleep.as_mut().as_pin_mut() {
            return match sleep.poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(_) => {
                    if let Ok(url) = Url::parse(&this.uri.to_string()) {
                        return Poll::Ready(Err(error::request(TimedOut).with_url(url).into()));
                    }

                    Poll::Ready(Err(TimedOut.into()))
                }
            };
        }

        Poll::Pending
    }
}

pin_project! {
    /// Response future for [`ResponseBodyTimeout`].
    pub struct ResponseBodyTimeoutFuture<Fut> {
        #[pin]
        pub(crate) inner: Fut,
        pub(crate) read_timeout: Option<Duration>,
        pub(crate) total_timeout: Option<Duration>,
    }
}

impl<Fut, ResBody, E> Future for ResponseBodyTimeoutFuture<Fut>
where
    Fut: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = Result<Response<TimeoutBody<ResBody>>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let total_timeout = self.total_timeout;
        let read_timeout = self.read_timeout;
        let this = self.project();
        let res = ready!(this.inner.poll(cx))?;
        Poll::Ready(Ok(
            res.map(|body| TimeoutBody::new(total_timeout, read_timeout, body))
        ))
    }
}
