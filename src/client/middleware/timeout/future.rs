use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};

use http::{Response, Uri};
use pin_project_lite::pin_project;
use tokio::time::Sleep;

use super::body::TimeoutBody;
use crate::{
    error::{BoxError, Error, TimedOut},
    into_url::IntoUrlSealed,
};

pin_project! {
    /// [`Timeout`] response future
    #[derive(Debug)]
    pub struct ResponseFuture<T> {
        #[pin]
        pub(crate) response: T,
        #[pin]
        pub(crate) total_timeout: Option<Sleep>,
        #[pin]
        pub(crate) read_timeout: Option<Sleep>,
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

        // Helper closure for polling a timeout and returning a TimedOut error
        let mut check_timeout = |sleep: Option<Pin<&mut Sleep>>| {
            if let Some(sleep) = sleep {
                if sleep.poll(cx).is_ready() {
                    let err = match IntoUrlSealed::into_url(this.uri.to_string()) {
                        Ok(url) => Error::request(TimedOut).with_url(url).into(),
                        Err(_err) => {
                            warn!(
                                "Failed to convert URI to URL: {}, falling back to generic error: {}",
                                this.uri, _err,
                            );
                            Error::builder(TimedOut).into()
                        }
                    };
                    return Some(Poll::Ready(Err(err)));
                }
            }
            None
        };

        // Check total timeout first
        if let Some(poll) = check_timeout(this.total_timeout.as_mut().as_pin_mut()) {
            return poll;
        }

        // Check read timeout
        if let Some(poll) = check_timeout(this.read_timeout.as_mut().as_pin_mut()) {
            return poll;
        }

        Poll::Pending
    }
}

pin_project! {
    /// Response future for [`ResponseBodyTimeout`].
    pub struct ResponseBodyTimeoutFuture<Fut> {
        #[pin]
        pub(crate) inner: Fut,
        pub(crate) total_timeout: Option<Duration>,
        pub(crate) read_timeout: Option<Duration>,
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
