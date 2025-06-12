use crate::error::{self, BoxError, TimedOut};
use http::Uri;
use pin_project_lite::pin_project;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
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
        response: T,
        #[pin]
        sleep: Option<Sleep>,
        uri: Uri,
    }
}

impl<T> ResponseFuture<T> {
    pub(crate) fn new(response: T, sleep: Option<Sleep>, uri: Uri) -> Self {
        ResponseFuture {
            response,
            sleep,
            uri,
        }
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

        // Now check the sleep
        match this.sleep.as_pin_mut() {
            None => Poll::Pending,
            Some(sleep) => match sleep.poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(_) => {
                    if let Ok(url) = Url::parse(&this.uri.to_string()) {
                        return Poll::Ready(Err(error::request(TimedOut).with_url(url).into()));
                    }

                    Poll::Ready(Err(TimedOut.into()))
                }
            },
        }
    }
}
