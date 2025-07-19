use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{self, Poll},
};

use http::Response;

use crate::core::{body::Incoming, client::Error};

/// A `Future` that will resolve to an HTTP Response.
#[must_use = "futures do nothing unless polled"]
pub struct ResponseFuture {
    inner: Pin<Box<dyn Future<Output = Result<Response<Incoming>, Error>> + Send>>,
}

impl ResponseFuture {
    #[inline]
    pub(super) fn new<F>(value: F) -> ResponseFuture
    where
        F: Future<Output = Result<Response<Incoming>, Error>> + Send + 'static,
    {
        ResponseFuture {
            inner: Box::pin(value),
        }
    }
}

impl fmt::Debug for ResponseFuture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("Future<Response>")
    }
}

impl Future for ResponseFuture {
    type Output = Result<Response<Incoming>, Error>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}
