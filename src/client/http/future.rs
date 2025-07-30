use std::{
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use url::Url;

use super::{
    Response,
    types::{CoreResponseFuture, ResponseFuture},
};
use crate::{
    Error,
    client::{body, layer::redirect::RequestUri},
    core::client::body::Incoming,
    error::BoxError,
    into_url::IntoUrlSealed,
};

macro_rules! take_url {
    ($url:ident) => {
        match $url.take() {
            Some(url) => url,
            None => {
                return Poll::Ready(Err(Error::builder("URL already taken in Pending::Request")))
            }
        }
    };
}

macro_rules! take_err {
    ($err:ident) => {
        match $err.take() {
            Some(err) => err,
            None => Error::builder("Error already taken in Error"),
        }
    };
}

pin_project! {
    /// [`Pending`] HTTP request future, representing either an in-flight request or an error state.
    #[project = PendingProj]
    pub enum Pending {
        Request {
            fut: Pin<Box<ResponseFuture>>,
            url: Option<Url>,
        },
        Error {
            error: Option<Error>,
        },
    }
}

pin_project! {
    /// [`CorePending`] wraps a low-level HTTP response future or an error state for
    #[project = CorePendingProj]
    pub enum CorePending {
        Request {
            #[pin]
            fut: CoreResponseFuture,
        },
        Error {
            error: Option<Error>,
        },
    }
}

// ======== Pending impl ========

impl Pending {
    /// Creates a new [`Pending`] representing an in-flight HTTP request with the given URL and
    #[inline(always)]
    pub(crate) fn request(fut: ResponseFuture, url: Url) -> Self {
        Pending::Request {
            fut: Box::pin(fut),
            url: Some(url),
        }
    }

    /// Creates a new [`Pending`] with an error.
    #[inline(always)]
    pub(crate) fn error(error: Error) -> Self {
        Pending::Error { error: Some(error) }
    }
}

impl Future for Pending {
    type Output = Result<Response, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (url, res) = match self.project() {
            PendingProj::Request { url, fut } => (url, fut.as_mut().poll(cx)),
            PendingProj::Error { error } => return Poll::Ready(Err(take_err!(error))),
        };

        match res {
            Poll::Ready(Ok(res)) => {
                if let Some(uri) = res.extensions().get::<RequestUri>() {
                    *url = Some(IntoUrlSealed::into_url(uri.0.to_string())?);
                }

                let resp = Response::new(res.map(body::boxed), take_url!(url));
                Poll::Ready(Ok(resp))
            }
            Poll::Ready(Err(err)) => {
                let mut err = err
                    .downcast::<Error>()
                    .map_or_else(Error::request, |err| *err);
                if err.url().is_none() {
                    err = err.with_url(take_url!(url));
                }

                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ======== CorePending impl ========

impl CorePending {
    /// Creates a new [`CorePending`] from a [`CoreResponseFuture`].
    #[inline(always)]
    pub(crate) fn new(fut: CoreResponseFuture) -> Self {
        CorePending::Request { fut }
    }

    /// Creates a new [`CorePending`] with an error.
    #[inline(always)]
    pub(crate) fn error(error: Error) -> Self {
        CorePending::Error { error: Some(error) }
    }
}

impl Future for CorePending {
    type Output = Result<http::Response<Incoming>, BoxError>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            CorePendingProj::Request { fut } => fut.poll(cx).map(|res| res.map_err(Into::into)),
            CorePendingProj::Error { error } => Poll::Ready(Err(take_err!(error).into())),
        }
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test_future_size() {
        let s = std::mem::size_of::<super::Pending>();
        assert!(s <= 360, "size_of::<Pending>() == {s}, too big");
    }

    #[tokio::test]
    async fn error_has_url() {
        let u = "http://does.not.exist.local/ever";
        let err = crate::Client::new().get(u).send().await.unwrap_err();
        assert_eq!(err.url().map(AsRef::as_ref), Some(u), "{err:?}");
    }
}
