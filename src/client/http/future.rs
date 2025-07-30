use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::future::Either;
use http::{Request as HttpRequest, Response as HttpResponse};
use pin_project_lite::pin_project;
use tower::util::Oneshot;
use url::Url;

use super::{BoxedClientService, GenericClientService, Response};
use crate::{
    Body, Error,
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

type ResponseFuture = Either<
    Oneshot<BoxedClientService, HttpRequest<Body>>,
    Oneshot<GenericClientService, HttpRequest<Body>>,
>;

type RawResponseFuture = crate::core::client::ResponseFuture;

pin_project! {
    /// Pending HTTP request future, representing either an in-flight request or an error state.
    #[project = PendingProj]
    pub enum Pending {
        Request {
            url: Option<Url>,
            #[pin]
            fut: ResponseFuture,
        },
        Error {
            error: Option<Error>,
        },
    }
}

pin_project! {
    /// RawPending wraps a low-level HTTP response future or an error state for
    #[project = CorePendingProj]
    pub enum RawPending {
        Request {
            #[pin]
            fut: RawResponseFuture,
        },
        Error {
            error: Option<Error>,
        },
    }
}

// ======== Pending impl ========

impl Pending {
    /// Creates a new [`Pending`] from a [`ResponseFuture`].
    #[inline(always)]
    pub(crate) fn request(url: Url, fut: ResponseFuture) -> Self {
        Pending::Request {
            url: Some(url),
            fut,
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
            PendingProj::Request { url, fut } => (url, fut.poll(cx)),
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

// ======== RawPending impl ========

impl RawPending {
    /// Creates a new [`RawPending`] from a [`RawResponseFuture`].
    #[inline(always)]
    pub(crate) fn new(fut: RawResponseFuture) -> Self {
        RawPending::Request { fut }
    }

    /// Creates a new [`RawPending`] with an error.
    #[inline(always)]
    pub(crate) fn error(error: Error) -> Self {
        RawPending::Error { error: Some(error) }
    }
}

impl Future for RawPending {
    type Output = Result<HttpResponse<Incoming>, BoxError>;

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
