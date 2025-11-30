use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use http::{Request, Uri};
use pin_project_lite::pin_project;
use tower::util::Oneshot;

use super::{Body, ClientRef, Response};
use crate::{
    Error,
    client::{body, connect::capture::CaptureConnection},
    ext::RequestUri,
};

type ResponseFuture = Oneshot<ClientRef, Request<Body>>;

pin_project! {
    /// [`Pending`] is a future representing the state of an HTTP request, which may be either
    /// an in-flight request (with its associated future and URI) or an error state.
    /// Used to drive the HTTP request to completion or report an error.
    #[project = PendingProj]
    pub enum Pending {
        Request {
            uri: Uri,
            captured: CaptureConnection,
            fut: Pin<Box<ResponseFuture>>,
        },
        Error {
            error: Option<Error>,
        },
    }
}

impl Pending {
    /// Creates a new [`Pending`] with a request future and its associated URI.
    #[inline]
    pub(crate) fn request(uri: Uri, captured: CaptureConnection, fut: ResponseFuture) -> Self {
        Pending::Request {
            uri,
            captured,
            fut: Box::pin(fut),
        }
    }

    /// Creates a new [`Pending`] with an error.
    #[inline]
    pub(crate) fn error(error: Error) -> Self {
        Pending::Error { error: Some(error) }
    }
}

impl Future for Pending {
    type Output = Result<Response, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (uri, captured, res) = match self.project() {
            PendingProj::Request { uri, captured, fut } => (uri, captured, fut.as_mut().poll(cx)),
            PendingProj::Error { error } => {
                return error
                    .take()
                    .map(Err)
                    .map(Poll::Ready)
                    .expect("Pending::Error polled after completion");
            }
        };

        let res = match ready!(res) {
            Ok(mut res) => {
                if let Some(redirect_uri) = res.extensions_mut().remove::<RequestUri>() {
                    *uri = redirect_uri.0;
                }
                Ok(Response::new(
                    uri.clone(),
                    captured.clone(),
                    res.map(body::boxed),
                ))
            }
            Err(err) => {
                let mut err = err
                    .downcast::<Error>()
                    .map_or_else(Error::request, |err| *err);
                if err.uri().is_none() {
                    err = err.with_uri(uri.clone());
                }
                Err(err)
            }
        };

        Poll::Ready(res)
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
        assert_eq!(err.uri().unwrap(), u, "{err:?}");
    }
}
