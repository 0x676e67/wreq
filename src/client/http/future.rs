use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use http::{Request, Uri};
use pin_project_lite::pin_project;
use tower::util::{Either, Oneshot};

use super::{Body, BoxedClientService, CaptureConnection, ClientService, Response};
use crate::{Error, ext::RequestUri};

type ResponseFuture = Oneshot<Either<ClientService, BoxedClientService>, Request<Body>>;

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

impl Future for Pending {
    type Output = Result<Response, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (uri, captured, res) = match self.project() {
            PendingProj::Request { uri, captured, fut } => (uri, captured, fut.as_mut().poll(cx)),
            PendingProj::Error { error } => {
                let err = error
                    .take()
                    .expect("Pending::Error polled after completion");
                return Poll::Ready(Err(err));
            }
        };

        let res = match ready!(res) {
            Ok(mut res) => {
                if let Some(redirect_uri) = res.extensions_mut().remove::<RequestUri>() {
                    *uri = redirect_uri.0;
                }

                let mut res = Response::new(res, uri.clone());
                res.extensions_mut().insert(captured.clone());
                Ok(res)
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
