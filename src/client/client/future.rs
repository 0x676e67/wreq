use std::{
    pin::Pin,
    task::{Context, Poll},
};

use http::Response as HttpResponse;
use pin_project_lite::pin_project;
use tower::util::Oneshot;
use url::Url;

use super::{
    Response,
    types::{BoxedClientService, CoreResponseFuture, GenericClientService, HttpRequest},
};
use crate::{
    Body, Error,
    client::{body, middleware::redirect::RequestUri},
    core::body::Incoming,
    error::BoxError,
    into_url::IntoUrlSealed,
};

pin_project! {
    #[project = PendingProj]
    pub enum Pending {
        BoxedRequest {
            url: Option<Url>,
            #[pin]
            fut: Oneshot<BoxedClientService, HttpRequest<Body>>,
        },
        GenericRequest {
            url: Option<Url>,
            fut: Pin<Box<Oneshot<GenericClientService, HttpRequest<Body>>>>,
        },
        Error {
            error: Option<Error>,
        },
    }
}

pin_project! {
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

impl Future for Pending {
    type Output = Result<Response, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (url, res) = match self.project() {
            PendingProj::BoxedRequest { url, fut } => (url, fut.poll(cx)),
            PendingProj::GenericRequest { url, fut } => (url, fut.as_mut().poll(cx)),
            PendingProj::Error { error } => return Poll::Ready(Err(take_err!(error))),
        };

        let res = match res {
            Poll::Ready(Ok(res)) => res.map(body::boxed),
            Poll::Ready(Err(err)) => {
                let mut err = match err.downcast::<Error>() {
                    Ok(err) => *err,
                    Err(e) => Error::request(e),
                };

                if err.url().is_none() {
                    err = err.with_url(take_url!(url));
                }

                return Poll::Ready(Err(err));
            }
            Poll::Pending => return Poll::Pending,
        };

        if let Some(uri) = res.extensions().get::<RequestUri>() {
            *url = Some(IntoUrlSealed::into_url(uri.0.to_string())?);
        }

        Poll::Ready(Ok(Response::new(res, take_url!(url))))
    }
}

// ======== CorePending impl ========

impl Future for CorePending {
    type Output = Result<HttpResponse<Incoming>, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            CorePendingProj::Request { fut } => match fut.poll(cx) {
                Poll::Ready(Ok(res)) => Poll::Ready(Ok(res)),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
                Poll::Pending => Poll::Pending,
            },
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
