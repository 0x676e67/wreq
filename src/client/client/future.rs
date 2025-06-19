use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use http::{Request as HttpRequest, Response as HttpResponse};
use pin_project_lite::pin_project;
use tower::util::Oneshot;
use url::Url;

use super::{
    Body, Response,
    types::{BoxedResponseFuture, ResponseBody, SimpleResponseFuture},
};
use crate::{
    Error,
    client::{
        body,
        client::service::ClientService,
        middleware::{self},
    },
    error::BoxError,
};

pin_project! {
    #[project = ResponseFutureProj]
    pub enum ResponseFuture {
        Simple {
            #[pin]
            fut: SimpleResponseFuture,
        },
        WithLayers {
            fut: BoxedResponseFuture,
        },
    }
}

impl Future for ResponseFuture {
    type Output = Result<HttpResponse<ResponseBody>, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            ResponseFutureProj::Simple { fut } => Poll::Ready(ready!(fut.poll(cx))),
            ResponseFutureProj::WithLayers { fut } => Poll::Ready(ready!(fut.as_mut().poll(cx))),
        }
    }
}

pin_project! {
    #[project = PendingProj]
    pub enum Pending {
        Request {
            url: Url,
            #[pin]
            in_flight: Oneshot<ClientService, HttpRequest<Body>>,
        },
        Error {
            error: Option<Error>,
        },
    }
}

impl Pending {
    #[inline(always)]
    pub(crate) fn new(url: Url, in_flight: Oneshot<ClientService, HttpRequest<Body>>) -> Pending {
        Pending::Request { url, in_flight }
    }

    #[inline(always)]
    pub(crate) fn new_err(err: Error) -> Pending {
        Pending::Error { error: Some(err) }
    }
}

impl Future for Pending {
    type Output = Result<Response, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            PendingProj::Request { url, in_flight } => {
                let res = {
                    match in_flight.poll(cx) {
                        Poll::Ready(Ok(res)) => res.map(body::boxed),
                        Poll::Ready(Err(e)) => {
                            let mut e = match e.downcast::<Error>() {
                                Ok(e) => *e,
                                Err(e) => Error::request(e),
                            };

                            if e.url().is_none() {
                                e = e.with_url(url.clone());
                            }

                            return Poll::Ready(Err(e));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                };

                if let Some(uri) = res.extensions().get::<middleware::redirect::RequestUri>() {
                    *url = Url::parse(&uri.0.to_string()).map_err(Error::decode)?;
                }

                Poll::Ready(Ok(Response::new(res, url.clone())))
            }
            PendingProj::Error { error } => Poll::Ready(Err(error
                .take()
                .expect("Error already taken in PendingInner::Error"))),
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
