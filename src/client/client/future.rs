use std::{
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use tower::util::BoxCloneSyncService;
use url::Url;

use super::{Body, Response, ResponseBody};
use crate::{
    Error,
    client::{
        body,
        middleware::{self},
    },
    core::service::Oneshot,
    error::BoxError,
};

type ResponseFuture = Oneshot<
    BoxCloneSyncService<http::Request<Body>, http::Response<ResponseBody>, BoxError>,
    http::Request<Body>,
>;

pin_project! {
    pub enum Pending {
        Request { url: Url, #[pin] in_flight: Pin<Box<ResponseFuture>> },
        Error { error: Option<Error> },
    }
}

impl Pending {
    #[inline(always)]
    pub(crate) fn new(url: Url, fut: ResponseFuture) -> Pending {
        Pending::Request {
            url,
            in_flight: Box::pin(fut),
        }
    }

    #[inline(always)]
    pub(crate) fn new_err(err: Error) -> Pending {
        Pending::Error { error: Some(err) }
    }
}

impl Future for Pending {
    type Output = Result<Response, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Pending::Request { url, in_flight } => {
                let res = {
                    let r = in_flight.as_mut().get_mut();
                    match Pin::new(r).poll(cx) {
                        Poll::Ready(Ok(res)) => res.map(body::boxed),
                        Poll::Ready(Err(e)) => {
                            return match e.downcast::<Error>() {
                                Ok(e) => Poll::Ready(Err(*e)),
                                Err(e) => Poll::Ready(Err(Error::request(e))),
                            };
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                };

                if let Some(uri) = res.extensions().get::<middleware::redirect::RequestUri>() {
                    *url = Url::parse(&uri.0.to_string()).map_err(Error::decode)?;
                }

                Poll::Ready(Ok(Response::new(res, url.clone())))
            }
            Pending::Error { error } => Poll::Ready(Err(error
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
        assert!(s < 128, "size_of::<Pending>() == {s}, too big");
    }
}
