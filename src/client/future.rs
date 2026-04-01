use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
};

use http::{Request, Uri};
use tower::util::{Either, Oneshot};

use super::{Body, BoxedClientService, ClientService, Error, Response};

type H12Future = Pin<Box<Oneshot<Either<ClientService, BoxedClientService>, Request<Body>>>>;

#[cfg(feature = "http3")]
type H3Future = Pin<
    Box<
        dyn Future<
                Output = Result<
                    http::Response<super::H3ResponseBody>,
                    tower::BoxError,
                >,
            > + Send,
    >,
>;

/// [`Pending`] is a future representing the state of an HTTP request, which may be either
/// an in-flight request (with its associated future and URI) or an error state.
/// Used to drive the HTTP request to completion or report an error.
#[allow(private_interfaces)]
pub enum Pending {
    #[doc(hidden)]
    Request {
        uri: Option<Uri>,
        fut: H12Future,
    },
    #[cfg(feature = "http3")]
    #[doc(hidden)]
    H3 {
        uri: Option<Uri>,
        fut: H3Future,
    },
    #[doc(hidden)]
    Error {
        error: Option<Error>,
    },
}

impl Unpin for Pending {}

impl Future for Pending {
    type Output = Result<Response, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match this {
            Pending::Request { uri, fut } => {
                let res = ready!(fut.as_mut().poll(cx));
                let uri = uri.take().expect("Pending::Request polled after completion");
                Poll::Ready(match res {
                    Ok(res) => Ok(Response::new(res, uri)),
                    Err(err) => {
                        let mut err = err
                            .downcast::<Error>()
                            .map_or_else(Error::request, |err| *err);
                        if err.uri().is_none() {
                            err = err.with_uri(uri);
                        }
                        Err(err)
                    }
                })
            }
            #[cfg(feature = "http3")]
            Pending::H3 { uri, fut } => {
                let res = ready!(fut.as_mut().poll(cx));
                let uri = uri.take().expect("Pending::H3 polled after completion");
                Poll::Ready(match res {
                    Ok(res) => Ok(Response::new(res, uri)),
                    Err(err) => {
                        let mut err = err
                            .downcast::<Error>()
                            .map_or_else(Error::request, |err| *err);
                        if err.uri().is_none() {
                            err = err.with_uri(uri);
                        }
                        Err(err)
                    }
                })
            }
            Pending::Error { error } => {
                let err = error.take().expect("Pending::Error polled after completion");
                Poll::Ready(Err(err))
            }
        }
    }
}

#[cfg(test)]
mod test {

    #[tokio::test]
    async fn error_has_url() {
        let u = "http://does.not.exist.local/ever";
        let err = crate::Client::new().get(u).send().await.unwrap_err();
        assert_eq!(err.uri().unwrap(), u, "{err:?}");
    }
}
