use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use pin_project_lite::pin_project;
use url::Url;

use super::{Response, types::ResponseFuture};
use crate::{
    Error,
    client::{body, layer::redirect::RequestUri},
    into_url::IntoUrlSealed,
};

pin_project! {
    /// [`Pending`] is a future representing the state of an HTTP request, which may be either
    /// an in-flight request (with its associated future and URL) or an error state.
    /// Used to drive the HTTP request to completion or report an error.
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

impl Pending {
    /// Creates a new [`Pending`] representing an in-flight HTTP request with the given URL and
    #[inline]
    pub(crate) fn request(fut: ResponseFuture, url: Url) -> Self {
        Pending::Request {
            fut: Box::pin(fut),
            url: Some(url),
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
        macro_rules! take_url {
            ($url:ident) => {
                $url.take()
                    .expect("Pending::Request polled after completion")
            };
        }

        let (url, res) = match self.project() {
            PendingProj::Request { url, fut } => (url, fut.as_mut().poll(cx)),
            PendingProj::Error { error } => {
                let err = error
                    .take()
                    .expect("Pending::Error polled after completion");
                return Poll::Ready(Err(err));
            }
        };

        let res = match ready!(res) {
            Ok(res) => {
                if let Some(uri) = res.extensions().get::<RequestUri>() {
                    let redirect_url = IntoUrlSealed::into_url(uri.0.to_string())?;
                    *url = Some(redirect_url);
                }
                Ok(Response::new(res.map(body::boxed), take_url!(url)))
            }
            Err(err) => {
                let mut err = err
                    .downcast::<Error>()
                    .map_or_else(Error::request, |err| *err);
                if err.url().is_none() {
                    err = err.with_url(take_url!(url));
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
        assert_eq!(err.url().map(AsRef::as_ref), Some(u), "{err:?}");
    }
}
