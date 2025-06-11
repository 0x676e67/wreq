use bytes::Bytes;
use http::{Extensions, HeaderMap, Method};
use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Sleep;
use url::Url;

use super::{Body, ClientRef, Response};

use crate::{
    Error,
    client::body,
    core::{body::Incoming, service::Oneshot},
    error::{self, BoxError},
    into_url::try_uri,
    redirect::{self},
};

type ResponseFuture = std::pin::Pin<
    Box<dyn Future<Output = Result<http::Response<Incoming>, BoxError>> + Send + 'static>,
>;

pin_project! {
    pub struct Pending {
        #[pin]
        pub inner: PendingInner,
    }
}

pub(super) enum PendingInner {
    Request(Pin<Box<PendingRequest>>),
    Error(Option<Error>),
}

pin_project! {
    pub(super) struct PendingRequest {
        pub method: Method,
        pub url: Url,
        pub headers: HeaderMap,
        pub body: Option<Option<Bytes>>,
        pub extensions: Extensions,
        pub http2_retry_count: usize,
        pub http2_max_retry_count: usize,
        pub redirect: Option<redirect::Policy>,
        pub inner: Arc<ClientRef>,
        #[pin]
        pub in_flight: ResponseFuture,
        #[pin]
        pub total_timeout: Option<Pin<Box<Sleep>>>,
        #[pin]
        pub read_timeout_fut: Option<Pin<Box<Sleep>>>,
        pub read_timeout: Option<Duration>,
    }
}

impl PendingRequest {
    #[inline]
    fn in_flight(self: Pin<&mut Self>) -> Pin<&mut ResponseFuture> {
        self.project().in_flight
    }

    #[inline]
    fn total_timeout(self: Pin<&mut Self>) -> Pin<&mut Option<Pin<Box<Sleep>>>> {
        self.project().total_timeout
    }

    #[inline]
    fn read_timeout(self: Pin<&mut Self>) -> Pin<&mut Option<Pin<Box<Sleep>>>> {
        self.project().read_timeout_fut
    }

    fn retry_error(mut self: Pin<&mut Self>, err: &(dyn std::error::Error + 'static)) -> bool {
        if !is_retryable_error(err) {
            return false;
        }

        trace!("can retry {:?}", err);

        let body = match self.body {
            Some(Some(ref body)) => Body::reusable(body.clone()),
            Some(None) => {
                debug!("error was retryable, but body not reusable");
                return false;
            }
            None => Body::empty(),
        };

        if self.http2_retry_count >= self.http2_max_retry_count {
            trace!("retry count too high");
            return false;
        }
        self.http2_retry_count += 1;

        let uri = match try_uri(&self.url) {
            Some(uri) => uri,
            None => {
                debug!("a parsed Url should always be a valid Uri: {}", self.url);
                return false;
            }
        };

        *self.as_mut().in_flight().get_mut() = {
            let mut req = http::Request::builder()
                .uri(uri)
                .method(self.method.clone())
                .body(body)
                .expect("valid request parts");

            *req.headers_mut() = self.headers.clone();
            *req.extensions_mut() = self.extensions.clone();
            Box::pin(Oneshot::new(self.inner.client.clone(), req))
        };

        true
    }
}

impl Pending {
    pub(crate) fn new_err(err: Error) -> Pending {
        Pending {
            inner: PendingInner::Error(Some(err)),
        }
    }

    fn inner(self: Pin<&mut Self>) -> Pin<&mut PendingInner> {
        self.project().inner
    }
}

impl Future for Pending {
    type Output = Result<Response, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.inner();
        match inner.get_mut() {
            PendingInner::Request(req) => Pin::new(req).poll(cx),
            PendingInner::Error(err) => Poll::Ready(Err(err
                .take()
                .unwrap_or_else(|| error::request("Pending error polled more than once")))),
        }
    }
}

impl Future for PendingRequest {
    type Output = Result<Response, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(delay) = self.as_mut().total_timeout().as_mut().as_pin_mut() {
            if let Poll::Ready(()) = delay.poll(cx) {
                return Poll::Ready(Err(
                    error::request(error::TimedOut).with_url(self.url.clone())
                ));
            }
        }

        if let Some(delay) = self.as_mut().read_timeout().as_mut().as_pin_mut() {
            if let Poll::Ready(()) = delay.poll(cx) {
                return Poll::Ready(Err(
                    error::request(error::TimedOut).with_url(self.url.clone())
                ));
            }
        }

        loop {
            let res = {
                let r = self.as_mut().in_flight().get_mut();
                match Pin::new(r).poll(cx) {
                    Poll::Ready(Err(e)) => {
                        // Http2 errors are retryable, so we check if we can retry
                        if let Some(e) = e.source() {
                            if self.as_mut().retry_error(e) {
                                continue;
                            }
                        }

                        // If the error is an Error, we return it
                        return match e.downcast::<Error>() {
                            Ok(e) => Poll::Ready(Err(*e)),
                            Err(e) => Poll::Ready(Err(error::request(e))),
                        };
                    }
                    Poll::Ready(Ok(res)) => res.map(body::boxed),
                    Poll::Pending => return Poll::Pending,
                }
            };

            if let Some(url) = &res
                .extensions()
                .get::<tower_http::follow_redirect::RequestUri>()
            {
                self.url = match Url::parse(&url.0.to_string()) {
                    Ok(url) => url,
                    Err(e) => return Poll::Ready(Err(error::decode(e))),
                }
            };

            let res = Response::new(
                res,
                self.url.clone(),
                self.inner.accepts,
                self.total_timeout.take(),
                self.read_timeout,
            );

            return Poll::Ready(Ok(res));
        }
    }
}

fn is_retryable_error(err: &(dyn std::error::Error + 'static)) -> bool {
    // pop the legacy::Error
    let err = if let Some(err) = err.source() {
        err
    } else {
        return false;
    };

    if let Some(cause) = err.source() {
        if let Some(err) = cause.downcast_ref::<http2::Error>() {
            // They sent us a graceful shutdown, try with a new connection!
            if err.is_go_away() && err.is_remote() && err.reason() == Some(http2::Reason::NO_ERROR)
            {
                return true;
            }

            // REFUSED_STREAM was sent from the server, which is safe to retry.
            // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.7-3.2
            if err.is_reset()
                && err.is_remote()
                && err.reason() == Some(http2::Reason::REFUSED_STREAM)
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod test {

    #[test]
    fn test_future_size() {
        let s = std::mem::size_of::<super::Pending>();
        assert!(s < 128, "size_of::<Pending>() == {s}, too big");
    }
}
