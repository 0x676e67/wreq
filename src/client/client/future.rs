use bytes::Bytes;
use http::{Extensions, HeaderMap, Method, Uri};
use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Sleep;
use tower::util::BoxCloneSyncService;
use url::Url;

use super::{Body, ClientRef, Response};

use crate::{
    Error,
    client::body,
    core::{body::Incoming, service::Oneshot},
    error::{self, BoxError},
    redirect::{self},
};

type ResponseFuture = Oneshot<
    BoxCloneSyncService<http::Request<Body>, http::Response<Incoming>, BoxError>,
    http::Request<Body>,
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
        pub uri: Uri,
        pub url: Url,
        pub headers: HeaderMap,
        pub body: Option<Option<Bytes>>,
        pub extensions: Extensions,
        pub http2_retry_count: usize,
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
    fn http2_retry_error(
        mut self: Pin<&mut Self>,
        err: &(dyn std::error::Error + 'static),
    ) -> bool {
        if !is_http2_retryable_error(err) {
            return false;
        }

        trace!(
            "HTTP/2 retryable error: {:?}, retry_count={}/max={}",
            err, self.http2_retry_count, self.inner.http2_max_retry_count
        );

        let body = match self.body {
            Some(Some(ref body)) => Body::reusable(body.clone()),
            Some(None) => {
                debug!("error was retryable, but body not reusable");
                return false;
            }
            None => Body::empty(),
        };

        if self.http2_retry_count >= self.inner.http2_max_retry_count {
            trace!("http2 retry count too high: {}", self.http2_retry_count);
            return false;
        }
        self.http2_retry_count += 1;

        *self.as_mut().project().in_flight = {
            let mut req = http::Request::builder()
                .uri(self.uri.clone())
                .method(self.method.clone())
                .body(body)
                .expect("valid request parts");

            *req.headers_mut() = self.headers.clone();
            *req.extensions_mut() = self.extensions.clone();
            Oneshot::new(self.inner.client.clone(), req)
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
}

impl Future for Pending {
    type Output = Result<Response, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.project().inner;
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
        if let Some(delay) = self.as_mut().project().read_timeout_fut.as_pin_mut() {
            if let Poll::Ready(()) = delay.poll(cx) {
                return Poll::Ready(Err(
                    error::request(error::TimedOut).with_url(self.url.clone())
                ));
            }
        }

        loop {
            let res = {
                let r = self.as_mut().project().in_flight.get_mut();
                match Pin::new(r).poll(cx) {
                    Poll::Ready(Err(e)) => {
                        // Http2 errors are retryable, so we check if we can retry
                        if let Some(e) = e.source() {
                            if self.as_mut().http2_retry_error(e) {
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

fn is_http2_retryable_error(err: &(dyn std::error::Error + 'static)) -> bool {
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
