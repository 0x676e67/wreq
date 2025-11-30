use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::{Request, Response};
use http_body::Body;
use pin_project_lite::pin_project;
use tower::{Layer, Service};

use super::{CompressedSize, body::CountingBody};

/// A layer that tracks the compressed (wire) size of response bodies.
///
/// This layer wraps response bodies with a counter that tracks bytes as they
/// are read. The counter is stored as a `CompressedSize` extension on the response.
#[derive(Clone, Copy, Debug, Default)]
pub struct WireSizeLayer;

impl WireSizeLayer {
    /// Creates a new `WireSizeLayer`.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for WireSizeLayer {
    type Service = WireSize<S>;

    #[inline]
    fn layer(&self, inner: S) -> Self::Service {
        WireSize { inner }
    }
}

/// A service that tracks the compressed (wire) size of response bodies.
#[derive(Clone, Debug)]
pub struct WireSize<S> {
    inner: S,
}

impl<S> WireSize<S> {
    /// Creates a new `WireSize` service wrapping the given service.
    #[inline]
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for WireSize<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Body,
{
    type Response = Response<CountingBody<ResBody>>;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        ResponseFuture {
            inner: self.inner.call(req),
        }
    }
}

pin_project! {
    /// Future for `WireSize` service responses.
    pub struct ResponseFuture<F> {
        #[pin]
        inner: F,
    }
}

impl<F, ResBody, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
    ResBody: Body,
{
    type Output = Result<Response<CountingBody<ResBody>>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.inner.poll(cx) {
            Poll::Ready(Ok(response)) => {
                let (mut parts, body) = response.into_parts();

                // Create a counter and store it in extensions
                let counter = CompressedSize::new();
                parts.extensions.insert(counter.clone());

                // Wrap the body with the counting wrapper
                let body = CountingBody::new(body, counter);

                Poll::Ready(Ok(Response::from_parts(parts, body)))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}
