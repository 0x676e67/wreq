use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures::future::BoxFuture;
use http::Response;
use http_body::Body as HttpBody;
use pin_project_lite::pin_project;
use tokio::time::Sleep;
use tower::{BoxError, Layer, Service};

/// This tower layer injects an arbitrary delay before calling downstream layers.
#[derive(Clone)]
pub struct DelayLayer {
    delay: Duration,
}

impl DelayLayer {
    #[allow(unused)]
    pub const fn new(delay: Duration) -> Self {
        DelayLayer { delay }
    }
}

impl<S> Layer<S> for DelayLayer {
    type Service = Delay<S>;
    fn layer(&self, service: S) -> Self::Service {
        Delay::new(service, self.delay)
    }
}

impl std::fmt::Debug for DelayLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("DelayLayer")
            .field("delay", &self.delay)
            .finish()
    }
}

/// This tower service injects an arbitrary delay before calling downstream layers.
#[derive(Debug, Clone)]
pub struct Delay<S> {
    inner: S,
    delay: Duration,
}

impl<S> Delay<S> {
    pub fn new(inner: S, delay: Duration) -> Self {
        Delay { inner, delay }
    }
}

impl<S, Request> Service<Request> for Delay<S>
where
    S: Service<Request>,
    S::Error: Into<BoxError>,
{
    type Response = S::Response;

    type Error = BoxError;

    type Future = ResponseFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        println!("Delay::poll_ready called");
        match self.inner.poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(r) => Poll::Ready(r.map_err(Into::into)),
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        println!("Delay::call executed");
        let response = self.inner.call(req);
        let sleep = tokio::time::sleep(self.delay);

        ResponseFuture::new(response, sleep)
    }
}

// `Delay` response future
pin_project! {
    #[derive(Debug)]
    pub struct ResponseFuture<S> {
        #[pin]
        response: S,
        #[pin]
        sleep: Sleep,
    }
}

impl<S> ResponseFuture<S> {
    pub(crate) fn new(response: S, sleep: Sleep) -> Self {
        ResponseFuture { response, sleep }
    }
}

#[derive(Clone)]
pub struct DelayBodyLayer {
    delay: Duration,
}

impl DelayBodyLayer {
    #[allow(unused)]
    pub const fn new(delay: Duration) -> Self {
        Self { delay }
    }
}

impl<S> Layer<S> for DelayBodyLayer {
    type Service = DelayBodyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DelayBodyService {
            inner,
            delay: self.delay,
        }
    }
}

#[derive(Clone)]
pub struct DelayBodyService<S> {
    inner: S,
    delay: Duration,
}

impl<S, Req, B> Service<Req> for DelayBodyService<S>
where
    S: Service<Req, Response = Response<B>>,
    B: HttpBody<Data = Bytes> + Send + Sync + 'static,
{
    type Response = Response<DelayBody<B>>;
    type Error = S::Error;
    type Future = DelayBodyResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Req) -> Self::Future {
        DelayBodyResponseFuture {
            future: self.inner.call(req),
            delay: self.delay,
        }
    }
}

pin_project! {
    pub struct DelayBodyResponseFuture<F> {
        #[pin]
        future: F,
        delay: Duration,
    }
}

impl<F, B, E> Future for DelayBodyResponseFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: HttpBody<Data = Bytes> + Send + Sync + 'static,
{
    type Output = Result<Response<DelayBody<B>>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.future.poll(cx) {
            Poll::Ready(Ok(response)) => {
                Poll::Ready(Ok(response.map(|body| DelayBody::new(body, *this.delay))))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

pin_project! {
    pub struct DelayBody<B> {
        #[pin]
        body: B,
        delay: Duration,
        #[pin]
        sleep: Option<Sleep>,
    }
}

impl<B> DelayBody<B> {
    fn new(body: B, delay: Duration) -> Self {
        Self {
            body,
            delay,
            sleep: None,
        }
    }
}

impl<B> HttpBody for DelayBody<B>
where
    B: HttpBody<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();

        if this.sleep.is_none() {
            this.sleep.set(Some(tokio::time::sleep(*this.delay)));
        }

        if let Some(sleep) = this.sleep.as_mut().as_pin_mut() {
            if sleep.poll(cx).is_pending() {
                return Poll::Pending;
            }
        }

        match this.body.poll_frame(cx) {
            Poll::Ready(Some(frame)) => {
                this.sleep.set(None);
                Poll::Ready(Some(frame))
            }
            other => other,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}

impl<F, S, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<S, E>>,
    E: Into<BoxError>,
{
    type Output = Result<S, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        // First poll the sleep until complete
        match this.sleep.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(_) => {}
        }

        // Then poll the inner future
        match this.response.poll(cx) {
            Poll::Ready(v) => Poll::Ready(v.map_err(Into::into)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Clone)]
pub struct SharedConcurrencyLimitLayer {
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
}

impl SharedConcurrencyLimitLayer {
    #[allow(unused)]
    pub fn new(limit: usize) -> Self {
        Self {
            semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(limit)),
        }
    }
}

impl<S> tower::Layer<S> for SharedConcurrencyLimitLayer {
    type Service = SharedConcurrencyLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SharedConcurrencyLimit {
            inner,
            semaphore: self.semaphore.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SharedConcurrencyLimit<S> {
    inner: S,
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
}

impl<S, Req> tower::Service<Req> for SharedConcurrencyLimit<S>
where
    S: tower::Service<Req> + Clone + Send + 'static,
    S::Future: Send + 'static,
    Req: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // always ready, we handle limits in call
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Req) -> Self::Future {
        let semaphore = self.semaphore.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let _permit = semaphore.acquire_owned().await.unwrap();
            inner.call(req).await
        })
    }
}
