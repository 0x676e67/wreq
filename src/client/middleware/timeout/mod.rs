mod body;
mod future;
mod layer;

use std::task::{Context, Poll};

use http::{Request, Response};
use tower_service::Service;

use self::future::{ResponseBodyTimeoutFuture, ResponseFuture};
pub use self::{
    body::TimeoutBody,
    layer::{ResponseBodyTimeoutLayer, TimeoutLayer},
};
use crate::{
    config::{RequestReadTimeout, RequestTotalTimeout},
    core::ext::RequestConfig,
    error::BoxError,
};

/// Timeout middleware for HTTP requests only.
#[derive(Clone)]
pub struct Timeout<T> {
    inner: T,
    total_timeout: RequestConfig<RequestTotalTimeout>,
    read_timeout: RequestConfig<RequestReadTimeout>,
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for Timeout<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = ResponseFuture<S::Future>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let total_timeout = self
            .total_timeout
            .fetch(req.extensions())
            .copied()
            .map(tokio::time::sleep);

        let read_timeout = self
            .read_timeout
            .fetch(req.extensions())
            .copied()
            .map(tokio::time::sleep);

        let uri = req.uri().clone();
        let response = self.inner.call(req);
        ResponseFuture {
            response,
            total_timeout,
            read_timeout,
            uri,
        }
    }
}

/// Applies a [`TimeoutBody`] to the response body.
#[derive(Clone)]
pub struct ResponseBodyTimeout<S> {
    inner: S,
    total_timeout: RequestConfig<RequestTotalTimeout>,
    read_timeout: RequestConfig<RequestReadTimeout>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseBodyTimeout<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = Response<TimeoutBody<ResBody>>;
    type Error = S::Error;
    type Future = ResponseBodyTimeoutFuture<S::Future>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let total_timeout = self.total_timeout.fetch(req.extensions()).copied();
        let read_timeout = self.read_timeout.fetch(req.extensions()).copied();
        ResponseBodyTimeoutFuture {
            inner: self.inner.call(req),
            total_timeout,
            read_timeout,
        }
    }
}
