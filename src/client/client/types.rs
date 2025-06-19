use std::pin::Pin;

use http::{Request as HttpRequest, Response as HttpResponse};
use tower::{
    retry::{Retry, future::ResponseFuture as RetryResponseFuture},
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, MapErr, future::MapErrFuture},
};

#[cfg(feature = "cookies")]
use crate::client::middleware::cookie::CookieManager;
use crate::{
    client::{
        Body,
        client::service::BaseClientService,
        middleware::{
            redirect::FollowRedirect,
            retry::Http2RetryPolicy,
            timeout::{ResponseBodyTimeout, Timeout, TimeoutBody, TimeoutResponseFuture},
        },
    },
    core::body::Incoming,
    error::BoxError,
    redirect::RedirectPolicy,
};

#[cfg(not(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
)))]
pub type ResponseBody = TimeoutBody<Incoming>;

#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
))]
pub type ResponseBody = TimeoutBody<DecompressionBody<Incoming>>;

#[cfg(not(feature = "cookies"))]
pub type SimpleResponseFuture = MapErrFuture<
    TimeoutResponseFuture<
        RetryResponseFuture<
            Http2RetryPolicy,
            FollowRedirect<ResponseBodyTimeout<BaseClientService>, RedirectPolicy>,
            HttpRequest<Body>,
        >,
    >,
    fn(BoxError) -> BoxError,
>;

#[cfg(feature = "cookies")]
pub type SimpleResponseFuture = MapErrFuture<
    TimeoutResponseFuture<
        RetryResponseFuture<
            Http2RetryPolicy,
            FollowRedirect<CookieManager<ResponseBodyTimeout<BaseClientService>>, RedirectPolicy>,
            HttpRequest<Body>,
        >,
    >,
    fn(BoxError) -> BoxError,
>;

pub type BoxedResponseFuture = Pin<
    Box<
        dyn Future<Output = Result<HttpResponse<TimeoutBody<Incoming>>, BoxError>> + Send + 'static,
    >,
>;

#[cfg(not(feature = "cookies"))]
pub type SimpleClientService = MapErr<
    Timeout<
        Retry<
            Http2RetryPolicy,
            FollowRedirect<ResponseBodyTimeout<BaseClientService>, RedirectPolicy>,
        >,
    >,
    fn(BoxError) -> BoxError,
>;

#[cfg(feature = "cookies")]
pub type SimpleClientService = MapErr<
    Timeout<
        Retry<
            Http2RetryPolicy,
            FollowRedirect<CookieManager<ResponseBodyTimeout<BaseClientService>>, RedirectPolicy>,
        >,
    >,
    fn(BoxError) -> BoxError,
>;

pub type BoxedClientService =
    BoxCloneSyncService<HttpRequest<Body>, HttpResponse<ResponseBody>, BoxError>;

pub type BoxedClientServiceLayer = BoxCloneSyncServiceLayer<
    BoxedClientService,
    HttpRequest<Body>,
    HttpResponse<ResponseBody>,
    BoxError,
>;
