use std::{future::Future, pin::Pin};

pub use http::{Request as HttpRequest, Response as HttpResponse};
use tower::{
    retry::{Retry, future::ResponseFuture as RetryResponseFuture},
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, MapErr, future::MapErrFuture},
};

use crate::{
    client::{
        Body,
        client::service::ClientService,
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

// =================== Intermediate Types ===================== //

#[cfg(not(feature = "cookies"))]
type MaybeCookieLayer<T> = T;

#[cfg(feature = "cookies")]
type MaybeCookieLayer<T> = crate::client::middleware::cookie::CookieManager<T>;

#[cfg(not(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate"
)))]
type MaybeDecompression<T> = T;

#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate"
))]
type MaybeDecompression<T> = crate::client::middleware::decoder::Decompression<T>;

#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate"
))]
pub type ResponseBody = TimeoutBody<tower_http::decompression::DecompressionBody<Incoming>>;

#[cfg(not(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate"
)))]
pub type ResponseBody = TimeoutBody<Incoming>;

// =================== Final Type Aliases ===================== //

type RedirectLayer = FollowRedirect<
    MaybeCookieLayer<ResponseBodyTimeout<MaybeDecompression<ClientService>>>,
    RedirectPolicy,
>;

pub type CoreResponseFuture = crate::core::client::ResponseFuture;

pub type GenericResponseFuture = Pin<
    Box<
        MapErrFuture<
            TimeoutResponseFuture<
                RetryResponseFuture<Http2RetryPolicy, RedirectLayer, HttpRequest<Body>>,
            >,
            fn(BoxError) -> BoxError,
        >,
    >,
>;

pub type BoxedResponseFuture =
    Pin<Box<dyn Future<Output = Result<HttpResponse<ResponseBody>, BoxError>> + Send + 'static>>;

pub type GenericClientService =
    Box<MapErr<Timeout<Retry<Http2RetryPolicy, RedirectLayer>>, fn(BoxError) -> BoxError>>;

pub type BoxedClientService =
    BoxCloneSyncService<HttpRequest<Body>, HttpResponse<ResponseBody>, BoxError>;

pub type BoxedClientServiceLayer = BoxCloneSyncServiceLayer<
    BoxedClientService,
    HttpRequest<Body>,
    HttpResponse<ResponseBody>,
    BoxError,
>;
