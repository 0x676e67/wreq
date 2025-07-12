use http::{Request as HttpRequest, Response as HttpResponse};
use tower::{
    retry::Retry,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, MapErr},
};

use super::{Body, service::ClientService};
use crate::{
    client::layer::{
        redirect::FollowRedirect,
        retry::Http2RetryPolicy,
        timeout::{ResponseBodyTimeout, Timeout, TimeoutBody},
    },
    core::body::Incoming,
    error::BoxError,
    redirect::RedirectPolicy,
};

#[cfg(not(feature = "cookies"))]
type CookieLayer<T> = T;

#[cfg(feature = "cookies")]
type CookieLayer<T> = crate::client::layer::cookie::CookieManager<T>;

#[cfg(not(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate"
)))]
type Decompression<T> = T;

#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate"
))]
type Decompression<T> = crate::client::layer::decoder::Decompression<T>;

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

pub type RedirectLayer =
    FollowRedirect<CookieLayer<ResponseBodyTimeout<Decompression<ClientService>>>, RedirectPolicy>;

pub type CoreResponseFuture = crate::core::client::ResponseFuture;

pub type GenericClientService =
    MapErr<Timeout<Retry<Http2RetryPolicy, RedirectLayer>>, fn(BoxError) -> BoxError>;

pub type BoxedClientService =
    BoxCloneSyncService<HttpRequest<Body>, HttpResponse<ResponseBody>, BoxError>;

pub type BoxedClientServiceLayer = BoxCloneSyncServiceLayer<
    BoxedClientService,
    HttpRequest<Body>,
    HttpResponse<ResponseBody>,
    BoxError,
>;
