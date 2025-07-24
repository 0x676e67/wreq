use http::{Request as HttpRequest, Response as HttpResponse};
use tower::{
    retry::Retry,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, MapErr},
};

use super::{
    Body,
    connect::{Conn, Unnameable},
    service::ClientService,
};
use crate::{
    client::layer::{
        redirect::FollowRedirect,
        retry::Http2RetryPolicy,
        timeout::{ResponseBodyTimeout, Timeout, TimeoutBody},
    },
    core::client::{body::Incoming, connect},
    dns::DynResolver,
    error::BoxError,
    redirect::FollowRedirectPolicy,
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

pub type FollowRedirectLayer = FollowRedirect<
    CookieLayer<ResponseBodyTimeout<Decompression<ClientService>>>,
    FollowRedirectPolicy,
>;

pub type GenericClientService =
    MapErr<Timeout<Retry<Http2RetryPolicy, FollowRedirectLayer>>, fn(BoxError) -> BoxError>;

pub type BoxedClientService =
    BoxCloneSyncService<HttpRequest<Body>, HttpResponse<ResponseBody>, BoxError>;

pub type BoxedClientLayer = BoxCloneSyncServiceLayer<
    BoxedClientService,
    HttpRequest<Body>,
    HttpResponse<ResponseBody>,
    BoxError,
>;

pub type HttpConnector = connect::HttpConnector<DynResolver>;

pub type BoxedConnectorService = BoxCloneSyncService<Unnameable, Conn, BoxError>;

pub type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedConnectorService, Unnameable, Conn, BoxError>;
