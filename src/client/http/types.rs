use http::{Request as HttpRequest, Response as HttpResponse};
use tower::{
    retry::Retry,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, Either, MapErr, Oneshot},
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

/// The HTTP response body type, with optional decompression and timeout.
#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate"
))]
pub type ResponseBody = TimeoutBody<tower_http::decompression::DecompressionBody<Incoming>>;

/// The HTTP response body type, with timeout but no decompression.
#[cfg(not(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate"
)))]
pub type ResponseBody = TimeoutBody<Incoming>;

/// Layer that adds redirect, cookie, timeout, and decompression support to a client service.
pub type FollowRedirectLayer = FollowRedirect<
    CookieLayer<ResponseBodyTimeout<Decompression<ClientService>>>,
    FollowRedirectPolicy,
>;

/// HTTP client service with retry, timeout, redirect, and error mapping for HTTP/2.
pub type GenericClientService =
    MapErr<Timeout<Retry<Http2RetryPolicy, FollowRedirectLayer>>, fn(BoxError) -> BoxError>;

/// Boxed HTTP client service object-safe type for requests and responses.
pub type BoxedClientService =
    BoxCloneSyncService<HttpRequest<Body>, HttpResponse<ResponseBody>, BoxError>;

/// Boxed layer for building a boxed client service.
pub type BoxedClientLayer = BoxCloneSyncServiceLayer<
    BoxedClientService,
    HttpRequest<Body>,
    HttpResponse<ResponseBody>,
    BoxError,
>;

/// HTTP connector with dynamic DNS resolver.
pub type HttpConnector = connect::HttpConnector<DynResolver>;

/// Boxed connector service for establishing connections.
pub type BoxedConnectorService = BoxCloneSyncService<Unnameable, Conn, BoxError>;

/// Boxed layer for building a boxed connector service.
pub type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedConnectorService, Unnameable, Conn, BoxError>;

/// Represents either a generic or boxed client service for HTTP
pub type ClientRef = Either<GenericClientService, BoxedClientService>;

/// Future for sending an HTTP request using a client service.
pub type ResponseFuture = Oneshot<ClientRef, HttpRequest<Body>>;

/// Future for sending a raw HTTP request and receiving a response.
pub type CoreResponseFuture = crate::core::client::ResponseFuture;
