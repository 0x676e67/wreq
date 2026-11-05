//! Tower services used by the low-level client request path.
//!
//! Configuration runs once before internal retries. Each attempt keeps its
//! checkout through dispatch, handing a busy HTTP/1 sender to a readiness task.
//! Only requests returned before encoding can be retried; bodies are never
//! reconstructed.

use std::{
    future::Future,
    mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use futures_util::future::{self, BoxFuture, Either, Ready};
#[cfg(feature = "http2")]
use http::{
    HeaderMap, Method,
    header::{CONNECTION, SEC_WEBSOCKET_KEY, UPGRADE},
};
use http::{Request, Response, Uri, Version};
use http_body::Body;
use netty::{body::Incoming, conn};
use pin_project_lite::pin_project;
use tower::{
    BoxError, Layer, Service, ServiceBuilder, ServiceExt,
    util::{MapErr, Oneshot},
};
#[cfg(feature = "cookies")]
use {
    crate::cookie::{CookieStore, Cookies},
    http::header::COOKIE,
};

use super::{
    error::{Error, ErrorKind},
    pool::{self, ConnectionConfig},
    request::RequestVersion,
};
use crate::{
    Protocol,
    config::RequestConfig,
    conn::{Conn, config::ConfigSet, request::ConnectRequest, transport::BindOptions},
    ext::UriExt,
    rt::RuntimeHandle,
};

/// Request and dispatch options distributed across the service stack at construction.
#[derive(Clone)]
pub struct Config {
    pub retry_unsent: bool,
    pub set_host: bool,
    pub protocol: Protocol,
    #[cfg(feature = "cookies")]
    pub cookie_store: Option<Arc<dyn CookieStore>>,
}

/// Configures requests and wraps dispatch with unsent retries and error mapping.
/// Client protocol builders are shared; request-local options are captured once
/// before any attempt, without cloning the body.
pub struct Stack<S, B> {
    #[allow(
        clippy::type_complexity,
        reason = "Keep the concrete Tower stack local without another alias"
    )]
    inner: MapErr<RetryUnsent<S>, fn(DispatchError<B>) -> BoxError>,
    proto: Arc<pool::ProtocolBuilders>,
    protocol: Protocol,
    /// Client options; connection keys count only request options that differ.
    config_set: ConfigSet,
    bind_options: Arc<BindOptions>,
}

/// Requests a new HTTP/1 connection that is never taken from or returned to the pool.
///
/// With `extended_connect`, dispatch first tries an established connection of the
/// default request group whose peer enabled RFC 8441 extended CONNECT.
#[derive(Clone, Copy)]
#[cfg_attr(
    not(feature = "ws"),
    allow(
        dead_code,
        reason = "Only WebSocket handshakes request dedicated connections"
    )
)]
pub(super) struct DedicatedConnection {
    #[cfg(feature = "http2")]
    pub(super) extended_connect: bool,
}

/// Original RFC 6455 header fields of a WebSocket handshake riding extended CONNECT.
/// They are restored in order if the request returns unsent, so a retry can use HTTP/1.1.
#[cfg(feature = "http2")]
struct Http1Upgrade {
    headers: HeaderMap,
}

/// A request paired with the connection configuration shared by its attempts.
/// Configuration is captured before checkout and retained across unsent retries.
/// Dispatch returns this value only when the original body has not been sent.
pub struct PoolRequest<B> {
    request: Request<B>,
    connection: ConnectionConfig,
    /// Default-group key whose established sender may carry this WebSocket.
    #[cfg(feature = "http2")]
    extended_connect: Option<crate::conn::request::ConnectionKey>,
}

/// Retries canceled checkouts and unsent requests on reused connections.
/// Only the original request returned by dispatch is eligible; failures after
/// encoding remain the responsibility of the public retry policy.
#[derive(Clone)]
pub struct RetryUnsent<S> {
    inner: S,
    enabled: bool,
}

pin_project! {
    /// Drives internal retries without cloning the request body.
    /// The first call consumes the caller's readiness reservation; subsequent
    /// attempts use `Oneshot` to pair readiness and dispatch on the same service.
    pub struct RetryUnsentFuture<S, B>
    where
        S: Service<PoolRequest<B>>,
    {
        #[pin]
        future: Either<S::Future, Oneshot<S, PoolRequest<B>>>,
        service: S,
        original_uri: Uri,
        had_cookie: bool,
        enabled: bool,
    }
}

/// Performs one connection-pool checkout and protocol send attempt.
///
/// Each call checks out a compatible sender, applies cookies, dispatches the
/// request, and attaches connection metadata. HTTP/2 and HTTP/3 release their
/// local checkout after response headers. HTTP/1 returns immediately only when
/// its sender is ready again; otherwise a pool-owned task waits before returning
/// it. Errors preserve an unsent request when the protocol dispatcher can prove
/// encoding never began.
pub struct Dispatch<C, B>
where
    C: Service<ConnectRequest, Response = Conn, Error = BoxError> + Clone + Send + Sync + 'static,
    C::Future: Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    pool: pool::Pool<C, B>,
    #[cfg(feature = "cookies")]
    cookie_store: RequestConfig<Arc<dyn CookieStore>>,
    runtime: RuntimeHandle,
}

/// Failure from one pool checkout and send attempt.
pub enum DispatchError<B> {
    CheckoutCanceled {
        error: Error,
        request: Box<PoolRequest<B>>,
    },
    Unsent {
        error: Error,
        request: Box<PoolRequest<B>>,
        connection_reused: bool,
    },
    Terminal(Error),
}

/// Creates the configuration and unsent-retry layers for a dispatch service.
///
/// Configuration runs once and shares its protocol builders across service
/// clones. Tower maps terminal dispatch errors only after retry classification,
/// preserving ownership of any request returned before encoding.
pub fn layer<S, B>(
    h1_builder: conn::http1::Builder,
    #[cfg(feature = "http2")] h2_builder: conn::http2::Builder<RuntimeHandle>,
    #[cfg(feature = "http3")] h3_builder: conn::http3::Builder<RuntimeHandle>,
    retry_unsent: bool,
    protocol: Protocol,
    config_set: ConfigSet,
    bind_options: BindOptions,
) -> impl Layer<S, Service = Stack<S, B>> + Clone {
    // Client builders share one allocation across stack clones and pooled requests.
    let proto = Arc::new(pool::ProtocolBuilders {
        http1: h1_builder,
        #[cfg(feature = "http2")]
        http2: h2_builder,
        #[cfg(feature = "http3")]
        http3: h3_builder,
    });
    let bind_options = Arc::new(bind_options);

    ServiceBuilder::new()
        .layer_fn(move |inner| Stack {
            inner,
            proto: proto.clone(),
            protocol,
            config_set: config_set.clone(),
            bind_options: bind_options.clone(),
        })
        .map_err(DispatchError::into_error as fn(DispatchError<B>) -> BoxError)
        .layer_fn(move |inner| RetryUnsent {
            inner,
            enabled: retry_unsent,
        })
        .into_inner()
}

// ===== impl Stack =====

impl<S, B> Stack<S, B> {
    /// Freezes connection settings before checkout and unsent retries.
    fn prepare(&self, mut request: Request<B>) -> Result<PoolRequest<B>, BoxError> {
        let extensions = request.extensions_mut();
        let config_set = extensions.remove::<ConfigSet>().unwrap_or_default();
        let bind_options = extensions.remove::<Arc<BindOptions>>();
        let dedicated = extensions.remove::<DedicatedConnection>();

        // Normalize wire versions to protocol choices; HTTP/1.0 and HTTP/1.1 share a pool.
        let version = RequestConfig::<RequestVersion>::remove(extensions);
        let uri = request.uri();

        // curl's ordinary H2 mode allows HTTPS negotiation; prior knowledge
        // remains explicit: https://curl.se/libcurl/c/CURLOPT_HTTP_VERSION.html
        let protocol = match version {
            Some(Version::HTTP_10 | Version::HTTP_11) => Some(Protocol::Http1),
            #[cfg(feature = "http2")]
            Some(Version::HTTP_2) if uri.is_https() && self.protocol != Protocol::Http2 => {
                Some(Protocol::Auto)
            }
            #[cfg(feature = "http2")]
            Some(Version::HTTP_2) => Some(Protocol::Http2),
            #[cfg(feature = "http3")]
            Some(Version::HTTP_3) => Some(Protocol::Http3),
            Some(_) => {
                return Err(Error::from_kind(ErrorKind::UserUnsupportedVersion).into());
            }
            None => None,
        };

        let req = ConnectRequest::new(
            uri,
            protocol,
            self.protocol,
            config_set,
            &self.config_set,
            bind_options,
            &self.bind_options,
        )
        .map_err(|source| Error::new(ErrorKind::UserAbsoluteUriRequired, source))?;

        // Only clients that may negotiate HTTP/2 have a default group to probe.
        #[cfg(feature = "http2")]
        let extended_connect = (dedicated.is_some_and(|d| d.extended_connect)
            && matches!(self.protocol, Protocol::Auto | Protocol::Http2))
        .then(|| req.key_with_protocol(None, self.protocol, &self.config_set));

        Ok(PoolRequest {
            request,
            connection: ConnectionConfig {
                req,
                proto: self.proto.clone(),
                dedicated: dedicated.is_some(),
            },
            #[cfg(feature = "http2")]
            extended_connect,
        })
    }
}

impl<S: Clone, B> Clone for Stack<S, B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            proto: self.proto.clone(),
            protocol: self.protocol,
            config_set: self.config_set.clone(),
            bind_options: self.bind_options.clone(),
        }
    }
}

impl<S, B> Service<Request<B>> for Stack<S, B>
where
    S: Service<PoolRequest<B>, Error = DispatchError<B>> + Clone,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Either<
        <MapErr<RetryUnsent<S>, fn(DispatchError<B>) -> BoxError> as Service<PoolRequest<B>>>::Future,
        Ready<Result<Self::Response, Self::Error>>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        match self.prepare(request) {
            Ok(request) => Either::Left(self.inner.call(request)),
            Err(error) => Either::Right(future::err(error)),
        }
    }
}

// ===== impl RetryUnsent =====

impl<S, B> Service<PoolRequest<B>> for RetryUnsent<S>
where
    S: Service<PoolRequest<B>, Error = DispatchError<B>> + Clone,
{
    type Response = S::Response;
    type Error = DispatchError<B>;
    type Future = RetryUnsentFuture<S, B>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: PoolRequest<B>) -> Self::Future {
        let original_uri = request.request.uri().clone();
        let had_cookie = cfg!(feature = "cookies")
            && request.request.headers().contains_key(http::header::COOKIE);
        let replacement = self.inner.clone();
        let mut service = mem::replace(&mut self.inner, replacement);
        let future = service.call(request);

        RetryUnsentFuture {
            future: Either::Left(future),
            service,
            original_uri,
            had_cookie,
            enabled: self.enabled,
        }
    }
}

// ===== impl RetryUnsentFuture =====

impl<S, B> Future for RetryUnsentFuture<S, B>
where
    S: Service<PoolRequest<B>, Error = DispatchError<B>> + Clone,
{
    type Output = Result<S::Response, DispatchError<B>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        const MAX_ATTEMPTS_PER_POLL: usize = 2;

        let mut this = self.project();

        // Retry recovery follows hyper-util's legacy client.
        // Poll budgeting follows Hyper's HTTP/1 dispatcher.
        for _ in 0..MAX_ATTEMPTS_PER_POLL {
            let mut request = match ready!(this.future.as_mut().poll(cx)) {
                Ok(response) => return Poll::Ready(Ok(response)),
                Err(DispatchError::CheckoutCanceled {
                    error: _error,
                    request,
                }) if *this.enabled => {
                    trace!("singleton connection batch canceled, trying again (reason={_error:?})");
                    *request
                }
                Err(DispatchError::Unsent {
                    error: _error,
                    request,
                    connection_reused: true,
                }) if *this.enabled => {
                    trace!("unstarted request canceled, trying again (reason={_error:?})");
                    *request
                }
                Err(error) => return Poll::Ready(Err(error)),
            };

            *request.request.uri_mut() = this.original_uri.clone();
            // Regenerate automatic cookies for the next protocol; retain user headers.
            #[cfg(feature = "cookies")]
            if !*this.had_cookie {
                request.request.headers_mut().remove(COOKIE);
            }
            this.future
                .set(Either::Right(Oneshot::new(this.service.clone(), request)));
        }

        // The next Oneshot has not registered a waker; resume it after yielding.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ===== impl DispatchError =====

impl<B> DispatchError<B> {
    fn into_error(self) -> BoxError {
        match self {
            Self::CheckoutCanceled { error, .. }
            | Self::Unsent { error, .. }
            | Self::Terminal(error) => error.into(),
        }
    }
}

// ===== impl Http1Upgrade =====

#[cfg(feature = "http2")]
impl Http1Upgrade {
    /// Rewrites the GET upgrade as extended CONNECT, keeping the other WebSocket fields
    /// ([RFC 8441 §5](https://www.rfc-editor.org/rfc/rfc8441#section-5)).
    fn into_extended_connect<B>(request: &mut Request<B>) -> Self {
        *request.method_mut() = Method::CONNECT;
        *request.version_mut() = Version::HTTP_2;
        request
            .extensions_mut()
            .insert(http2::ext::Protocol::from_static("websocket"));
        let headers = mem::take(request.headers_mut());
        // Connection-specific fields are malformed in HTTP/2; the rest keep their order:
        // https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2
        let extended = request.headers_mut();
        extended.reserve(headers.len());
        for (name, value) in &headers {
            if ![UPGRADE, CONNECTION, SEC_WEBSOCKET_KEY].contains(name) {
                extended.append(name, value.clone());
            }
        }
        Self { headers }
    }

    /// Restores the RFC 6455 GET after an unsent extended CONNECT.
    fn restore<B>(self, request: &mut Request<B>) {
        *request.method_mut() = Method::GET;
        *request.version_mut() = Version::HTTP_11;
        request.extensions_mut().remove::<http2::ext::Protocol>();
        *request.headers_mut() = self.headers;
    }
}

/// Explains failures of HTTP/2 used over HTTPS without negotiating `h2` in ALPN.
fn with_h2_alpn_context(error: Error, unnegotiated_h2: bool) -> Error {
    if unnegotiated_h2 {
        error.with_context(
            "HTTP/2 was used for HTTPS without reported h2 ALPN; \
             the peer may not support HTTP/2",
        )
    } else {
        error
    }
}

/// Rejects extended CONNECT unless the peer enabled it (RFC 8441 §3, RFC 9220 §3).
#[cfg(any(feature = "http2", feature = "http3"))]
fn extended_connect_disabled<B>(pooled: &pool::Pooled<B>) -> Error
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    warn!("peer did not enable extended CONNECT");
    Error::from_kind(ErrorKind::UserUnsupportedVersion)
        .with_context("peer did not enable extended CONNECT")
        .with_connect_info(pooled.conn_info().clone())
}

// ===== impl Dispatch =====

impl<C, B> Dispatch<C, B>
where
    C: Service<ConnectRequest, Response = Conn, Error = BoxError> + Clone + Send + Sync + 'static,
    C::Future: Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Creates the terminal request service and its shared connection pool.
    pub(crate) fn new(
        pool_config: pool::Config,
        connector: C,
        config: Config,
        runtime: RuntimeHandle,
    ) -> Self {
        Self {
            pool: pool::Pool::new(pool_config, connector, runtime.clone(), config.set_host),
            #[cfg(feature = "cookies")]
            cookie_store: RequestConfig::new(config.cookie_store),
            runtime,
        }
    }
}

impl<C, B> Clone for Dispatch<C, B>
where
    C: Service<ConnectRequest, Response = Conn, Error = BoxError> + Clone + Send + Sync + 'static,
    C::Future: Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            runtime: self.runtime.clone(),
            #[cfg(feature = "cookies")]
            cookie_store: self.cookie_store.clone(),
        }
    }
}

impl<C, B> Service<PoolRequest<B>> for Dispatch<C, B>
where
    C: Service<ConnectRequest, Response = Conn, Error = BoxError> + Clone + Send + Sync + 'static,
    C::Future: Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Incoming>;
    type Error = DispatchError<B>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: PoolRequest<B>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let PoolRequest {
                mut request,
                connection,
                #[cfg(feature = "http2")]
                extended_connect,
            } = request;

            // RFC 8441 §3: extended CONNECT only after the peer enabled it. A miss keeps
            // the dedicated HTTP/1.1 upgrade, so no HTTP/2 connection is opened for it.
            #[cfg(feature = "http2")]
            let reused = extended_connect
                .as_ref()
                .and_then(|key| this.pool.checkout_extended_connect(key));
            #[cfg(not(feature = "http2"))]
            let reused: Option<pool::Pooled<B>> = None;
            #[cfg(feature = "http2")]
            let upgrade = reused
                .is_some()
                .then(|| Http1Upgrade::into_extended_connect(&mut request));

            let mut pooled = match reused {
                Some(pooled) => pooled,
                None => {
                    let protocol = connection.req.resolved_protocol();
                    #[cfg(feature = "http3")]
                    if protocol == Protocol::Http3 && !connection.req.uri().is_https() {
                        return Err(DispatchError::Terminal(Error::from_kind(
                            ErrorKind::UserUnsupportedVersion,
                        )));
                    }
                    match this.pool.checkout(connection.clone(), protocol).await {
                        Ok(pooled) => pooled,
                        Err(error) if pool::is_canceled(&*error) => {
                            return Err(DispatchError::CheckoutCanceled {
                                error: Error::new(ErrorKind::Connect, error),
                                request: Box::new(PoolRequest {
                                    request,
                                    connection,
                                    #[cfg(feature = "http2")]
                                    extended_connect,
                                }),
                            });
                        }
                        Err(error) => {
                            return Err(DispatchError::Terminal(Error::new(
                                ErrorKind::Connect,
                                error,
                            )));
                        }
                    }
                }
            };

            #[cfg(feature = "http3")]
            if pooled.is_http3() {
                *request.version_mut() = Version::HTTP_3;
            }

            #[cfg(feature = "http2")]
            let extended = request.extensions().get::<http2::ext::Protocol>().is_some();
            #[cfg(all(not(feature = "http2"), feature = "http3"))]
            let extended = false;
            #[cfg(feature = "http3")]
            let extended = extended
                || (pooled.is_http3()
                    && request
                        .extensions()
                        .get::<netty::http3::Protocol>()
                        .is_some());
            #[cfg(any(feature = "http2", feature = "http3"))]
            if extended {
                // Extended CONNECT needs HTTP/2 (RFC 8441) or HTTP/3 (RFC 9220).
                // Over HTTP/1 it would be an ordinary tunnel request:
                // https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6
                if pooled.is_http1() {
                    warn!("Connection is HTTP/1, but extended CONNECT requires HTTP/2 or HTTP/3");
                    return Err(DispatchError::Terminal(
                        Error::from_kind(ErrorKind::UserUnsupportedVersion)
                            .with_connect_info(pooled.conn_info().clone()),
                    ));
                }
                if pooled.extended_connect() == Some(false) {
                    return Err(DispatchError::Terminal(extended_connect_disabled(&pooled)));
                }
            }

            if connection.req.protocol() == Some(Protocol::Auto) {
                // Resolve the wire version on every attempt: an unsent retry may
                // select a different protocol, but retains the original preference.
                *request.version_mut() = if pooled.is_http2() {
                    Version::HTTP_2
                } else {
                    Version::HTTP_11
                };
            } else if pooled.is_http1()
                && !matches!(request.version(), Version::HTTP_10 | Version::HTTP_11)
            {
                warn!(
                    "Connection is HTTP/1, but request requires {:?}",
                    request.version()
                );
                return Err(DispatchError::Terminal(
                    Error::from_kind(ErrorKind::UserUnsupportedVersion)
                        .with_connect_info(pooled.conn_info().clone()),
                ));
            }

            #[cfg(feature = "cookies")]
            let uri = request.uri().clone();
            #[cfg(feature = "cookies")]
            let cookie_store = this.cookie_store.fetch(request.extensions()).cloned();

            #[cfg(feature = "cookies")]
            if let Some(ref cookie_store) = cookie_store {
                // ALPN may select HTTP/2 while an automatic request still has
                // its default HTTP/1.1 version in the request object.
                let version = if pooled.is_http2() {
                    Version::HTTP_2
                } else if pooled.is_http1() {
                    Version::HTTP_11
                } else {
                    Version::HTTP_3
                };
                apply_request_cookies(&mut request, cookie_store.as_ref(), &uri, version);
            }

            let mut response = match pooled.call(request).await {
                Ok(response) => response,
                Err(mut error) => {
                    let connection_reused = pooled.is_reused();
                    let connect_info = pooled.conn_info().clone();
                    let unnegotiated_h2 = pooled.is_http2()
                        && connection.req.uri().is_https()
                        && !connect_info.is_negotiated_h2();
                    // A returned request was not sent; only protocol rejections are final,
                    // since they repeat on the same connection.
                    if let Some(request) =
                        (!error.is_user()).then(|| error.take_message()).flatten()
                    {
                        #[cfg(feature = "http2")]
                        let mut request = request;
                        #[cfg(feature = "http2")]
                        if let Some(upgrade) = upgrade {
                            upgrade.restore(&mut request);
                        }
                        let error = error.into_client_error(ErrorKind::Canceled);
                        return Err(DispatchError::Unsent {
                            error: with_h2_alpn_context(error, unnegotiated_h2)
                                .with_connect_info(connect_info),
                            request: Box::new(PoolRequest {
                                request,
                                connection,
                                #[cfg(feature = "http2")]
                                extended_connect,
                            }),
                            connection_reused,
                        });
                    }
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    if extended && pooled.extended_connect() == Some(false) {
                        return Err(DispatchError::Terminal(extended_connect_disabled(&pooled)));
                    }
                    let error = error.into_client_error(ErrorKind::SendRequest);
                    return Err(DispatchError::Terminal(
                        with_h2_alpn_context(error, unnegotiated_h2)
                            .with_connect_info(connect_info),
                    ));
                }
            };

            #[cfg(feature = "cookies")]
            if let Some(cookie_store) = cookie_store {
                store_response_cookies(&response, cookie_store.as_ref(), &uri);
            }

            pooled.conn_info().set_extras(response.extensions_mut());
            response.extensions_mut().insert(pooled.conn_info().clone());

            // Multiplexed senders are shared, so only HTTP/1 waits to become ready again.
            if !pooled.is_http1() || !pooled.is_pool_enabled() || pooled.is_ready() {
                drop(pooled);
            } else {
                this.runtime.execute(Box::pin(async move {
                    let _ = pooled.ready().await;
                }));
            }

            Ok(response)
        })
    }
}

#[cfg(feature = "cookies")]
fn apply_request_cookies<B>(
    request: &mut Request<B>,
    cookie_store: &dyn CookieStore,
    uri: &Uri,
    version: Version,
) {
    let headers = request.headers_mut();
    if headers.contains_key(COOKIE) {
        return;
    }
    match cookie_store.cookies(uri, version) {
        Cookies::Compressed(value) => {
            headers.insert(COOKIE, value);
        }
        Cookies::Uncompressed(values) => {
            for value in values {
                headers.append(COOKIE, value);
            }
        }
        Cookies::Empty => {}
    }
}

#[cfg(feature = "cookies")]
fn store_response_cookies(
    response: &Response<Incoming>,
    cookie_store: &dyn CookieStore,
    uri: &Uri,
) {
    let mut cookies = response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .peekable();
    if cookies.peek().is_some() {
        cookie_store.set_cookies(&mut cookies, uri);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn protocol_options_partition_connections_and_preserve_reuse() {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Full};

        for protocol in [
            Protocol::Http1,
            #[cfg(feature = "http2")]
            Protocol::Http2,
        ] {
            #[cfg(feature = "http2")]
            let h2 = protocol == Protocol::Http2;
            #[cfg(not(feature = "http2"))]
            let h2 = false;
            let calls = Arc::new(AtomicUsize::new(0));
            let accepted = calls.clone();
            let connector = tower::service_fn(move |conn_req: ConnectRequest| {
                let id = accepted.fetch_add(1, Ordering::Relaxed);
                assert_eq!(conn_req.uri(), "http://localhost/");
                assert!(
                    conn_req
                        .config_set()
                        .get::<crate::http1::Http1Options>()
                        .is_some()
                );
                #[cfg(feature = "http2")]
                assert!(
                    conn_req
                        .config_set()
                        .get::<crate::http2::Http2Options>()
                        .is_some()
                );
                let (client, server) = tokio::io::duplex(16384);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |request: http::Request<hyper::body::Incoming>| async move {
                            let mut response =
                                Response::new(Full::new(Bytes::from(id.to_string())));
                            if request.uri().path() == "/limits" {
                                for i in 0..40 {
                                    response.headers_mut().insert(
                                        http::HeaderName::from_bytes(format!("x-{i}").as_bytes())
                                            .unwrap(),
                                        http::HeaderValue::from_static("1"),
                                    );
                                }
                            }
                            Ok::<_, std::convert::Infallible>(response)
                        },
                    );
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(server), service)
                    .await;
                });
                future::ready(Ok::<_, BoxError>(Conn::test(client)))
            });
            let mut stack = layer(
                conn::http1::Builder::default(),
                #[cfg(feature = "http2")]
                conn::http2::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                #[cfg(feature = "http3")]
                conn::http3::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                true,
                protocol,
                ConfigSet::default(),
                BindOptions::default(),
            )
            .layer(Dispatch::new(
                pool::Config::default(),
                connector,
                Config {
                    retry_unsent: true,
                    set_host: true,
                    protocol,
                    #[cfg(feature = "cookies")]
                    cookie_store: None,
                },
                RuntimeHandle::new(crate::rt::tokio::TokioRuntime),
            ));
            for (attempt, (strict, id)) in [
                (false, "0"),
                (true, "1"),
                (true, "1"),
                (false, "0"),
                (true, "1"),
            ]
            .into_iter()
            .enumerate()
            {
                let limits = attempt == 4 && protocol == Protocol::Http1;
                let mut request = Request::builder()
                    .version(if h2 {
                        Version::HTTP_2
                    } else {
                        Version::HTTP_11
                    })
                    .uri(if limits {
                        "http://localhost/limits"
                    } else {
                        "http://localhost/"
                    })
                    .body(crate::Body::default())
                    .unwrap();
                let mut config_set = ConfigSet::default();
                config_set.insert(
                    crate::http1::Http1Options::builder()
                        .max_headers(if strict && protocol == Protocol::Http1 {
                            32
                        } else {
                            64
                        })
                        .build(),
                );
                #[cfg(feature = "http2")]
                config_set.insert(
                    crate::http2::Http2Options::builder()
                        .header_table_size(if strict && h2 { 8192 } else { 4096 })
                        .build(),
                );
                request.extensions_mut().insert(config_set);
                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    stack.ready().await.unwrap().call(request),
                )
                .await
                .unwrap();
                if limits {
                    assert!(
                        response.is_err(),
                        "the selected HTTP/1 override must reject 40 headers"
                    );
                    continue;
                }
                let response = response.unwrap();
                assert_eq!(
                    response.version(),
                    if protocol == Protocol::Http1 {
                        Version::HTTP_11
                    } else {
                        Version::HTTP_2
                    }
                );
                assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), id);
            }
            assert_eq!(calls.load(Ordering::Relaxed), 2);
        }
    }

    #[cfg(feature = "cookies")]
    #[tokio::test]
    async fn unsent_retries_regenerate_automatic_cookies() {
        for explicit in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let attempts = calls.clone();
            let service = tower::service_fn(move |mut request: PoolRequest<Vec<u8>>| {
                let headers = request.request.headers_mut();
                let values: Vec<_> = headers.get_all(COOKIE).iter().collect();
                if explicit {
                    assert_eq!(values, ["user=1", "other=2"]);
                } else {
                    assert!(values.is_empty(), "automatic cookies must be refreshed");
                }

                if attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                    if !explicit {
                        headers.append(COOKIE, http::HeaderValue::from_static("h2=1"));
                        headers.append(COOKIE, http::HeaderValue::from_static("other=2"));
                    }
                    future::ready(Err(DispatchError::Unsent {
                        error: Error::from_kind(ErrorKind::Canceled),
                        request: Box::new(request),
                        connection_reused: true,
                    }))
                } else {
                    future::ready(Ok(()))
                }
            });
            let mut request = Request::builder().uri("https://localhost/");
            if explicit {
                request = request.header(COOKIE, "user=1").header(COOKIE, "other=2");
            }
            ServiceBuilder::new()
                .layer(layer(
                    conn::http1::Builder::default(),
                    #[cfg(feature = "http2")]
                    conn::http2::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    #[cfg(feature = "http3")]
                    conn::http3::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    true,
                    Protocol::Auto,
                    ConfigSet::default(),
                    BindOptions::default(),
                ))
                .service(service)
                .oneshot(request.body(Vec::new()).unwrap())
                .await
                .unwrap();
            assert_eq!(calls.load(Ordering::Relaxed), 2);
        }
    }

    #[tokio::test]
    #[cfg(feature = "http2")]
    async fn protocol_selection_preserves_wire_versions_and_pool_groups() {
        let mut keys = Vec::new();
        let bind_options = Arc::new(BindOptions {
            ipv4_address: Some(std::net::Ipv4Addr::LOCALHOST),
            ..BindOptions::default()
        });
        for (wire, client, extended, expected) in [
            (
                Some(Version::HTTP_10),
                Protocol::Auto,
                false,
                Some(Protocol::Http1),
            ),
            (
                Some(Version::HTTP_11),
                Protocol::Auto,
                false,
                Some(Protocol::Http1),
            ),
            (
                #[cfg(feature = "http2")]
                Some(Version::HTTP_2),
                Protocol::Auto,
                false,
                Some(Protocol::Auto),
            ),
            (None, Protocol::Auto, false, None),
            (
                #[cfg(feature = "http2")]
                Some(Version::HTTP_2),
                Protocol::Http2,
                false,
                Some(Protocol::Http2),
            ),
            (
                #[cfg(feature = "http2")]
                Some(Version::HTTP_2),
                Protocol::Auto,
                true,
                Some(Protocol::Auto),
            ),
            (
                Some(Version::HTTP_11),
                Protocol::Http2,
                false,
                Some(Protocol::Http1),
            ),
            (
                #[cfg(feature = "http2")]
                Some(Version::HTTP_2),
                Protocol::Http1,
                false,
                Some(Protocol::Auto),
            ),
            #[cfg(feature = "http3")]
            (None, Protocol::Http3, false, None),
            #[cfg(feature = "http3")]
            (
                Some(Version::HTTP_3),
                Protocol::Auto,
                false,
                Some(Protocol::Http3),
            ),
            #[cfg(feature = "http3")]
            (
                Some(Version::HTTP_11),
                Protocol::Http3,
                false,
                Some(Protocol::Http1),
            ),
        ] {
            let mut request = Request::builder()
                .uri("https://localhost/upload?part=1")
                .version(wire.unwrap_or(Version::HTTP_11))
                .body(())
                .unwrap();
            *RequestConfig::<RequestVersion>::get_mut(request.extensions_mut()) = wire;
            request.extensions_mut().insert(bind_options.clone());
            request
                .extensions_mut()
                .get_or_insert_default::<ConfigSet>()
                .insert(crate::Group::new("seven"));
            #[cfg(any(feature = "http2", feature = "http3"))]
            if extended {
                *request.method_mut() = http::Method::CONNECT;
                request
                    .extensions_mut()
                    .insert(http2::ext::Protocol::from_static("websocket"));
            }
            let service = tower::service_fn(|request: PoolRequest<()>| {
                future::ready(Ok::<_, DispatchError<()>>(request))
            });
            let request = ServiceBuilder::new()
                .layer(layer(
                    conn::http1::Builder::default(),
                    #[cfg(feature = "http2")]
                    conn::http2::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    #[cfg(feature = "http3")]
                    conn::http3::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    true,
                    client,
                    ConfigSet::default(),
                    BindOptions::default(),
                ))
                .service(service)
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(request.connection.req.protocol(), expected);
            assert_eq!(
                request.connection.req.bind_options().as_deref(),
                Some(bind_options.as_ref())
            );
            assert!(
                request
                    .request
                    .extensions()
                    .get::<Arc<BindOptions>>()
                    .is_none()
            );
            assert_eq!(request.request.version(), wire.unwrap_or(Version::HTTP_11));
            assert!(RequestConfig::<RequestVersion>::get(request.request.extensions()).is_none());
            assert_eq!(
                request.connection.req.config_set().get::<crate::Group>(),
                Some(&crate::Group::new("seven"))
            );
            keys.push(request.connection.req.key());
        }
        assert_eq!(
            keys[0], keys[1],
            "HTTP/1.0 and HTTP/1.1 select one protocol pool"
        );
        assert_eq!(keys[1], keys[6], "explicit H1 overrides the client mode");
        assert_ne!(
            keys[1], keys[2],
            "fixed H1 and negotiated requests remain isolated"
        );
        assert_ne!(
            keys[2], keys[3],
            "explicit negotiation differs from client inheritance"
        );
        assert_ne!(
            keys[2], keys[4],
            "negotiated and fixed H2 must not share a pool entry"
        );
        assert_eq!(keys[2], keys[5], "Protocol does not override negotiation");
        assert_eq!(keys[2], keys[7], "request negotiation overrides fixed H1");
        #[cfg(feature = "http3")]
        assert_eq!(keys[1], keys[10], "explicit H1 overrides fixed H3");
    }

    #[tokio::test]
    #[cfg(feature = "http2")]
    async fn websocket_route_probes_default_group_and_restores_upgrade() {
        let request = |websocket: Option<bool>| {
            let mut request = Request::builder()
                .uri("https://localhost/chat")
                .body(())
                .unwrap();
            let extensions = request.extensions_mut();
            extensions
                .get_or_insert_default::<ConfigSet>()
                .insert(crate::Group::new("seven"));
            if let Some(extended_connect) = websocket {
                *RequestConfig::<RequestVersion>::get_mut(extensions) = Some(Version::HTTP_11);
                extensions.insert(DedicatedConnection { extended_connect });
            }
            request
        };
        for (client, extended_connect, probes) in [
            (Protocol::Auto, true, true),
            (Protocol::Http2, true, true),
            (Protocol::Auto, false, false),
            (Protocol::Http1, true, false),
            #[cfg(feature = "http3")]
            (Protocol::Http3, true, false),
        ] {
            let stack = ServiceBuilder::new()
                .layer(layer(
                    conn::http1::Builder::default(),
                    #[cfg(feature = "http2")]
                    conn::http2::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    #[cfg(feature = "http3")]
                    conn::http3::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    true,
                    client,
                    ConfigSet::default(),
                    BindOptions::default(),
                ))
                .service(tower::service_fn(|request: PoolRequest<()>| {
                    future::ready(Ok::<_, DispatchError<()>>(request))
                }));
            let websocket = stack
                .clone()
                .oneshot(request(Some(extended_connect)))
                .await
                .unwrap();
            let plain = stack.oneshot(request(None)).await.unwrap();
            assert!(websocket.connection.dedicated);
            assert_eq!(websocket.connection.req.protocol(), Some(Protocol::Http1));
            // The probe targets the group ordinary requests use; those never probe.
            assert!(plain.extended_connect.is_none());
            assert_eq!(
                websocket.extended_connect,
                probes.then(|| plain.connection.req.key())
            );
        }

        let mut request = Request::get("https://localhost/chat")
            .version(Version::HTTP_11)
            .header(http::header::SEC_WEBSOCKET_VERSION, "13")
            .header(UPGRADE, "websocket")
            .header(http::header::ORIGIN, "https://localhost")
            .header(CONNECTION, "upgrade")
            .header(SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .header(http::header::SEC_WEBSOCKET_PROTOCOL, "chat")
            .body(())
            .unwrap();
        let original = request.headers().clone();
        let upgrade = Http1Upgrade::into_extended_connect(&mut request);
        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(request.version(), Version::HTTP_2);
        assert!(request.extensions().get::<http2::ext::Protocol>().is_some());
        let names: Vec<_> = request.headers().keys().map(|name| name.as_str()).collect();
        assert_eq!(
            names,
            ["sec-websocket-version", "origin", "sec-websocket-protocol"]
        );

        upgrade.restore(&mut request);
        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.version(), Version::HTTP_11);
        assert!(request.extensions().get::<http2::ext::Protocol>().is_none());
        assert!(request.headers().iter().eq(original.iter()));
    }

    #[tokio::test]
    async fn unsent_retries_keep_request_state_and_error_sources() {
        for (enabled, reused, unsent, expected_calls) in [
            (true, true, false, 1),
            (true, true, true, 2),
            (false, true, true, 1),
            (true, false, true, 1),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let attempts = calls.clone();
            let mut connection = None;
            let service = tower::service_fn(move |mut request: PoolRequest<Vec<u8>>| {
                assert_eq!(request.request.uri(), "http://localhost/upload?part=1");
                assert_eq!(request.request.body(), b"payload");
                assert_eq!(request.connection.req.uri(), "http://localhost/");

                let result = if attempts.fetch_add(1, Ordering::Relaxed) == 0 && unsent {
                    connection = Some(request.connection.clone());
                    *request.request.uri_mut() = Uri::from_static("/upload?part=1");
                    Err(DispatchError::Unsent {
                        error: Error::new(ErrorKind::Canceled, std::io::Error::other("unsent")),
                        request: Box::new(request),
                        connection_reused: reused,
                    })
                } else {
                    if let Some(connection) = &connection {
                        assert_eq!(connection.req.key(), request.connection.req.key());
                        assert!(Arc::ptr_eq(&connection.proto, &request.connection.proto));
                    }
                    Ok(())
                };
                future::ready(result)
            });

            let result = ServiceBuilder::new()
                .layer(layer(
                    conn::http1::Builder::default(),
                    #[cfg(feature = "http2")]
                    conn::http2::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    #[cfg(feature = "http3")]
                    conn::http3::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    enabled,
                    Protocol::Auto,
                    ConfigSet::default(),
                    BindOptions::default(),
                ))
                .service(service)
                .oneshot(
                    Request::builder()
                        .uri("http://localhost/upload?part=1")
                        .body(b"payload".to_vec())
                        .unwrap(),
                );
            let mut task = tokio_test::task::spawn(result);
            let Poll::Ready(result) = task.poll() else {
                panic!("a successful or terminal result should finish without yielding");
            };
            assert!(!task.is_woken());

            assert_eq!(calls.load(Ordering::Relaxed), expected_calls);
            if !unsent || expected_calls == 2 {
                result.unwrap();
            } else {
                let error = result.unwrap_err();
                assert!(error.is::<Error>());
                assert_eq!(error.source().unwrap().to_string(), "unsent");
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let gate = Arc::new(tokio::sync::Notify::new());
        let ready = gate.clone();
        let service = tower::service_fn(move |request: PoolRequest<Vec<u8>>| {
            let first = attempts.fetch_add(1, Ordering::Relaxed) == 0;
            let ready = ready.clone();
            async move {
                if first {
                    Err(DispatchError::CheckoutCanceled {
                        error: Error::from_kind(ErrorKind::Canceled),
                        request: Box::new(request),
                    })
                } else {
                    ready.notified().await;
                    Ok(())
                }
            }
        });
        let mut task = tokio_test::task::spawn(
            ServiceBuilder::new()
                .layer(layer(
                    conn::http1::Builder::default(),
                    #[cfg(feature = "http2")]
                    conn::http2::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    #[cfg(feature = "http3")]
                    conn::http3::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    true,
                    Protocol::Auto,
                    ConfigSet::default(),
                    BindOptions::default(),
                ))
                .service(service)
                .oneshot(
                    Request::builder()
                        .uri("http://localhost/")
                        .body(Vec::new())
                        .unwrap(),
                ),
        );
        assert!(task.poll().is_pending());
        assert!(!task.is_woken(), "a pending retry owns its wakeup");
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        gate.notify_one();
        assert!(task.is_woken());
        assert!(matches!(task.poll(), Poll::Ready(Ok(()))));

        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let service = tower::service_fn(move |request: PoolRequest<Vec<u8>>| {
            attempts.fetch_add(1, Ordering::Relaxed);
            future::ready(Err::<(), _>(DispatchError::CheckoutCanceled {
                error: Error::from_kind(ErrorKind::Canceled),
                request: Box::new(request),
            }))
        });
        let mut task = tokio_test::task::spawn(
            ServiceBuilder::new()
                .layer(layer(
                    conn::http1::Builder::default(),
                    #[cfg(feature = "http2")]
                    conn::http2::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    #[cfg(feature = "http3")]
                    conn::http3::Builder::new(RuntimeHandle::new(crate::rt::tokio::TokioRuntime)),
                    true,
                    Protocol::Auto,
                    ConfigSet::default(),
                    BindOptions::default(),
                ))
                .service(service)
                .oneshot(
                    Request::builder()
                        .uri("http://localhost/")
                        .body(Vec::new())
                        .unwrap(),
                ),
        );
        for expected in [2, 4] {
            assert!(task.poll().is_pending());
            assert!(task.is_woken());
            assert_eq!(calls.load(Ordering::Relaxed), expected);
        }
    }
}
