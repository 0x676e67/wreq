//! Much of this codebase is adapted and refined from [hyper](https://github.com/hyperium/hyper-util),

mod pool;

use std::{
    error::Error as StdError,
    fmt,
    num::NonZeroUsize,
    task::{self, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_util::future::{self, BoxFuture, FutureExt, TryFutureExt};
use http::{
    HeaderValue, Method, Request, Response, Uri, Version,
    header::{HOST, PROXY_AUTHORIZATION},
    uri::{Authority, PathAndQuery, Scheme},
};
use http_body::Body;
use pool::Ver;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::BoxError;
use wreq_proto::{
    body::Incoming, conn, http1::Http1Options, http2::Http2Options, rt::Executor as _,
};
#[cfg(feature = "cookies")]
use {
    crate::cookie::{CookieStore, Cookies},
    http::header::COOKIE,
    std::sync::Arc,
};

use crate::{
    client::layer::config::RequestOptions,
    config::RequestConfig,
    conn::{Connected, Connection, descriptor::ConnectionDescriptor, proxy},
    error::ProxyConnect,
    pool::{PoolLimits, PoolStrategy},
    rt::{Executor, Timer},
};

/// A HttpClient to make outgoing HTTP requests.
///
/// `HttpClient` is cheap to clone and cloning is the recommended way to share a `HttpClient`. The
/// underlying connection pool will be reused.
#[must_use]
pub(crate) struct HttpClient<C, B>
where
    C: tower::Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    config: Config,
    exec: Executor,
    h1_builder: conn::http1::Builder,
    h2_builder: conn::http2::Builder<Executor>,
    pool: pool::Pool<C, B>,
    #[cfg(feature = "cookies")]
    cookie_store: RequestConfig<Arc<dyn CookieStore>>,
}

#[derive(Clone, Copy)]
struct Config {
    retry_canceled_requests: bool,
    set_host: bool,
    ver: Ver,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<BoxError>,
    #[allow(unused)]
    connect_info: Option<Connected>,
}

#[derive(Debug)]
enum ErrorKind {
    Canceled,
    ChannelClosed,
    Connect,
    ProxyConnect,
    UserUnsupportedRequestMethod,
    UserUnsupportedVersion,
    UserAbsoluteUriRequired,
    SendRequest,
}

#[allow(clippy::large_enum_variant)]
enum TrySendError<B> {
    Retryable {
        error: Error,
        req: Request<B>,
        connection_reused: bool,
    },
    Nope(Error),
}

macro_rules! e {
    ($kind:ident) => {
        Error {
            kind: ErrorKind::$kind,
            source: None,
            connect_info: None,
        }
    };
    ($kind:ident, $src:expr) => {
        Error {
            kind: ErrorKind::$kind,
            source: Some($src.into()),
            connect_info: None,
        }
    };
}

// ===== impl HttpClient =====

impl<C, B> HttpClient<C, B>
where
    C: tower::Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    fn request(
        &self,
        mut req: Request<B>,
    ) -> BoxFuture<'static, Result<Response<Incoming>, BoxError>> {
        let is_http_connect = req.method() == Method::CONNECT;
        // Validate HTTP version early
        match req.version() {
            Version::HTTP_10 if is_http_connect => {
                warn!("CONNECT is not allowed for HTTP/1.0");
                return Box::pin(future::err(e!(UserUnsupportedRequestMethod).into()));
            }
            Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2 => {}
            // completely unsupported HTTP version (like HTTP/0.9)!
            _unsupported => {
                warn!("Request has unsupported version: {:?}", _unsupported);
                return Box::pin(future::err(e!(UserUnsupportedVersion).into()));
            }
        };

        // Extract and normalize URI
        let uri = match normalize_uri(&mut req, is_http_connect) {
            Ok(uri) => uri,
            Err(err) => {
                return Box::pin(future::err(e!(UserAbsoluteUriRequired, err).into()));
            }
        };

        let mut this = self.clone();

        // Extract per-request options from the request extensions and apply them to the client.
        let descriptor = {
            let RequestOptions {
                group,
                proxy,
                version,
                tls_options,
                http1_options,
                http2_options,
                socket_bind_options,
            } = RequestConfig::<RequestOptions>::remove(req.extensions_mut()).unwrap_or_default();

            if let Some(opts) = http1_options {
                this.h1_builder = this.h1_builder.options(opts);
            }
            if let Some(opts) = http2_options {
                this.h2_builder = this.h2_builder.options(opts);
            }

            ConnectionDescriptor::new(uri, group, proxy, version, tls_options, socket_bind_options)
        };

        Box::pin(this.send_request(req, descriptor).map_err(Into::into))
    }

    async fn send_request(
        self,
        mut req: Request<B>,
        descriptor: ConnectionDescriptor,
    ) -> Result<Response<Incoming>, Error> {
        let uri = req.uri().clone();

        loop {
            req = match self.try_send_request(req, descriptor.clone()).await {
                Ok(resp) => return Ok(resp),
                Err(TrySendError::Nope(err)) => return Err(err),
                Err(TrySendError::Retryable {
                    mut req,
                    error,
                    connection_reused,
                }) => {
                    if !self.config.retry_canceled_requests || !connection_reused {
                        // if client disabled, don't retry
                        // a fresh connection means we definitely can't retry
                        return Err(error);
                    }

                    trace!(
                        "unstarted request canceled, trying again (reason={:?})",
                        error
                    );
                    *req.uri_mut() = uri.clone();
                    req
                }
            }
        }
    }

    #[allow(clippy::result_large_err)]
    async fn try_send_request(
        &self,
        mut req: Request<B>,
        descriptor: ConnectionDescriptor,
    ) -> Result<Response<Incoming>, TrySendError<B>> {
        let mut pooled = self
            .connection_for(descriptor)
            .await
            // `connection_for` already retries checkout errors, so if
            // it returns an error, there's not much else to retry
            .map_err(TrySendError::Nope)?;

        let uri = req.uri().clone();

        if pooled.is_http1() {
            if req.version() == Version::HTTP_2 {
                warn!("Connection is HTTP/1, but request requires HTTP/2");
                return Err(TrySendError::Nope(
                    e!(UserUnsupportedVersion).with_connect_info(pooled.conn_info().clone()),
                ));
            }

            if self.config.set_host {
                req.headers_mut()
                    .entry(HOST)
                    .or_insert_with(|| generate_host_header(&uri));
            }

            // CONNECT always sends authority-form, so check it first...
            if req.method() == Method::CONNECT {
                authority_form(req.uri_mut());
            } else if pooled.conn_info().is_proxied() {
                if let Some(auth) = pooled.conn_info().proxy_auth() {
                    req.headers_mut()
                        .entry(PROXY_AUTHORIZATION)
                        .or_insert_with(|| auth.clone());
                }

                if let Some(headers) = pooled.conn_info().proxy_headers() {
                    crate::util::replace_headers(req.headers_mut(), headers.clone());
                }

                absolute_form(req.uri_mut());
            } else {
                origin_form(req.uri_mut());
            }
        } else if req.method() == Method::CONNECT && !pooled.is_http2() {
            authority_form(req.uri_mut());
        }

        #[cfg(feature = "cookies")]
        let cookie_store = self.cookie_store.fetch(req.extensions()).cloned();

        #[cfg(feature = "cookies")]
        if let Some(ref cookie_store) = cookie_store {
            let headers = req.headers_mut();

            if !headers.contains_key(COOKIE) {
                let version = if pooled.is_http2() {
                    Version::HTTP_2
                } else {
                    Version::HTTP_11
                };

                match cookie_store.cookies(&uri, version) {
                    Cookies::Compressed(value) => {
                        headers.insert(COOKIE, value);
                    }
                    Cookies::Uncompressed(values) => {
                        for value in values {
                            headers.append(COOKIE, value);
                        }
                    }
                    Cookies::Empty => (),
                }
            }
        }

        let mut res = match pooled.try_send_request(req).await {
            Ok(res) => res,
            Err(mut err) => {
                let connection_reused = pooled.is_reused();
                let connect_info = pooled.conn_info().clone();
                pooled.discard();
                return if let Some(req) = err.take_message() {
                    Err(TrySendError::Retryable {
                        connection_reused,
                        error: Error::new(ErrorKind::Canceled, err.into_error())
                            .with_connect_info(connect_info),
                        req,
                    })
                } else {
                    Err(TrySendError::Nope(
                        Error::new(ErrorKind::SendRequest, err.into_error())
                            .with_connect_info(connect_info),
                    ))
                };
            }
        };

        #[cfg(feature = "cookies")]
        if let Some(cookie_store) = cookie_store {
            let mut cookies = res
                .headers()
                .get_all(http::header::SET_COOKIE)
                .iter()
                .peekable();
            if cookies.peek().is_some() {
                cookie_store.set_cookies(&mut cookies, &uri);
            }
        }

        // If the Connector included 'extra' info, add to Response...
        pooled.conn_info().set_extras(res.extensions_mut());

        // If the Connector included connection info, add to Response...
        res.extensions_mut().insert(pooled.conn_info().clone());

        // If pooled is HTTP/2, we can toss this reference immediately.
        //
        // when pooled is dropped, it will try to insert back into the
        // pool. To delay that, spawn a future that completes once the
        // sender is ready again.
        //
        // This *should* only be once the related `Connection` has polled
        // for a new request to start.
        //
        // It won't be ready if there is a body to stream.
        if pooled.is_http2()
            || (!pooled.is_pool_enabled() && !pooled.has_connection_limit())
            || pooled.is_ready()
        {
            drop(pooled);
        } else {
            let on_idle = std::future::poll_fn(move |cx| pooled.poll_ready(cx)).map(|_| ());
            self.exec.execute(on_idle);
        }

        Ok(res)
    }

    async fn connection_for(
        &self,
        descriptor: ConnectionDescriptor,
    ) -> Result<pool::Pooled<B>, Error> {
        let ver = match descriptor.version() {
            Some(Version::HTTP_10 | Version::HTTP_11) => Ver::Http1,
            Some(Version::HTTP_2) => Ver::Http2,
            _ => self.config.ver,
        };

        self.pool
            .checkout(
                descriptor,
                ver,
                self.h1_builder.clone(),
                self.h2_builder.clone(),
            )
            .await
            .map_err(|error| Error::new(ErrorKind::Connect, error))
    }
}

impl<C, B> tower::Service<Request<B>> for HttpClient<C, B>
where
    C: tower::Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Incoming>;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Response<Incoming>, Self::Error>>;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        self.request(req)
    }
}

impl<C, B> Clone for HttpClient<C, B>
where
    C: tower::Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    fn clone(&self) -> HttpClient<C, B> {
        HttpClient {
            config: self.config,
            exec: self.exec.clone(),
            h1_builder: self.h1_builder.clone(),
            h2_builder: self.h2_builder.clone(),
            pool: self.pool.clone(),
            #[cfg(feature = "cookies")]
            cookie_store: self.cookie_store.clone(),
        }
    }
}

/// A builder to configure a new [`HttpClient`].
#[derive(Clone)]
pub struct Builder {
    config: Config,
    exec: Executor,
    h1_builder: conn::http1::Builder,
    h2_builder: conn::http2::Builder<Executor>,
    pool_config: pool::Config,
    pool_timer: Timer,
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn CookieStore>>,
}

// ===== impl Builder =====

impl Builder {
    /// Construct a new Builder.
    pub fn new(exec: Executor) -> Self {
        Self {
            config: Config {
                retry_canceled_requests: true,
                set_host: true,
                ver: Ver::Auto,
            },
            exec: exec.clone(),
            h1_builder: conn::http1::Builder::default(),
            h2_builder: conn::http2::Builder::new(exec),
            pool_config: pool::Config {
                idle_timeout: Some(Duration::from_secs(90)),
                max_idle_per_host: usize::MAX,
                max_pool_size: None,
                ..pool::Config::default()
            },
            pool_timer: Timer::default(),
            #[cfg(feature = "cookies")]
            cookie_store: None,
        }
    }

    /// Set an optional timeout for idle sockets being kept-alive.
    /// A `Timer` is required for this to take effect. See `Builder::pool_timer`
    ///
    /// Pass `None` to disable timeout.
    ///
    /// Default is 90 seconds.
    #[inline]
    pub fn pool_idle_timeout<D>(mut self, val: D) -> Self
    where
        D: Into<Option<Duration>>,
    {
        self.pool_config.idle_timeout = val.into();
        self
    }

    /// Sets the maximum idle connection per host allowed in the pool.
    ///
    /// Default is `usize::MAX` (no limit).
    #[inline]
    pub fn pool_max_idle_per_host(mut self, max_idle: usize) -> Self {
        self.pool_config.max_idle_per_host = max_idle;
        self
    }

    /// Sets the maximum number of connections in the pool.
    ///
    /// Default is `None` (no limit).
    #[inline]
    pub fn pool_max_size(mut self, max_size: impl Into<Option<NonZeroUsize>>) -> Self {
        self.pool_config.max_pool_size = max_size.into();
        self
    }

    /// Sets the connection acquisition strategy.
    #[inline]
    pub fn pool_strategy(mut self, strategy: PoolStrategy) -> Self {
        self.pool_config.strategy = strategy;
        self
    }

    /// Sets connection limits for the pool.
    #[inline]
    pub fn pool_limits(mut self, limits: PoolLimits) -> Self {
        self.pool_config.limits = limits;
        self
    }

    /// Set whether the connection **must** use HTTP/1.
    #[inline]
    pub fn http1_only(mut self, val: bool) -> Self {
        if val {
            self.config.ver = Ver::Http1;
        } else if self.config.ver == Ver::Http1 {
            self.config.ver = Ver::Auto;
        }
        self
    }

    /// Set whether the connection **must** use HTTP/2.
    ///
    /// The destination must either allow HTTP2 Prior Knowledge, or the
    /// `Connect` should be configured to do use ALPN to upgrade to `h2`
    /// as part of the connection process. This will not make the `HttpClient`
    /// utilize ALPN by itself.
    ///
    /// Note that setting this to true prevents HTTP/1 from being allowed.
    ///
    /// Default is false.
    #[inline]
    pub fn http2_only(mut self, val: bool) -> Self {
        if val {
            self.config.ver = Ver::Http2;
        } else if self.config.ver == Ver::Http2 {
            self.config.ver = Ver::Auto;
        }
        self
    }

    /// Provide a timer to be used for http2
    ///
    /// See the documentation of [`http2::client::Builder::timer`] for more
    /// details.
    ///
    /// [`http2::client::Builder::timer`]: https://docs.rs/http2/latest/http2/client/struct.Builder.html#method.timer
    #[inline]
    pub fn http2_timer(mut self, timer: Timer) -> Self {
        self.h2_builder = self.h2_builder.timer(timer);
        self
    }

    /// Provide a configuration for HTTP/1.
    #[inline]
    pub fn http1_options<O>(mut self, opts: O) -> Self
    where
        O: Into<Option<Http1Options>>,
    {
        if let Some(opts) = opts.into() {
            self.h1_builder = self.h1_builder.options(opts);
        }

        self
    }

    /// Provide a configuration for HTTP/2.
    #[inline]
    pub fn http2_options<O>(mut self, opts: O) -> Self
    where
        O: Into<Option<Http2Options>>,
    {
        if let Some(opts) = opts.into() {
            self.h2_builder = self.h2_builder.options(opts);
        }
        self
    }

    /// Provide a timer to be used for timeouts and intervals in connection pools.
    #[inline]
    pub fn pool_timer(mut self, timer: Timer) -> Self {
        self.pool_timer = timer;
        self
    }

    /// Provide a cookie store for automatic cookie management.
    #[inline]
    #[cfg(feature = "cookies")]
    pub fn cookie_store(mut self, cookie_store: Option<Arc<dyn CookieStore>>) -> Self {
        self.cookie_store = cookie_store;
        self
    }

    /// Combine the configuration of this builder with a connector to create a `HttpClient`.
    pub fn build<C, B>(self, connector: C) -> HttpClient<C, B>
    where
        C: tower::Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
        C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
        C::Error: Into<BoxError>,
        C::Future: Unpin + Send + 'static,
        B: Body + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
    {
        let exec = self.exec.clone();
        let timer = self.pool_timer.clone();
        HttpClient {
            config: self.config,
            exec: exec.clone(),
            h1_builder: self.h1_builder,
            h2_builder: self.h2_builder,
            pool: pool::Pool::new(self.pool_config, connector, exec, timer),
            #[cfg(feature = "cookies")]
            cookie_store: RequestConfig::new(self.cookie_store),
        }
    }
}

// ==== impl Error ====

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "client error ({:?})", self.kind)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|e| &**e as _)
    }
}

impl Error {
    fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: Into<BoxError>,
    {
        let error = error.into();
        let kind = if error.is::<proxy::tunnel::TunnelError>() || error.is::<ProxyConnect>() || {
            #[cfg(feature = "socks")]
            {
                error.is::<proxy::socks::SocksError>()
            }
            #[cfg(not(feature = "socks"))]
            {
                false
            }
        } {
            ErrorKind::ProxyConnect
        } else {
            kind
        };

        Self {
            kind,
            source: Some(error),
            connect_info: None,
        }
    }

    /// Returns true if this was an error from [`ErrorKind::Connect`].
    #[inline]
    pub fn is_connect(&self) -> bool {
        matches!(self.kind, ErrorKind::Connect)
    }

    /// Returns true if this was an error from [`ErrorKind::ProxyConnect`].
    #[inline]
    pub fn is_proxy_connect(&self) -> bool {
        matches!(self.kind, ErrorKind::ProxyConnect)
    }

    #[inline]
    fn with_connect_info(self, connect_info: Connected) -> Self {
        Self {
            connect_info: Some(connect_info),
            ..self
        }
    }

    #[inline]
    fn closed(src: wreq_proto::Error) -> Self {
        Self::new(ErrorKind::ChannelClosed, src)
    }
}

fn origin_form(uri: &mut Uri) {
    let path = match uri.path_and_query() {
        Some(path) if path.as_str() != "/" => {
            let mut parts = ::http::uri::Parts::default();
            parts.path_and_query.replace(path.clone());
            Uri::from_parts(parts).expect("path is valid uri")
        }
        _none_or_just_slash => {
            debug_assert!(Uri::default() == "/");
            Uri::default()
        }
    };
    *uri = path
}

fn absolute_form(uri: &mut Uri) {
    debug_assert!(uri.scheme().is_some(), "absolute_form needs a scheme");
    debug_assert!(
        uri.authority().is_some(),
        "absolute_form needs an authority"
    );
}

fn authority_form(uri: &mut Uri) {
    if let Some(path) = uri.path_and_query() {
        // `https://hyper.rs` would parse with `/` path, don't
        // annoy people about that...
        if path != "/" {
            warn!("HTTP/1.1 CONNECT request stripping path: {:?}", path);
        }
    }
    *uri = match uri.authority() {
        Some(auth) => {
            let mut parts = ::http::uri::Parts::default();
            parts.authority = Some(auth.clone());
            Uri::from_parts(parts).expect("authority is valid")
        }
        None => {
            unreachable!("authority_form with relative uri");
        }
    };
}

fn normalize_uri<B>(req: &mut Request<B>, is_http_connect: bool) -> Result<Uri, Error> {
    let uri = req.uri().clone();

    let build_base_uri = |scheme: Scheme, authority: Authority| {
        Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query(PathAndQuery::from_static("/"))
            .build()
            .expect("valid base URI")
    };

    match (uri.scheme(), uri.authority()) {
        (Some(scheme), Some(auth)) => Ok(build_base_uri(scheme.clone(), auth.clone())),
        (None, Some(auth)) if is_http_connect => {
            let scheme = match auth.port_u16() {
                Some(443) => Scheme::HTTPS,
                _ => Scheme::HTTP,
            };
            set_scheme(req.uri_mut(), scheme.clone());
            Ok(build_base_uri(scheme, auth.clone()))
        }
        _ => {
            debug!("Client requires absolute-form URIs, received: {:?}", uri);
            Err(e!(UserAbsoluteUriRequired))
        }
    }
}

fn generate_host_header(uri: &Uri) -> HeaderValue {
    let hostname = uri.host().expect("authority implies host");
    let port = match (uri.port().map(|p| p.as_u16()), is_schema_secure(uri)) {
        (Some(443), true) | (Some(80), false) => None,
        _ => uri.port(),
    };
    if let Some(port) = port {
        let host = format!("{hostname}:{port}");
        HeaderValue::from_maybe_shared(Bytes::from(host))
    } else {
        HeaderValue::from_str(hostname)
    }
    .expect("uri host is valid header value")
}

fn set_scheme(uri: &mut Uri, scheme: Scheme) {
    debug_assert!(
        uri.scheme().is_none(),
        "set_scheme expects no existing scheme"
    );
    let old = std::mem::take(uri);
    let mut parts: ::http::uri::Parts = old.into();
    parts.scheme = Some(scheme);
    parts.path_and_query = Some(PathAndQuery::from_static("/"));
    *uri = Uri::from_parts(parts).expect("scheme is valid");
}

fn is_schema_secure(uri: &Uri) -> bool {
    uri.scheme_str()
        .map(|scheme_str| matches!(scheme_str, "wss" | "https"))
        .unwrap_or_default()
}
