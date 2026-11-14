mod proto;
mod svc;

pub(super) mod body;
pub(super) mod emulate;
pub(super) mod error;
pub(super) mod future;
pub(super) mod layer;
pub(super) mod pool;
pub(super) mod request;
pub(super) mod response;
pub(super) mod upgrade;

#[cfg(feature = "multipart")]
pub mod multipart;
#[cfg(feature = "ws")]
pub mod ws;

use std::{
    borrow::Cow,
    collections::HashMap,
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::{
    Request as HttpRequest,
    header::{HeaderMap, HeaderValue, USER_AGENT},
};
use netty::body::Incoming;
use tower::{
    BoxError, Layer, Service, ServiceBuilder, ServiceExt,
    retry::{Retry, RetryLayer},
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, Either, Oneshot},
};

#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
))]
use self::layer::decoder::{AcceptEncoding, DecompressionLayer};
#[cfg(feature = "ws")]
use self::ws::WebSocketRequestBuilder;
use self::{
    body::Body,
    emulate::IntoEmulation,
    future::Pending,
    layer::{
        config::{ConfigService, ConfigServiceLayer},
        redirect::{FollowRedirect, FollowRedirectLayer},
        retry::RetryPolicy,
        timeout::{Timeout, TimeoutLayer, TimeoutOptions, body::TimeoutBody},
    },
    pool::PoolStrategy,
    request::{Request, RequestBuilder},
    response::Response,
};
#[cfg(feature = "cookies")]
use crate::cookie;
#[cfg(feature = "http2")]
use crate::http2::Http2Options;
use crate::{
    IntoUri, Method, Proxy,
    config::connect::ConfigSet,
    conn::{self, BoxedTransportConnector, Conn, Connector, Unnameable, dialer},
    dns::{DynResolver, IntoResolve, OverrideResolver, Resolve},
    error::Error,
    header::OrigHeaderMap,
    http1::Http1Options,
    protocol::Protocol,
    proxy::Matcher as ProxyMatcher,
    redirect::{self, FollowRedirectPolicy},
    retry,
    rt::{DynRuntime, IntoRuntime},
    tls::{
        TlsOptions, TlsVersion,
        keylog::KeyLog,
        session::{IntoTlsSessionStore, Tickets},
        trust::{CertStore, Identity},
    },
};

cfg_select! {
    any(
        feature = "gzip",
        feature = "zstd",
        feature = "brotli",
        feature = "deflate"
    ) => {
        type MaybeDecompression<T> = self::layer::decoder::Decompression<T>;
        type MaybeDecompressionBody<T> = tower_http::decompression::DecompressionBody<T>;
    }
    _ => {
        type MaybeDecompression<T> = T;
        type MaybeDecompressionBody<T> = T;
    }
}

type ClientService = Timeout<
    ConfigService<
        MaybeDecompression<FollowRedirect<Retry<RetryPolicy, sealed::Client<Connector>>>>,
    >,
>;

type BoxedClientService = BoxCloneSyncService<
    http::Request<Body>,
    http::Response<TimeoutBody<MaybeDecompressionBody<Incoming>>>,
    BoxError,
>;

type BoxedClientServiceLayer = BoxCloneSyncServiceLayer<
    BoxCloneSyncService<
        http::Request<Body>,
        http::Response<MaybeDecompressionBody<Incoming>>,
        BoxError,
    >,
    http::Request<Body>,
    http::Response<MaybeDecompressionBody<Incoming>>,
    BoxError,
>;

/// An [`Client`] to make Requests with.
///
/// The Client has various configuration values to tweak, but the defaults
/// are set to what is usually the most commonly desired value. To configure a
/// [`Client`], use [`Client::builder`] with your chosen runtime.
///
/// The [`Client`] holds a connection pool internally, so it is advised that
/// you create one and **reuse** it.
///
/// You do **not** have to wrap the [`Client`] in an [`Rc`] or [`Arc`] to **reuse** it,
/// because it already uses an [`Arc`] internally.
///
/// [`Rc`]: std::rc::Rc
#[derive(Clone)]
pub struct Client(Arc<Either<ClientService, BoxedClientService>>);

/// A [`ClientBuilder`] can be used to create a [`Client`] with custom configuration.
#[must_use]
pub struct ClientBuilder {
    config: Config,
    runtime: DynRuntime,
}

/// Configuration collected before the client service stack is built.
/// Holds transport settings, protocol selection, and request defaults.
/// Building consumes it into the shared services and their middleware.
struct Config {
    error: Option<Error>,
    headers: HeaderMap,
    orig_headers: OrigHeaderMap,
    #[cfg(any(
        feature = "gzip",
        feature = "zstd",
        feature = "brotli",
        feature = "deflate",
    ))]
    accept_encoding: AcceptEncoding,
    connect: conn::Config,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: usize,
    pool_max_size: Option<NonZeroUsize>,
    pool_strategy: PoolStrategy,
    auto_sys_proxy: bool,
    retry_policy: retry::Policy,
    redirect_policy: redirect::Policy,
    referer: bool,
    timeout_options: TimeoutOptions,
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn cookie::CookieStore>>,
    dns_overrides: HashMap<Cow<'static, str>, Vec<SocketAddr>>,
    dns_resolver: Option<Arc<dyn Resolve>>,
    protocol: Protocol,
    https_only: bool,
    layers: Vec<BoxedClientServiceLayer>,
    config_set: ConfigSet,
}

// ===== impl Client =====

impl Client {
    /// Constructs a new [`Client`] using the selected runtime.
    ///
    /// # Panics
    ///
    /// This method panics if a TLS backend cannot be initialized.
    ///
    /// Use [`Client::builder`] if you wish to handle the failure as a [`crate::Error`]
    /// instead of panicking.
    #[inline]
    pub fn new<R>(runtime: R) -> Client
    where
        R: IntoRuntime,
    {
        Client::builder(runtime).build().expect("Client::new")
    }

    /// Creates a client builder with the selected runtime.
    /// Accepts a runtime value or an existing `Arc`; its DNS resolver is used
    /// unless explicitly overridden.
    pub fn builder<R>(runtime: R) -> ClientBuilder
    where
        R: IntoRuntime,
    {
        ClientBuilder {
            config: Config {
                error: None,
                headers: HeaderMap::new(),
                orig_headers: OrigHeaderMap::new(),
                #[cfg(any(
                    feature = "gzip",
                    feature = "zstd",
                    feature = "brotli",
                    feature = "deflate",
                ))]
                accept_encoding: AcceptEncoding::default(),
                connect: conn::Config::default(),
                pool_idle_timeout: Some(Duration::from_secs(90)),
                pool_max_idle_per_host: usize::MAX,
                pool_max_size: None,
                pool_strategy: PoolStrategy::default(),
                auto_sys_proxy: true,
                retry_policy: retry::Policy::default(),
                redirect_policy: redirect::Policy::none(),
                referer: true,
                timeout_options: TimeoutOptions::default(),
                #[cfg(feature = "cookies")]
                cookie_store: None,
                dns_overrides: HashMap::new(),
                dns_resolver: None,
                protocol: Protocol::Auto,
                https_only: false,
                layers: Vec::new(),
                config_set: ConfigSet::default(),
            },
            runtime: DynRuntime::new(runtime),
        }
    }

    /// Creates a client builder using Tokio for tasks, timers and DNS.
    #[cfg(feature = "tokio-rt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tokio-rt")))]
    pub fn builder_tokio() -> ClientBuilder {
        Self::builder(crate::rt::tokio::TokioRuntime)
    }

    /// Creates a client builder using Compio for tasks, timers and DNS.
    ///
    /// Use the client and its clones from a single Compio runtime thread; calling them from
    /// another thread panics. See [`CompioRuntime`](crate::rt::compio::CompioRuntime).
    #[cfg(feature = "compio-rt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "compio-rt")))]
    pub fn builder_compio() -> ClientBuilder {
        Self::builder(crate::rt::compio::CompioRuntime)
    }

    /// Convenience method to make a `GET` request to a URI.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Uri` cannot be parsed.
    #[inline]
    pub fn get<U: IntoUri>(&self, uri: U) -> RequestBuilder {
        self.request(Method::GET, uri)
    }

    /// Convenience method to make a `POST` request to a URI.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Uri` cannot be parsed.
    #[inline]
    pub fn post<U: IntoUri>(&self, uri: U) -> RequestBuilder {
        self.request(Method::POST, uri)
    }

    /// Convenience method to make a `PUT` request to a URI.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Uri` cannot be parsed.
    #[inline]
    pub fn put<U: IntoUri>(&self, uri: U) -> RequestBuilder {
        self.request(Method::PUT, uri)
    }

    /// Convenience method to make a `PATCH` request to a URI.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Uri` cannot be parsed.
    #[inline]
    pub fn patch<U: IntoUri>(&self, uri: U) -> RequestBuilder {
        self.request(Method::PATCH, uri)
    }

    /// Convenience method to make a `DELETE` request to a URI.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Uri` cannot be parsed.
    #[inline]
    pub fn delete<U: IntoUri>(&self, uri: U) -> RequestBuilder {
        self.request(Method::DELETE, uri)
    }

    /// Convenience method to make a `HEAD` request to a URI.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Uri` cannot be parsed.
    #[inline]
    pub fn head<U: IntoUri>(&self, uri: U) -> RequestBuilder {
        self.request(Method::HEAD, uri)
    }

    /// Convenience method to make a `OPTIONS` request to a URI.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Uri` cannot be parsed.
    #[inline]
    pub fn options<U: IntoUri>(&self, uri: U) -> RequestBuilder {
        self.request(Method::OPTIONS, uri)
    }

    /// Start building a `Request` with the `Method` and `Uri`.
    ///
    /// Returns a `RequestBuilder`, which will allow setting headers and
    /// the request body before sending.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Uri` cannot be parsed.
    pub fn request<U: IntoUri>(&self, method: Method, uri: U) -> RequestBuilder {
        let req = uri.into_uri().map(move |uri| Request::new(method, uri));
        RequestBuilder::new(self.clone(), req)
    }

    /// Upgrades the [`RequestBuilder`] to perform a
    /// websocket handshake. This returns a wrapped type, so you must do
    /// this after you set up your request, and just before you send the
    /// request.
    #[inline]
    #[cfg(feature = "ws")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ws")))]
    pub fn websocket<U: IntoUri>(&self, uri: U) -> WebSocketRequestBuilder {
        WebSocketRequestBuilder::new(self.request(Method::GET, uri))
    }

    /// Executes a `Request`.
    ///
    /// A `Request` can be built manually with `Request::new()` or obtained
    /// from a RequestBuilder with `RequestBuilder::build()`.
    ///
    /// You should prefer to use the `RequestBuilder` and
    /// `RequestBuilder::send()`.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending request,
    /// redirect loop was detected or redirect limit was exhausted.
    pub fn execute(&self, request: Request) -> Pending {
        let req: HttpRequest<Body> = request.into();
        Pending::Request {
            uri: Some(req.uri().clone()),
            fut: Box::pin(Oneshot::new(self.0.as_ref().clone(), req)),
        }
    }
}

impl tower::Service<Request> for Client {
    type Response = Response;
    type Error = Error;
    type Future = Pending;

    #[inline(always)]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline(always)]
    fn call(&mut self, req: Request) -> Self::Future {
        self.execute(req)
    }
}

impl tower::Service<Request> for &'_ Client {
    type Response = Response;
    type Error = Error;
    type Future = Pending;

    #[inline(always)]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline(always)]
    fn call(&mut self, req: Request) -> Self::Future {
        self.execute(req)
    }
}

// ===== impl ClientBuilder =====

impl ClientBuilder {
    /// Returns a [`Client`] that uses this [`ClientBuilder`] configuration.
    ///
    /// # Errors
    ///
    /// This method fails if a TLS backend cannot be initialized.
    pub fn build(mut self) -> crate::Result<Client> {
        if let Some(err) = self.config.error {
            return Err(err);
        }

        // Prepare proxies
        if self.config.auto_sys_proxy {
            self.config.connect.proxies.push(ProxyMatcher::system());
        }

        // Create base client service
        let service = {
            let resolver = {
                let mut resolver: Arc<dyn Resolve> = match self.config.dns_resolver {
                    Some(dns_resolver) => dns_resolver,
                    None => self.runtime.resolver(),
                };

                if !self.config.dns_overrides.is_empty() {
                    resolver = Arc::new(OverrideResolver::new(resolver, self.config.dns_overrides));
                }
                DynResolver::new(resolver)
            };

            // The request stack inherits the client's bindings.
            let connector = Connector::new(
                self.config.connect,
                self.runtime.clone(),
                resolver,
                &self.config.config_set,
            )?;

            sealed::Builder::new(self.runtime.clone())
                .cookie_store(
                    #[cfg(feature = "cookies")]
                    self.config.cookie_store,
                )
                .config_set(self.config.config_set)
                .protocol(self.config.protocol)
                .pool_idle_timeout(self.config.pool_idle_timeout)
                .pool_max_idle_per_host(self.config.pool_max_idle_per_host)
                .pool_max_size(self.config.pool_max_size)
                .pool_strategy(self.config.pool_strategy)
                .build(connector)
        };

        // Configured client service with layers
        let client = {
            let service = ServiceBuilder::new()
                .layer({
                    let policy = FollowRedirectPolicy::new(self.config.redirect_policy)
                        .with_referer(self.config.referer)
                        .with_https_only(self.config.https_only);
                    FollowRedirectLayer::with_policy(policy)
                })
                .layer(RetryLayer::new(RetryPolicy::new(self.config.retry_policy)))
                .service(service);

            #[cfg(any(
                feature = "gzip",
                feature = "zstd",
                feature = "brotli",
                feature = "deflate",
            ))]
            let service = ServiceBuilder::new()
                .layer(DecompressionLayer::new(self.config.accept_encoding))
                .service(service);

            let service = ServiceBuilder::new()
                .layer(ConfigServiceLayer::new(
                    self.config.https_only,
                    self.config.headers,
                    self.config.orig_headers,
                ))
                .service(service);

            if self.config.layers.is_empty() {
                let service = ServiceBuilder::new()
                    .layer(TimeoutLayer::new(self.runtime, self.config.timeout_options))
                    .service(service);

                Either::Left(service)
            } else {
                let service = self
                    .config
                    .layers
                    .into_iter()
                    .fold(BoxCloneSyncService::new(service), |service, layer| {
                        ServiceBuilder::new().layer(layer).service(service)
                    });

                let service = ServiceBuilder::new()
                    .layer(TimeoutLayer::new(self.runtime, self.config.timeout_options))
                    .service(service)
                    .map_err(crate::error::map_timeout_to_request_error);

                Either::Right(BoxCloneSyncService::new(service))
            }
        };

        Ok(Client(Arc::new(client)))
    }

    // Higher-level options

    /// Sets the `User-Agent` header to be used by this client.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "tokio-rt")] {
    /// use wreq::Client;
    ///
    /// # async fn doc() -> wreq::Result<()> {
    /// // Name your user agent after your app?
    /// static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);
    ///
    /// let client = Client::builder_tokio().user_agent(APP_USER_AGENT).build()?;
    /// let res = client.get("https://www.rust-lang.org").send().await?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn user_agent<V>(mut self, value: V) -> ClientBuilder
    where
        V: TryInto<HeaderValue>,
        V::Error: Into<http::Error>,
    {
        match value.try_into() {
            Ok(value) => {
                self.config.headers.insert(USER_AGENT, value);
            }
            Err(err) => {
                self.config.error = Some(Error::builder(err.into()));
            }
        };
        self
    }

    /// Sets the default headers for every request.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "tokio-rt")] {
    /// use wreq::{Client, header};
    ///
    /// # async fn doc() -> wreq::Result<()> {
    /// let mut headers = header::HeaderMap::new();
    /// headers.insert("X-MY-HEADER", header::HeaderValue::from_static("value"));
    ///
    /// // Consider marking security-sensitive headers with `set_sensitive`.
    /// let mut auth_value = header::HeaderValue::from_static("secret");
    /// auth_value.set_sensitive(true);
    /// headers.insert(header::AUTHORIZATION, auth_value);
    ///
    /// // get a client builder
    /// let client = Client::builder_tokio().default_headers(headers).build()?;
    /// let res = client.get("https://www.rust-lang.org").send().await?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    ///
    /// Override the default headers:
    ///
    /// ```rust
    /// # #[cfg(feature = "tokio-rt")] {
    /// use wreq::{Client, header};
    ///
    /// # async fn doc() -> wreq::Result<()> {
    /// let mut headers = header::HeaderMap::new();
    /// headers.insert("X-MY-HEADER", header::HeaderValue::from_static("value"));
    ///
    /// // get a client builder
    /// let client = Client::builder_tokio().default_headers(headers).build()?;
    /// let res = client
    ///     .get("https://www.rust-lang.org")
    ///     .header("X-MY-HEADER", "new_value")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[inline]
    pub fn default_headers(mut self, headers: HeaderMap) -> ClientBuilder {
        crate::util::replace_headers(&mut self.config.headers, headers);
        self
    }

    /// Sets the original headers for every request.
    #[inline]
    pub fn orig_headers(mut self, orig_headers: OrigHeaderMap) -> ClientBuilder {
        self.config.orig_headers.extend(orig_headers);
        self
    }

    /// Enable a persistent cookie store for the client.
    ///
    /// Cookies received in responses will be preserved and included in
    /// additional requests.
    ///
    /// By default, no cookie store is used.
    ///
    /// # Optional
    ///
    /// This requires the optional `cookies` feature to be enabled.
    #[inline]
    #[cfg(feature = "cookies")]
    #[cfg_attr(docsrs, doc(cfg(feature = "cookies")))]
    pub fn cookie_store(mut self, enable: bool) -> ClientBuilder {
        if enable {
            self.cookie_provider(Arc::new(cookie::Jar::default()))
        } else {
            self.config.cookie_store = None;
            self
        }
    }

    /// Set the persistent cookie store for the client.
    ///
    /// Cookies received in responses will be passed to this store, and
    /// additional requests will query this store for cookies.
    ///
    /// By default, no cookie store is used.
    ///
    /// # Optional
    ///
    /// This requires the optional `cookies` feature to be enabled.
    #[inline]
    #[cfg(feature = "cookies")]
    #[cfg_attr(docsrs, doc(cfg(feature = "cookies")))]
    pub fn cookie_provider<C: cookie::IntoCookieStore>(mut self, cookie_store: C) -> ClientBuilder {
        self.config.cookie_store = Some(cookie_store.into_shared());
        self
    }

    /// Enable auto gzip decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto gzip decompression is turned on:
    ///
    /// - Requests without `Accept-Encoding` advertise `gzip`. Range requests use `Accept-Encoding:
    ///   identity` instead. The request body is **not** automatically compressed.
    /// - When receiving a response, if its headers contain a `Content-Encoding` value of `gzip`,
    ///   both `Content-Encoding` and `Content-Length` are removed from the headers' set. The
    ///   response body is automatically decompressed.
    ///
    /// If the `gzip` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `gzip` feature to be enabled
    #[inline]
    #[cfg(feature = "gzip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gzip")))]
    pub fn gzip(mut self, enable: bool) -> ClientBuilder {
        self.config.accept_encoding.gzip = enable;
        self
    }

    /// Enable auto brotli decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto brotli decompression is turned on:
    ///
    /// - Requests without `Accept-Encoding` advertise `br`. Range requests use `Accept-Encoding:
    ///   identity` instead. The request body is **not** automatically compressed.
    /// - When receiving a response, if its headers contain a `Content-Encoding` value of `br`, both
    ///   `Content-Encoding` and `Content-Length` are removed from the headers' set. The response
    ///   body is automatically decompressed.
    ///
    /// If the `brotli` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `brotli` feature to be enabled
    #[inline]
    #[cfg(feature = "brotli")]
    #[cfg_attr(docsrs, doc(cfg(feature = "brotli")))]
    pub fn brotli(mut self, enable: bool) -> ClientBuilder {
        self.config.accept_encoding.brotli = enable;
        self
    }

    /// Enable auto zstd decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto zstd decompression is turned on:
    ///
    /// - Requests without `Accept-Encoding` advertise `zstd`. Range requests use `Accept-Encoding:
    ///   identity` instead. The request body is **not** automatically compressed.
    /// - When receiving a response, if its headers contain a `Content-Encoding` value of `zstd`,
    ///   both `Content-Encoding` and `Content-Length` are removed from the headers' set. The
    ///   response body is automatically decompressed.
    ///
    /// If the `zstd` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `zstd` feature to be enabled
    #[inline]
    #[cfg(feature = "zstd")]
    #[cfg_attr(docsrs, doc(cfg(feature = "zstd")))]
    pub fn zstd(mut self, enable: bool) -> ClientBuilder {
        self.config.accept_encoding.zstd = enable;
        self
    }

    /// Enable auto deflate decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto deflate decompression is turned on:
    ///
    /// - Requests without `Accept-Encoding` advertise `deflate`. Range requests use
    ///   `Accept-Encoding: identity` instead. The request body is **not** automatically compressed.
    /// - When receiving a response, if it's headers contain a `Content-Encoding` value that equals
    ///   to `deflate`, both values `Content-Encoding` and `Content-Length` are removed from the
    ///   headers' set. The response body is automatically decompressed.
    ///
    /// If the `deflate` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `deflate` feature to be enabled
    #[inline]
    #[cfg(feature = "deflate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
    pub fn deflate(mut self, enable: bool) -> ClientBuilder {
        self.config.accept_encoding.deflate = enable;
        self
    }

    /// Disable auto response body zstd decompression.
    ///
    /// This method exists even if the optional `zstd` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use zstd decompression
    /// even if another dependency were to enable the optional `zstd` feature.
    #[inline]
    pub fn no_zstd(self) -> ClientBuilder {
        cfg_select! {
            feature = "zstd" => self.zstd(false),
            _ => self,
        }
    }

    /// Disable auto response body gzip decompression.
    ///
    /// This method exists even if the optional `gzip` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use gzip decompression
    /// even if another dependency were to enable the optional `gzip` feature.
    #[inline]
    pub fn no_gzip(self) -> ClientBuilder {
        cfg_select! {
            feature = "gzip" => self.gzip(false),
            _ => self,
        }
    }

    /// Disable auto response body brotli decompression.
    ///
    /// This method exists even if the optional `brotli` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use brotli decompression
    /// even if another dependency were to enable the optional `brotli` feature.
    #[inline]
    pub fn no_brotli(self) -> ClientBuilder {
        cfg_select! {
            feature = "brotli" => self.brotli(false),
            _ => self,
        }
    }

    /// Disable auto response body deflate decompression.
    ///
    /// This method exists even if the optional `deflate` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use deflate decompression
    /// even if another dependency were to enable the optional `deflate` feature.
    #[inline]
    pub fn no_deflate(self) -> ClientBuilder {
        cfg_select! {
            feature = "deflate" => self.deflate(false),
            _ => self,
        }
    }

    // Redirect options

    /// Set a `RedirectPolicy` for this client.
    ///
    /// Default is [`Policy::none()`](redirect::Policy::none), which returns redirect responses
    /// as-is. Use [`Policy::default()`](redirect::Policy::default) to follow up to 10 redirects.
    #[inline]
    pub fn redirect(mut self, policy: redirect::Policy) -> ClientBuilder {
        self.config.redirect_policy = policy;
        self
    }

    /// Enable or disable automatic `Referer` management during redirects.
    ///
    /// When enabled, redirect responses can control how an existing `Referer`
    /// is forwarded through `Referrer-Policy`. No header is added when the
    /// request has none.
    ///
    /// Default is `true`.
    #[inline]
    pub fn referer(mut self, enable: bool) -> ClientBuilder {
        self.config.referer = enable;
        self
    }

    // Retry options

    /// Set a request retry policy.
    pub fn retry(mut self, policy: retry::Policy) -> ClientBuilder {
        self.config.retry_policy = policy;
        self
    }

    // Proxy options

    /// Add a `Proxy` to the list of proxies the `Client` will use.
    ///
    /// # Note
    ///
    /// Adding a proxy will disable the automatic usage of the "system" proxy.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "tokio-rt")] {
    /// use wreq::{Client, Proxy};
    ///
    /// let proxy = Proxy::http("http://proxy:8080").unwrap();
    /// let client = Client::builder_tokio().proxy(proxy).build().unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn proxy(mut self, proxy: Proxy) -> ClientBuilder {
        self.config.connect.proxies.push(proxy.into_matcher());
        self.config.auto_sys_proxy = false;
        self
    }

    /// Clear all `Proxies`, so `Client` will use no proxy anymore.
    ///
    /// # Note
    /// To add a proxy exclusion list, use [crate::proxy::Proxy::no_proxy()]
    /// on all desired proxies instead.
    ///
    /// This also disables the automatic usage of the "system" proxy.
    #[inline]
    pub fn no_proxy(mut self) -> ClientBuilder {
        self.config.connect.proxies.clear();
        self.config.auto_sys_proxy = false;
        self
    }

    // Timeout options

    /// Enables a request timeout.
    ///
    /// The timeout is applied from when the request starts connecting until the
    /// response body has finished.
    ///
    /// Default is no timeout.
    #[inline]
    pub fn timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.config.timeout_options.total_timeout(timeout);
        self
    }

    /// Sets a timeout for waiting for response headers and reading each body frame.
    ///
    /// Time spent by the caller between body reads is not counted.
    ///
    /// Default is `None`.
    #[inline]
    pub fn read_timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.config.timeout_options.read_timeout(timeout);
        self
    }

    /// Set a timeout for only the connect phase of a `Client`.
    ///
    /// The timeout covers connection establishment for every protocol: connector layers,
    /// proxies, DNS resolution, the TCP address race and TLS handshake, or the QUIC handshake.
    /// The HTTP/3 handshake itself does not wait for the server. A timeout while resolving or
    /// dialing a proxy is a proxy connect error.
    ///
    /// Default is `None`.
    #[inline]
    pub fn connect_timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.config.connect.connect_timeout = Some(timeout);
        self
    }

    /// Set whether connections should emit verbose logs.
    ///
    /// Enabling this option will emit [log][] messages at the `TRACE` level
    /// for read and write operations on TCP and Unix connections. HTTP/3
    /// connections are not traced.
    ///
    /// [log]: https://crates.io/crates/log
    #[inline]
    pub fn connection_verbose(mut self, verbose: bool) -> ClientBuilder {
        self.config.connect.verbose = verbose;
        self
    }

    // HTTP options

    /// Sets how long an idle pooled connection remains eligible for reuse.
    ///
    /// Pass `None` to disable time-based eviction. The default is 90 seconds.
    #[inline]
    pub fn pool_idle_timeout<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.pool_idle_timeout = val.into();
        self
    }

    /// Sets the maximum idle HTTP/1 connections retained per compatibility group.
    ///
    /// This does not limit active physical connections. Passing `0` disables
    /// connection reuse.
    #[inline]
    pub fn pool_max_idle_per_host(mut self, max: usize) -> ClientBuilder {
        self.config.pool_max_idle_per_host = max;
        self
    }

    /// Sets the maximum number of compatibility groups retaining reusable connections.
    ///
    /// Idle HTTP/1 senders and shared HTTP/2 and HTTP/3 senders count toward this limit.
    /// A full limit evicts the least recently used idle group; a shared sender with a live
    /// request, body or tunnel is not evicted. This does not limit physical connections;
    /// `0` means unlimited.
    #[inline]
    pub fn pool_max_size(mut self, max: usize) -> ClientBuilder {
        self.config.pool_max_size = NonZeroUsize::new(max);
        self
    }

    /// Selects whether a reuse miss immediately connects or briefly waits for reuse.
    #[inline]
    pub fn pool_strategy(mut self, strategy: PoolStrategy) -> ClientBuilder {
        self.config.pool_strategy = strategy;
        self
    }

    /// Restrict the Client to be used with HTTPS only requests.
    ///
    /// Defaults to false.
    #[inline]
    pub fn https_only(mut self, enabled: bool) -> ClientBuilder {
        self.config.https_only = enabled;
        self
    }

    /// Uses HTTP/1 for both cleartext and TLS connections, without upgrading to H2.
    /// Only `http/1.1` is offered through TLS ALPN. A request-level
    /// [`version`](RequestBuilder::version) overrides this client setting.
    #[inline]
    pub fn http1_only(mut self) -> ClientBuilder {
        self.config.protocol = Protocol::Http1;
        self
    }

    /// Uses HTTP/2 without falling back to HTTP/1.
    ///
    /// Cleartext connections use prior knowledge, without an HTTP/1 Upgrade.
    /// TLS connections offer only `h2` through ALPN; if the peer omits ALPN,
    /// the client still attempts H2 and fails if the peer cannot speak it.
    /// An explicit HTTP/1 [`version`](RequestBuilder::version) on a request
    /// overrides this setting, as does HTTP/3 with the `http3` feature, which
    /// connects over QUIC. A WebSocket handshake without an explicit version
    /// may still use a dedicated HTTP/1.1 connection.
    #[inline]
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_only(mut self) -> ClientBuilder {
        self.config.protocol = Protocol::Http2;
        self
    }

    /// Uses HTTP/3 over QUIC without falling back to TCP.
    ///
    /// Enabling the `http3` feature alone does not select HTTP/3. HTTP/3 needs `https` URIs
    /// ([RFC 9114 Section 3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1)), and a
    /// request routed to an `http://` or `https://` proxy, including one from the environment,
    /// fails; use a `quic://` proxy, a SOCKS5 proxy with the `socks` feature, or
    /// [`no_proxy`](Self::no_proxy). An explicit HTTP/1 or HTTP/2 request
    /// [`version`](RequestBuilder::version) overrides this setting. A WebSocket handshake without
    /// an explicit version uses an established HTTP/3 connection whose peer enabled extended
    /// CONNECT, otherwise a dedicated HTTP/1.1 connection.
    #[cfg(feature = "http3")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
    pub fn http3_only(mut self) -> ClientBuilder {
        self.config.protocol = Protocol::Http3;
        self
    }

    /// Sets the HTTP/1 options for the client.
    #[inline]
    pub fn http1_options<T>(mut self, options: T) -> ClientBuilder
    where
        T: Into<Option<Http1Options>>,
    {
        self.config.config_set.set(options.into());
        self
    }

    /// Sets the HTTP/2 options for the client.
    #[inline]
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_options<T>(mut self, options: T) -> ClientBuilder
    where
        T: Into<Option<Http2Options>>,
    {
        self.config.config_set.set(options.into());
        self
    }

    /// Sets the HTTP/3 options for the client.
    #[cfg(feature = "http3")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
    pub fn http3_options<T>(mut self, options: T) -> ClientBuilder
    where
        T: Into<Option<netty::http3::Http3Options>>,
    {
        self.config.config_set.set(options.into());
        self
    }

    /// Sets the QUIC transport and TLS options of HTTP/3 connections, `quic://` proxy hops
    /// included. TCP connections use [`tls_options`](Self::tls_options) instead.
    #[cfg(feature = "http3")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
    pub fn quic_options<T>(mut self, options: T) -> ClientBuilder
    where
        T: Into<Option<crate::quic::QuicOptions>>,
    {
        self.config.config_set.set(options.into());
        self
    }

    // TCP options

    /// Set whether sockets have `TCP_NODELAY` enabled.
    ///
    /// Default is `true`.
    #[inline]
    pub fn tcp_nodelay(mut self, enabled: bool) -> ClientBuilder {
        self.config.connect.tcp.nodelay = enabled;
        self
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied duration.
    ///
    /// If `None`, the option will not be set.
    ///
    /// Default is 15 seconds.
    #[inline]
    pub fn tcp_keepalive<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.connect.tcp.keepalive = val.into();
        self
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied interval.
    ///
    /// If `None`, the option will not be set.
    ///
    /// Default is 15 seconds.
    #[inline]
    pub fn tcp_keepalive_interval<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.connect.tcp.keepalive_interval = val.into();
        self
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied retry count.
    ///
    /// If `None`, the option will not be set.
    ///
    /// Default is 3 retries.
    #[inline]
    pub fn tcp_keepalive_retries<C>(mut self, retries: C) -> ClientBuilder
    where
        C: Into<Option<u32>>,
    {
        self.config.connect.tcp.keepalive_retries = retries.into();
        self
    }

    /// Set that all sockets have `TCP_USER_TIMEOUT` set with the supplied duration.
    ///
    /// This option controls how long transmitted data may remain unacknowledged before
    /// the connection is force-closed.
    ///
    /// If `None`, the option will not be set.
    ///
    /// Default is 30 seconds.
    #[inline]
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
    )]
    pub fn tcp_user_timeout<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.connect.tcp.tcp_user_timeout = val.into();
        self
    }

    /// Set whether sockets have `SO_REUSEADDR` enabled.
    #[inline]
    pub fn tcp_reuse_address(mut self, enabled: bool) -> ClientBuilder {
        self.config.connect.tcp.reuse_address = enabled;
        self
    }

    /// Set that all sockets have `SO_LINGER` set with the supplied duration.
    ///
    /// This option controls how long the socket lingers on close while data
    /// remains unsent. A duration of zero aborts the connection on close: unsent
    /// data is discarded, the connection is reset (`RST`) rather than going
    /// through the normal `FIN` termination sequence, and the socket does not
    /// enter `TIME_WAIT`.
    ///
    /// If `None`, the option will not be set and the operating system default
    /// applies.
    ///
    /// Default is `None`.
    #[inline]
    pub fn tcp_linger<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.connect.tcp.linger = val.into();
        self
    }

    /// Sets the size of the TCP send buffer on this client socket.
    ///
    /// On most operating systems, this sets the `SO_SNDBUF` socket option.
    #[inline]
    pub fn tcp_send_buffer_size<S>(mut self, size: S) -> ClientBuilder
    where
        S: Into<Option<usize>>,
    {
        self.config.connect.tcp.send_buffer_size = size.into();
        self
    }

    /// Sets the size of the TCP receive buffer on this client socket.
    ///
    /// On most operating systems, this sets the `SO_RCVBUF` socket option.
    #[inline]
    pub fn tcp_recv_buffer_size<S>(mut self, size: S) -> ClientBuilder
    where
        S: Into<Option<usize>>,
    {
        self.config.connect.tcp.recv_buffer_size = size.into();
        self
    }

    /// Set the delay between connection attempts for
    /// [RFC 8305 (Happy Eyeballs v2)][RFC 8305].
    ///
    /// The first address is attempted immediately. Later addresses are started
    /// after this delay without waiting for the previous attempt to finish.
    ///
    /// If `None`, parallel connection attempts are disabled.
    ///
    /// HTTP/3 QUIC dials and SOCKS5 UDP target races use the same delay.
    ///
    /// Default is 300 milliseconds.
    ///
    /// [RFC 8305]: https://www.rfc-editor.org/rfc/rfc8305.html#section-5
    #[inline]
    pub fn tcp_happy_eyeballs_timeout<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.connect.happy_eyeballs_timeout = val.into();
        self
    }

    /// Bind to a local IP Address.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "tokio-rt")] {
    /// use std::net::IpAddr;
    /// use wreq::Client;
    ///
    /// let local_addr = IpAddr::from([12, 4, 1, 8]);
    /// let client = Client::builder_tokio()
    ///     .local_address(local_addr)
    ///     .build()
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn local_address<T>(mut self, addr: T) -> ClientBuilder
    where
        T: Into<Option<IpAddr>>,
    {
        dialer::set_local_address(&mut self.config.config_set, addr.into());
        self
    }

    /// Set that all sockets are bound to the configured IPv4 or IPv6 address (depending on host's
    /// preferences) before connection.
    ///
    ///  # Example
    /// ///
    /// ```
    /// # #[cfg(feature = "tokio-rt")] {
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    /// use wreq::Client;
    ///
    /// let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
    /// let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    /// let client = Client::builder_tokio()
    ///     .local_addresses(ipv4, ipv6)
    ///     .build()
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn local_addresses<V4, V6>(mut self, ipv4: V4, ipv6: V6) -> ClientBuilder
    where
        V4: Into<Option<Ipv4Addr>>,
        V6: Into<Option<Ipv6Addr>>,
    {
        dialer::set_local_addresses(&mut self.config.config_set, ipv4.into(), ipv6.into());
        self
    }

    /// Bind connections only on the specified network interface.
    ///
    /// This option is only available on the following operating systems:
    ///
    /// - Android
    /// - Fuchsia
    /// - Linux,
    /// - macOS and macOS-like systems (iOS, tvOS, watchOS and visionOS)
    /// - Solaris and illumos
    ///
    /// On Android, Linux, and Fuchsia, this uses the
    /// [`SO_BINDTODEVICE`][man-7-socket] socket option. On macOS and macOS-like
    /// systems, Solaris, and illumos, this instead uses the [`IP_BOUND_IF` and
    /// `IPV6_BOUND_IF`][man-7p-ip] socket options (as appropriate).
    ///
    /// Note that connections will fail if the provided interface name is not a
    /// network interface that currently exists when a connection is established.
    ///
    /// HTTP/3 connections share one UDP socket per address family, bound to the interface
    /// when the first one opens. If the interface is removed and re-created, that socket
    /// keeps the old one, so rebuild the client to use HTTP/3 over the new interface.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "tokio-rt")] {
    /// use wreq::Client;
    ///
    /// # fn doc() -> Result<(), wreq::Error> {
    /// let interface = "lo";
    /// let client = Client::builder_tokio()
    ///     .interface(interface)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    ///
    /// [man-7-socket]: https://man7.org/linux/man-pages/man7/socket.7.html
    /// [man-7p-ip]: https://docs.oracle.com/cd/E86824_01/html/E54777/ip-7p.html
    #[inline]
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        )))
    )]
    pub fn interface<T>(mut self, interface: T) -> ClientBuilder
    where
        T: Into<std::borrow::Cow<'static, str>>,
    {
        dialer::set_interface(&mut self.config.config_set, interface.into());
        self
    }

    // TLS options

    /// Sets the identity to be used for client certificate authentication.
    ///
    /// The identity is also offered to `https://` and `quic://` proxies that request one.
    #[inline]
    pub fn tls_identity(mut self, identity: Identity) -> ClientBuilder {
        self.config.connect.tls.identity = Some(identity);
        self
    }

    /// Sets a custom certificate store for TLS server verification.
    ///
    /// This replaces bundled roots and BoringSSL's default verification paths, and also verifies
    /// `https://` and `quic://` proxies.
    #[inline]
    pub fn tls_cert_store(mut self, store: CertStore) -> ClientBuilder {
        self.config.connect.tls.cert_store = Some(store);
        self
    }

    /// Controls the use of certificate validation.
    ///
    /// Applies to targets and to `https://` and `quic://` proxies. Defaults to `true`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If
    /// invalid certificates are trusted, *any* certificate for *any* site
    /// will be trusted for use. This includes expired certificates. This
    /// introduces significant vulnerabilities, and should only be used
    /// as a last resort.
    #[inline]
    pub fn tls_cert_verification(mut self, cert_verification: bool) -> ClientBuilder {
        self.config.connect.tls.cert_verification = cert_verification;
        self
    }

    /// Configures the use of hostname verification when connecting.
    ///
    /// Each hop is checked against its own host: an `https://` or `quic://` proxy against the
    /// proxy host, the target against the request host. Defaults to `true`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before you use this method. If hostname verification is not
    /// used, *any* valid certificate for *any* site will be trusted for use from any other. This
    /// introduces a significant vulnerability to man-in-the-middle attacks.
    #[inline]
    pub fn tls_verify_hostname(mut self, verify_hostname: bool) -> ClientBuilder {
        self.config.connect.tls.verify_hostname = verify_hostname;
        self
    }

    /// Configures the use of Server Name Indication (SNI) when connecting.
    ///
    /// Also applies to `https://` and `quic://` proxies, which receive the proxy host; IP literals
    /// are never sent. Defaults to `true`.
    #[inline]
    pub fn tls_sni(mut self, tls_sni: bool) -> ClientBuilder {
        self.config.connect.tls.sni = tls_sni;
        self
    }

    /// Configures TLS key logging for the client.
    #[inline]
    pub fn tls_keylog(mut self, keylog: KeyLog) -> ClientBuilder {
        self.config.connect.tls.keylog = Some(keylog);
        self
    }

    /// Set the minimum required TLS version for connections.
    ///
    /// By default the TLS backend's own default is used. HTTP/3 always uses
    /// TLS 1.3 and ignores this setting.
    #[inline]
    pub fn tls_min_version(mut self, version: TlsVersion) -> ClientBuilder {
        self.config.connect.tls.min_version = Some(version);
        self
    }

    /// Set the maximum allowed TLS version for connections.
    ///
    /// By default there's no maximum. HTTP/3 requires TLS 1.3, so a lower
    /// maximum makes every HTTP/3 connection fail.
    #[inline]
    pub fn tls_max_version(mut self, version: TlsVersion) -> ClientBuilder {
        self.config.connect.tls.max_version = Some(version);
        self
    }

    /// Add TLS information as `TlsInfo` extension to responses.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    #[inline]
    pub fn tls_info(mut self, tls_info: bool) -> ClientBuilder {
        self.config.connect.tls.tls_info = tls_info;
        self
    }

    /// Replaces the built-in store of 1024 connection keys with two tickets each.
    /// The supplied store controls retention when ticket-based resumption is enabled.
    /// Session keys remain scoped to this client and its request configuration.
    #[inline]
    pub fn tls_session_store<S: IntoTlsSessionStore>(mut self, store: S) -> ClientBuilder {
        self.config.connect.tls.tickets = Arc::new(Tickets::new(Some(store.into_shared())));
        self
    }

    /// Sets the TLS options of TCP connections, `https://` proxy hops included; proxy hops offer
    /// no ALPN. HTTP/3 connections use `quic_options` instead.
    #[inline]
    pub fn tls_options<T>(mut self, options: T) -> ClientBuilder
    where
        T: Into<Option<TlsOptions>>,
    {
        self.config.config_set.set(options.into());
        self
    }

    // DNS options

    /// Override DNS resolution for specific domains to a particular IP address.
    ///
    /// Warning
    ///
    /// Since the DNS protocol has no notion of ports, if you wish to send
    /// traffic to a particular port you must include this port in the URI
    /// itself, any port in the overridden addr will be ignored and traffic sent
    /// to the conventional port for the given scheme (e.g. 80 for http).
    #[inline]
    pub fn resolve<D>(self, domain: D, addr: SocketAddr) -> ClientBuilder
    where
        D: Into<Cow<'static, str>>,
    {
        self.resolve_to_addrs(domain, std::iter::once(addr))
    }

    /// Override DNS resolution for specific domains to particular IP addresses.
    ///
    /// Warning
    ///
    /// Since the DNS protocol has no notion of ports, if you wish to send
    /// traffic to a particular port you must include this port in the URI
    /// itself, any port in the overridden addresses will be ignored and traffic sent
    /// to the conventional port for the given scheme (e.g. 80 for http).
    #[inline]
    pub fn resolve_to_addrs<D, A>(mut self, domain: D, addrs: A) -> ClientBuilder
    where
        D: Into<Cow<'static, str>>,
        A: IntoIterator<Item = SocketAddr>,
    {
        self.config
            .dns_overrides
            .insert(domain.into(), addrs.into_iter().collect());
        self
    }

    /// Override the DNS resolver implementation.
    ///
    /// Pass any type implementing `IntoResolve`.
    /// Overrides for specific names passed to `resolve` and `resolve_to_addrs` will
    /// still be applied on top of this resolver.
    #[inline]
    pub fn dns_resolver<R: IntoResolve>(mut self, resolver: R) -> ClientBuilder {
        self.config.dns_resolver = Some(resolver.into_shared());
        self
    }

    // Tower middleware options

    /// Adds a new Tower [`Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) to the
    /// request [`Service`](https://docs.rs/tower/latest/tower/trait.Service.html) which is responsible
    /// for request processing.
    ///
    /// Each subsequent invocation of this function will wrap previous layers.
    ///
    /// If configured, the `timeout` will be the outermost layer.
    ///
    /// Example usage:
    /// ```
    /// # #[cfg(feature = "tokio-rt")] {
    /// use std::time::Duration;
    /// use tower::timeout::TimeoutLayer;
    /// use wreq::Client;
    ///
    /// let client = Client::builder_tokio()
    ///     .timeout(Duration::from_millis(200))
    ///     .layer(TimeoutLayer::new(Duration::from_millis(50)))
    ///     .build()
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn layer<L>(mut self, layer: L) -> ClientBuilder
    where
        L: Layer<
                BoxCloneSyncService<
                    http::Request<Body>,
                    http::Response<MaybeDecompressionBody<Incoming>>,
                    BoxError,
                >,
            > + Send
            + Sync
            + 'static,
        L::Service: Service<
                http::Request<Body>,
                Response = http::Response<MaybeDecompressionBody<Incoming>>,
                Error = BoxError,
                Future: Send + 'static,
            > + Clone
            + Send
            + Sync
            + 'static,
    {
        let layer = BoxCloneSyncServiceLayer::new(layer);
        self.config.layers.push(layer);
        self
    }

    /// Adds a Tower [`Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) around
    /// connection establishment, including TCP, proxies, TLS and QUIC.
    /// Both transport paths share the same layer stack.
    ///
    /// Each subsequent invocation of this function will wrap previous layers.
    ///
    /// If configured, `connect_timeout` wraps the layer stack. It starts when the
    /// service is called, after readiness waits such as concurrency admission.
    ///
    /// Example usage:
    /// ```
    /// # #[cfg(feature = "tokio-rt")] {
    /// use std::time::Duration;
    /// use tower::limit::ConcurrencyLimitLayer;
    /// use tower::timeout::TimeoutLayer;
    /// use wreq::Client;
    ///
    /// let client = Client::builder_tokio()
    ///     // The outer connection deadline starts after concurrency admission.
    ///     .connect_timeout(Duration::from_millis(200))
    ///     // underneath the concurrency check, so only after concurrency limit lets us through
    ///     .connector_layer(TimeoutLayer::new(Duration::from_millis(50)))
    ///     .connector_layer(ConcurrencyLimitLayer::new(2))
    ///     .build()
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn connector_layer<L>(mut self, layer: L) -> ClientBuilder
    where
        L: Layer<BoxedTransportConnector> + Send + Sync + 'static,
        L::Service: Service<Unnameable, Response = Conn, Error = BoxError, Future: Send + 'static>
            + Clone
            + Send
            + Sync
            + 'static,
    {
        let layer = BoxCloneSyncServiceLayer::new(layer);
        self.config.connect.layers.push(layer);
        self
    }

    // Emulation options

    /// Applies the emulation's headers and protocol options.
    /// Supplied options replace matching settings; absent ones are kept.
    /// The emulation does not create a connection group.
    #[inline]
    pub fn emulation<T: IntoEmulation>(mut self, emulation: T) -> ClientBuilder {
        let emulate::Emulation(headers, orig_headers, config_set) = emulation.into_emulation();
        self.config.config_set.extend(config_set);
        self.default_headers(headers).orig_headers(orig_headers)
    }
}

/// Low-level Tower client and builder used by the public client.
mod sealed {
    use super::{pool::TransportConnector, *};

    /// Tower service beneath [`crate::Client`] that validates and sends HTTP requests.
    /// Applies request configuration, cancellation retries, pool checkout and protocol dispatch.
    /// Clones share the pool without cloning request bodies.
    pub type Client<C> = svc::Stack<svc::Dispatch<C>, Body>;

    /// Assembles the protocol, runtime, and pool services used by [`Client`].
    ///
    /// The builder owns client connection configuration until [`Builder::build`]
    /// consumes it. The resulting client clones share the pool created around
    /// the supplied connector.
    pub struct Builder {
        /// Runtime used by protocol drivers and pool maintenance.
        runtime: DynRuntime,

        /// Protocol, options and socket bindings that requests inherit.
        protocol: Protocol,
        config_set: ConfigSet,

        /// Connection-pool reuse and retention policy.
        pool_config: pool::Config,

        /// Cookie store consulted immediately around protocol dispatch.
        #[cfg(feature = "cookies")]
        cookie_store: Option<Arc<dyn cookie::CookieStore>>,
    }

    // ===== impl Builder =====

    impl Builder {
        /// Creates a builder using `runtime` for protocol drivers and pool tasks.
        pub fn new(runtime: DynRuntime) -> Self {
            Self {
                protocol: Protocol::Auto,
                config_set: ConfigSet::default(),
                pool_config: pool::Config {
                    idle_timeout: Some(Duration::from_secs(90)),
                    max_idle_per_host: usize::MAX,
                    max_size: None,
                    ..pool::Config::default()
                },
                #[cfg(feature = "cookies")]
                cookie_store: None,
                runtime,
            }
        }

        /// Sets how long a connection considered idle remains eligible for reuse.
        ///
        /// `None` disables time-based eviction. The default is 90 seconds.
        #[inline]
        pub fn pool_idle_timeout<D>(mut self, val: D) -> Self
        where
            D: Into<Option<Duration>>,
        {
            self.pool_config.idle_timeout = val.into();
            self
        }

        /// Sets the maximum idle HTTP/1 senders retained per compatibility group.
        ///
        /// This does not limit active physical connections. `0` disables pooling;
        /// the default is `usize::MAX`.
        #[inline]
        pub fn pool_max_idle_per_host(mut self, max_idle: usize) -> Self {
            self.pool_config.max_idle_per_host = max_idle;
            self
        }

        /// Sets the maximum number of compatibility groups retaining reusable senders.
        ///
        /// An entry is counted only while it owns a reusable sender. Routing-only
        /// and connecting entries are not counted. This does not limit physical
        /// connections. The default is `None`.
        #[inline]
        pub fn pool_max_size(mut self, max_size: impl Into<Option<NonZeroUsize>>) -> Self {
            self.pool_config.max_size = max_size.into();
            self
        }

        /// Selects whether a reuse miss immediately connects or waits for reuse.
        #[inline]
        pub fn pool_strategy(mut self, strategy: PoolStrategy) -> Self {
            self.pool_config.strategy = strategy;
            self
        }

        /// Shares the client's protocol selection with the request stack and pool.
        #[inline]
        pub fn protocol(mut self, protocol: Protocol) -> Self {
            self.protocol = protocol;
            self
        }

        /// Sets the connection options inherited by requests.
        ///
        /// Pool and session identities count only request values that differ from these.
        #[inline]
        pub fn config_set(mut self, config_set: ConfigSet) -> Self {
            self.config_set = config_set;
            self
        }

        /// Sets the cookie store consulted immediately around protocol dispatch.
        #[inline]
        pub fn cookie_store(
            #[cfg_attr(
                not(feature = "cookies"),
                expect(unused_mut, reason = "Only the cookies feature mutates this builder")
            )]
            mut self,
            #[cfg(feature = "cookies")] cookie_store: Option<Arc<dyn cookie::CookieStore>>,
        ) -> Self {
            #[cfg(feature = "cookies")]
            {
                self.cookie_store = cookie_store;
            }
            self
        }

        /// Consumes the builder and wraps the connector in the complete client stack.
        ///
        /// Every client retries unsent requests and lets HTTP/1 generate a missing `Host`.
        pub fn build<C>(self, connector: C) -> Client<C>
        where
            C: TransportConnector,
        {
            let dispatch = svc::Dispatch::new(
                self.pool_config,
                connector,
                &self.config_set,
                true,
                #[cfg(feature = "cookies")]
                self.cookie_store,
                self.runtime,
            );
            ServiceBuilder::new()
                .layer(svc::layer(self.protocol, self.config_set, true))
                .service(dispatch)
        }
    }
}
