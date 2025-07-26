mod aliases;
mod connect;
mod future;
mod service;

use std::{
    collections::HashMap,
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use aliases::{
    BoxedClientLayer, BoxedClientService, BoxedConnectorLayer, BoxedConnectorService,
    GenericClientService, ResponseBody,
};
pub use future::Pending;
use http::{
    Request as HttpRequest, Response as HttpResponse,
    header::{HeaderMap, HeaderValue, USER_AGENT},
};
use service::ClientService;
use tower::{
    Layer, Service, ServiceBuilder, ServiceExt,
    retry::RetryLayer,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer},
};
#[cfg(feature = "cookies")]
use {super::layer::cookie::CookieManagerLayer, crate::cookie};

#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
))]
use super::layer::decoder::{AcceptEncoding, DecompressionLayer};
#[cfg(feature = "ws")]
use super::ws::WebSocketRequestBuilder;
use super::{
    Body, EmulationFactory,
    layer::{
        redirect::FollowRedirectLayer,
        retry::Http2RetryPolicy,
        timeout::{ResponseBodyTimeoutLayer, TimeoutLayer},
    },
    request::{Request, RequestBuilder},
    response::Response,
};
#[cfg(feature = "hickory-dns")]
use crate::dns::hickory::{HickoryDnsResolver, LookupIpStrategy};
use crate::{
    IntoUrl, Method, OriginalHeaders, Proxy,
    client::{
        http::{
            aliases::HttpConnector,
            connect::{Conn, Connector, Unnameable},
        },
        layer::timeout::TimeoutOptions,
    },
    core::{
        client::{HttpClient, connect::TcpConnectOptions, options::TransportOptions},
        rt::{TokioExecutor, tokio::TokioTimer},
    },
    dns::{DnsResolverWithOverrides, DynResolver, Resolve, gai::GaiResolver},
    error::{self, BoxError, Error},
    proxy::Matcher as ProxyMatcher,
    redirect::{self, FollowRedirectPolicy, Policy as RedirectPolicy},
    tls::{AlpnProtocol, CertStore, Identity, KeyLogPolicy, TlsConnectorBuilder, TlsVersion},
};

/// An `Client` to make Requests with.
///
/// The Client has various configuration values to tweak, but the defaults
/// are set to what is usually the most commonly desired value. To configure a
/// `Client`, use `Client::builder()`.
///
/// The `Client` holds a connection pool internally, so it is advised that
/// you create one and **reuse** it.
///
/// You do **not** have to wrap the `Client` in an [`Rc`] or [`Arc`] to **reuse** it,
/// because it already uses an [`Arc`] internally.
///
/// [`Rc`]: std::rc::Rc
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientRef>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum ClientRef {
    Boxed(BoxedClientService),
    Generic(GenericClientService),
}

/// A `ClientBuilder` can be used to create a `Client` with custom configuration.
#[must_use]
pub struct ClientBuilder {
    config: Config,
}

/// The HTTP version preference for the client.
#[repr(u8)]
enum HttpVersionPref {
    Http1,
    Http2,
    All,
}

struct Config {
    error: Option<Error>,
    headers: HeaderMap,
    original_headers: Option<OriginalHeaders>,
    #[cfg(any(
        feature = "gzip",
        feature = "zstd",
        feature = "brotli",
        feature = "deflate",
    ))]
    accept_encoding: AcceptEncoding,
    connect_timeout: Option<Duration>,
    connection_verbose: bool,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: usize,
    pool_max_size: Option<NonZeroU32>,
    tcp_nodelay: bool,
    tcp_reuse_address: bool,
    tcp_keepalive: Option<Duration>,
    tcp_keepalive_interval: Option<Duration>,
    tcp_keepalive_retries: Option<u32>,
    tcp_send_buffer_size: Option<usize>,
    tcp_recv_buffer_size: Option<usize>,
    tcp_happy_eyeballs_timeout: Option<Duration>,
    tcp_connect_options: Option<TcpConnectOptions>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    tcp_user_timeout: Option<Duration>,
    proxies: Vec<ProxyMatcher>,
    auto_sys_proxy: bool,
    redirect_policy: RedirectPolicy,
    referer: bool,
    timeout_options: TimeoutOptions,
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn cookie::CookieStore>>,
    #[cfg(feature = "hickory-dns")]
    hickory_dns: bool,
    dns_overrides: HashMap<String, Vec<SocketAddr>>,
    dns_resolver: Option<Arc<dyn Resolve>>,
    http_version_pref: HttpVersionPref,
    https_only: bool,
    http2_max_retry: usize,
    layers: Vec<BoxedClientLayer>,
    connector_layers: Vec<BoxedConnectorLayer>,
    keylog_policy: Option<KeyLogPolicy>,
    tls_info: bool,
    tls_sni: bool,
    verify_hostname: bool,
    identity: Option<Identity>,
    cert_store: CertStore,
    cert_verification: bool,
    min_tls_version: Option<TlsVersion>,
    max_tls_version: Option<TlsVersion>,
    transport_options: TransportOptions,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    /// Constructs a new `ClientBuilder`.
    ///
    /// This is the same as `Client::builder()`.
    pub fn new() -> ClientBuilder {
        ClientBuilder {
            config: Config {
                error: None,
                headers: HeaderMap::new(),
                original_headers: None,
                #[cfg(any(
                    feature = "gzip",
                    feature = "zstd",
                    feature = "brotli",
                    feature = "deflate",
                ))]
                accept_encoding: AcceptEncoding::default(),
                connect_timeout: None,
                connection_verbose: false,
                pool_idle_timeout: Some(Duration::from_secs(90)),
                pool_max_idle_per_host: usize::MAX,
                pool_max_size: None,
                // TODO: Re-enable default duration once core's HttpConnector is fixed
                // to no longer error when an option fails.
                tcp_keepalive: None,
                tcp_keepalive_interval: None,
                tcp_keepalive_retries: None,
                tcp_connect_options: None,
                tcp_nodelay: true,
                tcp_reuse_address: false,
                tcp_send_buffer_size: None,
                tcp_recv_buffer_size: None,
                tcp_happy_eyeballs_timeout: Some(Duration::from_millis(300)),
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                tcp_user_timeout: None,
                proxies: Vec::new(),
                auto_sys_proxy: true,
                redirect_policy: RedirectPolicy::none(),
                referer: true,
                timeout_options: TimeoutOptions::default(),
                #[cfg(feature = "hickory-dns")]
                hickory_dns: cfg!(feature = "hickory-dns"),
                #[cfg(feature = "cookies")]
                cookie_store: None,
                dns_overrides: HashMap::new(),
                dns_resolver: None,
                http_version_pref: HttpVersionPref::All,
                https_only: false,
                http2_max_retry: 2,
                layers: Vec::new(),
                connector_layers: Vec::new(),
                keylog_policy: None,
                tls_info: false,
                tls_sni: true,
                verify_hostname: true,
                identity: None,
                cert_store: CertStore::default(),
                cert_verification: true,
                min_tls_version: None,
                max_tls_version: None,
                // Transport options for HTTP/1/2 and TLS.
                transport_options: TransportOptions::default(),
            },
        }
    }

    /// Returns a `Client` that uses this `ClientBuilder` configuration.
    ///
    /// # Errors
    ///
    /// This method fails if a TLS backend cannot be initialized, or the resolver
    /// cannot load the system configuration.
    pub fn build(self) -> crate::Result<Client> {
        let config = self.config;

        if let Some(err) = config.error {
            return Err(err);
        }

        let mut proxies = config.proxies;
        if config.auto_sys_proxy {
            proxies.push(ProxyMatcher::system());
        }
        let proxies = Arc::new(proxies);

        let (tls_opts, http1_opts, http2_opts) = config.transport_options.into_parts();

        // Create the TLS connector with the provided options.
        let connector = {
            let resolver = {
                let mut resolver: Arc<dyn Resolve> = match config.dns_resolver {
                    Some(dns_resolver) => dns_resolver,
                    #[cfg(feature = "hickory-dns")]
                    None if config.hickory_dns => {
                        Arc::new(HickoryDnsResolver::new(LookupIpStrategy::Ipv4thenIpv6)?)
                    }
                    None => Arc::new(GaiResolver::new()),
                };

                if !config.dns_overrides.is_empty() {
                    resolver = Arc::new(DnsResolverWithOverrides::new(
                        resolver,
                        config.dns_overrides,
                    ));
                }
                DynResolver::new(resolver)
            };

            // Apply http connector options
            let http = |http: &mut HttpConnector| {
                http.enforce_http(false);
                http.set_keepalive(config.tcp_keepalive);
                http.set_keepalive_interval(config.tcp_keepalive_interval);
                http.set_keepalive_retries(config.tcp_keepalive_retries);
                http.set_reuse_address(config.tcp_reuse_address);
                http.set_connect_options(config.tcp_connect_options);
                http.set_connect_timeout(config.connect_timeout);
                http.set_nodelay(config.tcp_nodelay);
                http.set_send_buffer_size(config.tcp_send_buffer_size);
                http.set_recv_buffer_size(config.tcp_recv_buffer_size);
                http.set_happy_eyeballs_timeout(config.tcp_happy_eyeballs_timeout);
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                http.set_tcp_user_timeout(config.tcp_user_timeout);
            };

            // Apply tls connector options
            let tls = |tls: TlsConnectorBuilder| {
                let alpn_protocol = match config.http_version_pref {
                    HttpVersionPref::Http1 => Some(AlpnProtocol::HTTP1),
                    HttpVersionPref::Http2 => Some(AlpnProtocol::HTTP2),
                    _ => None,
                };
                tls.alpn_protocol(alpn_protocol)
                    .max_version(config.max_tls_version)
                    .min_version(config.min_tls_version)
                    .tls_sni(config.tls_sni)
                    .verify_hostname(config.verify_hostname)
                    .cert_verification(config.cert_verification)
                    .cert_store(config.cert_store)
                    .identity(config.identity)
                    .keylog(config.keylog_policy)
            };

            Connector::builder(proxies.clone(), resolver)
                .timeout(config.connect_timeout)
                .tls_info(config.tls_info)
                .verbose(config.connection_verbose)
                .tls_options(tls_opts)
                .with_tls(tls)
                .with_http(http)
                .build(config.connector_layers)?
        };

        // Create client with the configured connector
        let client = {
            let http2_only = matches!(config.http_version_pref, HttpVersionPref::Http2);
            let mut builder = HttpClient::builder(TokioExecutor::new());
            builder
                .http1_options(http1_opts)
                .http2_options(http2_opts)
                .http2_only(http2_only)
                .http2_timer(TokioTimer::new())
                .pool_timer(TokioTimer::new())
                .pool_idle_timeout(config.pool_idle_timeout)
                .pool_max_idle_per_host(config.pool_max_idle_per_host)
                .pool_max_size(config.pool_max_size);
            builder.build(connector)
        };

        // Create the client with the configured service layers
        let client = {
            let service = ClientService::new(
                client,
                config.headers,
                config.original_headers,
                config.https_only,
                proxies,
            );

            #[cfg(any(
                feature = "gzip",
                feature = "zstd",
                feature = "brotli",
                feature = "deflate",
            ))]
            let service = ServiceBuilder::new()
                .layer(DecompressionLayer::new(config.accept_encoding))
                .service(service);

            let service = ServiceBuilder::new()
                .layer(ResponseBodyTimeoutLayer::new(config.timeout_options))
                .service(service);

            #[cfg(feature = "cookies")]
            let service = ServiceBuilder::new()
                .layer(CookieManagerLayer::new(config.cookie_store))
                .service(service);

            let service = {
                let policy = FollowRedirectPolicy::new(config.redirect_policy)
                    .with_referer(config.referer)
                    .with_https_only(config.https_only);

                ServiceBuilder::new()
                    .layer(FollowRedirectLayer::with_policy(policy))
                    .service(service)
            };

            let service = ServiceBuilder::new()
                .layer(RetryLayer::new(Http2RetryPolicy::new(
                    config.http2_max_retry,
                )))
                .service(service);

            if config.layers.is_empty() {
                let service = ServiceBuilder::new()
                    .layer(TimeoutLayer::new(config.timeout_options))
                    .service(service);

                let service = ServiceBuilder::new()
                    .map_err(error::map_timeout_to_request_error as _)
                    .service(service);

                ClientRef::Generic(service)
            } else {
                let service = config.layers.into_iter().fold(
                    BoxCloneSyncService::new(service),
                    |client_service, layer| {
                        ServiceBuilder::new().layer(layer).service(client_service)
                    },
                );

                let service = ServiceBuilder::new()
                    .layer(TimeoutLayer::new(config.timeout_options))
                    .service(service);

                let service = ServiceBuilder::new()
                    .map_err(error::map_timeout_to_request_error)
                    .service(service);

                ClientRef::Boxed(BoxCloneSyncService::new(service))
            }
        };

        Ok(Client {
            inner: Arc::new(client),
        })
    }

    // Higher-level options

    /// Sets the `User-Agent` header to be used by this client.
    ///
    /// # Example
    ///
    /// ```rust
    /// # async fn doc() -> wreq::Result<()> {
    /// // Name your user agent after your app?
    /// static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);
    ///
    /// let client = wreq::Client::builder().user_agent(APP_USER_AGENT).build()?;
    /// let res = client.get("https://www.rust-lang.org").send().await?;
    /// # Ok(())
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
    /// use wreq::header;
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
    /// let client = wreq::Client::builder().default_headers(headers).build()?;
    /// let res = client.get("https://www.rust-lang.org").send().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Override the default headers:
    ///
    /// ```rust
    /// use wreq::header;
    /// # async fn doc() -> wreq::Result<()> {
    /// let mut headers = header::HeaderMap::new();
    /// headers.insert("X-MY-HEADER", header::HeaderValue::from_static("value"));
    ///
    /// // get a client builder
    /// let client = wreq::Client::builder().default_headers(headers).build()?;
    /// let res = client
    ///     .get("https://www.rust-lang.org")
    ///     .header("X-MY-HEADER", "new_value")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn default_headers(mut self, headers: HeaderMap) -> ClientBuilder {
        crate::util::replace_headers(&mut self.config.headers, headers);
        self
    }

    /// Sets the original headers for every request.
    #[inline]
    pub fn original_headers(mut self, original_headers: OriginalHeaders) -> ClientBuilder {
        self.config.original_headers = Some(original_headers);
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
    pub fn cookie_provider<C: cookie::CookieStore + 'static>(
        mut self,
        cookie_store: Arc<C>,
    ) -> ClientBuilder {
        self.config.cookie_store = Some(cookie_store as _);
        self
    }

    /// Enable auto gzip decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto gzip decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already contain an
    ///   `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to `gzip`.
    ///   The request body is **not** automatically compressed.
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
    pub fn gzip(mut self, enable: bool) -> ClientBuilder {
        self.config.accept_encoding.gzip(enable);
        self
    }

    /// Enable auto brotli decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto brotli decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already contain an
    ///   `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to `br`. The
    ///   request body is **not** automatically compressed.
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
    pub fn brotli(mut self, enable: bool) -> ClientBuilder {
        self.config.accept_encoding.brotli(enable);
        self
    }

    /// Enable auto zstd decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto zstd decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already contain an
    ///   `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to `zstd`.
    ///   The request body is **not** automatically compressed.
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
    pub fn zstd(mut self, enable: bool) -> ClientBuilder {
        self.config.accept_encoding.zstd(enable);
        self
    }

    /// Enable auto deflate decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto deflate decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already contain an
    ///   `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to
    ///   `deflate`. The request body is **not** automatically compressed.
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
    pub fn deflate(mut self, enable: bool) -> ClientBuilder {
        self.config.accept_encoding.deflate(enable);
        self
    }

    /// Disable auto response body zstd decompression.
    ///
    /// This method exists even if the optional `zstd` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use zstd decompression
    /// even if another dependency were to enable the optional `zstd` feature.
    #[inline]
    pub fn no_zstd(self) -> ClientBuilder {
        #[cfg(feature = "zstd")]
        {
            self.zstd(false)
        }

        #[cfg(not(feature = "zstd"))]
        {
            self
        }
    }

    /// Disable auto response body gzip decompression.
    ///
    /// This method exists even if the optional `gzip` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use gzip decompression
    /// even if another dependency were to enable the optional `gzip` feature.
    #[inline]
    pub fn no_gzip(self) -> ClientBuilder {
        #[cfg(feature = "gzip")]
        {
            self.gzip(false)
        }

        #[cfg(not(feature = "gzip"))]
        {
            self
        }
    }

    /// Disable auto response body brotli decompression.
    ///
    /// This method exists even if the optional `brotli` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use brotli decompression
    /// even if another dependency were to enable the optional `brotli` feature.
    #[inline]
    pub fn no_brotli(self) -> ClientBuilder {
        #[cfg(feature = "brotli")]
        {
            self.brotli(false)
        }

        #[cfg(not(feature = "brotli"))]
        {
            self
        }
    }

    /// Disable auto response body deflate decompression.
    ///
    /// This method exists even if the optional `deflate` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use deflate decompression
    /// even if another dependency were to enable the optional `deflate` feature.
    #[inline]
    pub fn no_deflate(self) -> ClientBuilder {
        #[cfg(feature = "deflate")]
        {
            self.deflate(false)
        }

        #[cfg(not(feature = "deflate"))]
        {
            self
        }
    }

    // Redirect options

    /// Set a `RedirectPolicy` for this client.
    ///
    /// Default will follow redirects up to a maximum of 10.
    #[inline]
    pub fn redirect(mut self, policy: redirect::Policy) -> ClientBuilder {
        self.config.redirect_policy = policy;
        self
    }

    /// Enable or disable automatic setting of the `Referer` header.
    ///
    /// Default is `true`.
    #[inline]
    pub fn referer(mut self, enable: bool) -> ClientBuilder {
        self.config.referer = enable;
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
    /// use wreq::{Client, Proxy};
    ///
    /// let proxy = Proxy::http("http://proxy:8080").unwrap();
    /// let client = Client::builder().proxy(proxy).build().unwrap();
    /// ```
    #[inline]
    pub fn proxy(mut self, proxy: Proxy) -> ClientBuilder {
        self.config.proxies.push(proxy.into_matcher());
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
        self.config.proxies.clear();
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

    /// Set a timeout for only the read phase of a `Client`.
    ///
    /// Default is `None`.
    #[inline]
    pub fn read_timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.config.timeout_options.read_timeout(timeout);
        self
    }

    /// Set a timeout for only the connect phase of a `Client`.
    ///
    /// Default is `None`.
    ///
    /// # Note
    ///
    /// This **requires** the futures be executed in a tokio runtime with
    /// a tokio timer enabled.
    #[inline]
    pub fn connect_timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.config.connect_timeout = Some(timeout);
        self
    }

    /// Set whether connections should emit verbose logs.
    ///
    /// Enabling this option will emit [log][] messages at the `TRACE` level
    /// for read and write operations on connections.
    ///
    /// [log]: https://crates.io/crates/log
    #[inline]
    pub fn connection_verbose(mut self, verbose: bool) -> ClientBuilder {
        self.config.connection_verbose = verbose;
        self
    }

    // HTTP options

    /// Set an optional timeout for idle sockets being kept-alive.
    ///
    /// Pass `None` to disable timeout.
    ///
    /// Default is 90 seconds.
    #[inline]
    pub fn pool_idle_timeout<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.pool_idle_timeout = val.into();
        self
    }

    /// Sets the maximum idle connection per host allowed in the pool.
    #[inline]
    pub fn pool_max_idle_per_host(mut self, max: usize) -> ClientBuilder {
        self.config.pool_max_idle_per_host = max;
        self
    }

    /// Sets the maximum number of connections in the pool.
    #[inline]
    pub fn pool_max_size(mut self, max: u32) -> ClientBuilder {
        self.config.pool_max_size = NonZeroU32::new(max);
        self
    }

    /// Disable keep-alive for the client.
    #[inline]
    pub fn no_keepalive(mut self) -> ClientBuilder {
        self.config.pool_max_idle_per_host = 0;
        self.config.tcp_keepalive = None;
        self
    }

    /// Only use HTTP/1.
    #[inline]
    pub fn http1_only(mut self) -> ClientBuilder {
        self.config.http_version_pref = HttpVersionPref::Http1;
        self
    }

    /// Only use HTTP/2.
    #[inline]
    pub fn http2_only(mut self) -> ClientBuilder {
        self.config.http_version_pref = HttpVersionPref::Http2;
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

    /// Sets the maximum number of safe retries for HTTP/2 connections.
    ///
    /// Default is 2.
    #[inline]
    pub fn http2_max_retry(mut self, max: usize) -> ClientBuilder {
        self.config.http2_max_retry = max;
        self
    }

    // TCP options

    /// Set whether sockets have `TCP_NODELAY` enabled.
    ///
    /// Default is `true`.
    #[inline]
    pub fn tcp_nodelay(mut self, enabled: bool) -> ClientBuilder {
        self.config.tcp_nodelay = enabled;
        self
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied duration.
    ///
    /// If `None`, the option will not be set.
    #[inline]
    pub fn tcp_keepalive<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.tcp_keepalive = val.into();
        self
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied interval.
    ///
    /// If `None`, the option will not be set.
    #[inline]
    pub fn tcp_keepalive_interval<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.tcp_keepalive_interval = val.into();
        self
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied retry count.
    ///
    /// If `None`, the option will not be set.
    #[inline]
    pub fn tcp_keepalive_retries<C>(mut self, retries: C) -> ClientBuilder
    where
        C: Into<Option<u32>>,
    {
        self.config.tcp_keepalive_retries = retries.into();
        self
    }

    /// Set that all sockets have `TCP_USER_TIMEOUT` set with the supplied duration.
    ///
    /// This option controls how long transmitted data may remain unacknowledged before
    /// the connection is force-closed.
    ///
    /// The current default is `None` (option disabled).
    #[inline]
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn tcp_user_timeout<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.tcp_user_timeout = val.into();
        self
    }

    /// Set whether sockets have `SO_REUSEADDR` enabled.
    #[inline]
    pub fn tcp_reuse_address(mut self, enabled: bool) -> ClientBuilder {
        self.config.tcp_reuse_address = enabled;
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
        self.config.tcp_send_buffer_size = size.into();
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
        self.config.tcp_recv_buffer_size = size.into();
        self
    }

    /// Set timeout for [RFC 6555 (Happy Eyeballs)][RFC 6555] algorithm.
    ///
    /// If hostname resolves to both IPv4 and IPv6 addresses and connection
    /// cannot be established using preferred address family before timeout
    /// elapses, then connector will in parallel attempt connection using other
    /// address family.
    ///
    /// If `None`, parallel connection attempts are disabled.
    ///
    /// Default is 300 milliseconds.
    ///
    /// [RFC 6555]: https://tools.ietf.org/html/rfc6555
    #[inline]
    pub fn tcp_happy_eyeballs_timeout<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.tcp_happy_eyeballs_timeout = val.into();
        self
    }

    /// Bind to a local IP Address.
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::IpAddr;
    /// let local_addr = IpAddr::from([12, 4, 1, 8]);
    /// let client = wreq::Client::builder()
    ///     .local_address(local_addr)
    ///     .build()
    ///     .unwrap();
    /// ```
    #[inline]
    pub fn local_address<T>(mut self, addr: T) -> ClientBuilder
    where
        T: Into<Option<IpAddr>>,
    {
        self.config
            .tcp_connect_options
            .get_or_insert_default()
            .set_local_address(addr.into());
        self
    }

    /// Set that all sockets are bound to the configured IPv4 or IPv6 address (depending on host's
    /// preferences) before connection.
    ///
    ///  # Example
    /// ///
    /// ```
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    /// let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
    /// let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    /// let client = wreq::Client::builder()
    ///     .local_addresses(ipv4, ipv6)
    ///     .build()
    ///     .unwrap();
    /// ```
    #[inline]
    pub fn local_addresses<V4, V6>(mut self, ipv4: V4, ipv6: V6) -> ClientBuilder
    where
        V4: Into<Option<Ipv4Addr>>,
        V6: Into<Option<Ipv6Addr>>,
    {
        self.config
            .tcp_connect_options
            .get_or_insert_default()
            .set_local_addresses(ipv4.into(), ipv6.into());
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
    /// # Example
    ///
    /// ```
    /// # fn doc() -> Result<(), wreq::Error> {
    /// let interface = "lo";
    /// let client = wreq::Client::builder()
    ///     .interface(interface)
    ///     .build()?;
    /// # Ok(())
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
    pub fn interface<T>(mut self, interface: T) -> ClientBuilder
    where
        T: Into<std::borrow::Cow<'static, str>>,
    {
        self.config
            .tcp_connect_options
            .get_or_insert_default()
            .set_interface(interface.into());
        self
    }

    // TLS options

    /// Sets the identity to be used for client certificate authentication.
    #[inline]
    pub fn identity(mut self, identity: Identity) -> ClientBuilder {
        self.config.identity = Some(identity);
        self
    }

    /// Sets the verify certificate store for the client.
    ///
    /// This method allows you to specify a custom verify certificate store to be used
    /// for TLS connections. By default, the system's verify certificate store is used.
    #[inline]
    pub fn cert_store(mut self, store: CertStore) -> ClientBuilder {
        self.config.cert_store = store;
        self
    }

    /// Controls the use of certificate validation.
    ///
    /// Defaults to `true`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If
    /// invalid certificates are trusted, *any* certificate for *any* site
    /// will be trusted for use. This includes expired certificates. This
    /// introduces significant vulnerabilities, and should only be used
    /// as a last resort.
    #[inline]
    pub fn cert_verification(mut self, cert_verification: bool) -> ClientBuilder {
        self.config.cert_verification = cert_verification;
        self
    }

    /// Configures the use of hostname verification when connecting.
    ///
    /// Defaults to `true`.
    /// # Warning
    ///
    /// You should think very carefully before you use this method. If hostname verification is not
    /// used, *any* valid certificate for *any* site will be trusted for use from any other. This
    /// introduces a significant vulnerability to man-in-the-middle attacks.
    #[inline]
    pub fn verify_hostname(mut self, verify_hostname: bool) -> ClientBuilder {
        self.config.verify_hostname = verify_hostname;
        self
    }

    /// Configures the use of Server Name Indication (SNI) when connecting.
    ///
    /// Defaults to `true`.
    #[inline]
    pub fn tls_sni(mut self, tls_sni: bool) -> ClientBuilder {
        self.config.tls_sni = tls_sni;
        self
    }

    /// Configures TLS key logging policy for the client.
    #[inline]
    pub fn keylog(mut self, policy: KeyLogPolicy) -> ClientBuilder {
        self.config.keylog_policy = Some(policy);
        self
    }

    /// Set the minimum required TLS version for connections.
    ///
    /// By default the TLS backend's own default is used.
    #[inline]
    pub fn min_tls_version(mut self, version: TlsVersion) -> ClientBuilder {
        self.config.min_tls_version = Some(version);
        self
    }

    /// Set the maximum allowed TLS version for connections.
    ///
    /// By default there's no maximum.
    #[inline]
    pub fn max_tls_version(mut self, version: TlsVersion) -> ClientBuilder {
        self.config.max_tls_version = Some(version);
        self
    }

    /// Add TLS information as `TlsInfo` extension to responses.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    #[inline]
    pub fn tls_info(mut self, tls_info: bool) -> ClientBuilder {
        self.config.tls_info = tls_info;
        self
    }

    // DNS options

    /// Disables the hickory-dns async resolver.
    ///
    /// This method exists even if the optional `hickory-dns` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use the hickory-dns async resolver
    /// even if another dependency were to enable the optional `hickory-dns` feature.
    #[inline]
    #[cfg(feature = "hickory-dns")]
    pub fn no_hickory_dns(mut self) -> ClientBuilder {
        self.config.hickory_dns = false;
        self
    }

    /// Override DNS resolution for specific domains to a particular IP address.
    ///
    /// Warning
    ///
    /// Since the DNS protocol has no notion of ports, if you wish to send
    /// traffic to a particular port you must include this port in the URL
    /// itself, any port in the overridden addr will be ignored and traffic sent
    /// to the conventional port for the given scheme (e.g. 80 for http).
    #[inline]
    pub fn resolve(self, domain: &str, addr: SocketAddr) -> ClientBuilder {
        self.resolve_to_addrs(domain, &[addr])
    }

    /// Override DNS resolution for specific domains to particular IP addresses.
    ///
    /// Warning
    ///
    /// Since the DNS protocol has no notion of ports, if you wish to send
    /// traffic to a particular port you must include this port in the URL
    /// itself, any port in the overridden addresses will be ignored and traffic sent
    /// to the conventional port for the given scheme (e.g. 80 for http).
    #[inline]
    pub fn resolve_to_addrs(mut self, domain: &str, addrs: &[SocketAddr]) -> ClientBuilder {
        self.config
            .dns_overrides
            .insert(domain.to_string(), addrs.to_vec());
        self
    }

    /// Override the DNS resolver implementation.
    ///
    /// Pass an `Arc` wrapping a trait object implementing `Resolve`.
    /// Overrides for specific names passed to `resolve` and `resolve_to_addrs` will
    /// still be applied on top of this resolver.
    #[inline]
    pub fn dns_resolver<R: Resolve + 'static>(mut self, resolver: Arc<R>) -> ClientBuilder {
        self.config.dns_resolver = Some(resolver as _);
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
    /// use std::time::Duration;
    ///
    /// let client = wreq::Client::builder()
    ///     .timeout(Duration::from_millis(200))
    ///     .layer(tower::timeout::TimeoutLayer::new(Duration::from_millis(50)))
    ///     .build()
    ///     .unwrap();
    /// ```
    #[inline]
    pub fn layer<L>(mut self, layer: L) -> ClientBuilder
    where
        L: Layer<BoxedClientService> + Clone + Send + Sync + 'static,
        L::Service: Service<HttpRequest<Body>, Response = HttpResponse<ResponseBody>, Error = BoxError>
            + Clone
            + Send
            + Sync
            + 'static,
        <L::Service as Service<HttpRequest<Body>>>::Future: Send + 'static,
    {
        let layer = BoxCloneSyncServiceLayer::new(layer);
        self.config.layers.push(layer);
        self
    }

    /// Adds a new Tower [`Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) to the
    /// base connector [`Service`](https://docs.rs/tower/latest/tower/trait.Service.html) which
    /// is responsible for connection establishment.a
    ///
    /// Each subsequent invocation of this function will wrap previous layers.
    ///
    /// If configured, the `connect_timeout` will be the outermost layer.
    ///
    /// Example usage:
    /// ```
    /// use std::time::Duration;
    ///
    /// let client = wreq::Client::builder()
    ///     // resolved to outermost layer, meaning while we are waiting on concurrency limit
    ///     .connect_timeout(Duration::from_millis(200))
    ///     // underneath the concurrency check, so only after concurrency limit lets us through
    ///     .connector_layer(tower::timeout::TimeoutLayer::new(Duration::from_millis(50)))
    ///     .connector_layer(tower::limit::concurrency::ConcurrencyLimitLayer::new(2))
    ///     .build()
    ///     .unwrap();
    /// ```
    #[inline]
    pub fn connector_layer<L>(mut self, layer: L) -> ClientBuilder
    where
        L: Layer<BoxedConnectorService> + Clone + Send + Sync + 'static,
        L::Service:
            Service<Unnameable, Response = Conn, Error = BoxError> + Clone + Send + Sync + 'static,
        <L::Service as Service<Unnameable>>::Future: Send + 'static,
    {
        let layer = BoxCloneSyncServiceLayer::new(layer);
        self.config.connector_layers.push(layer);
        self
    }

    // TLS/HTTP2 emulation options

    /// Configures the client builder to emulation the specified HTTP context.
    ///
    /// This method sets the necessary headers, HTTP/1 and HTTP/2 options configurations, and  TLS
    /// options config to use the specified HTTP context. It allows the client to mimic the
    /// behavior of different versions or setups, which can be useful for testing or ensuring
    /// compatibility with various environments.
    ///
    /// # Note
    /// This will overwrite the existing configuration.
    /// You must set emulation before you can perform subsequent HTTP1/HTTP2/TLS fine-tuning.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wreq::{
    ///     Client,
    ///     Emulation,
    /// };
    /// use wreq_util::Emulation;
    ///
    /// let client = Client::builder()
    ///     .emulation(Emulation::Firefox128)
    ///     .build()
    ///     .unwrap();
    /// ```
    #[inline]
    pub fn emulation<P>(mut self, factory: P) -> ClientBuilder
    where
        P: EmulationFactory,
    {
        let emulation = factory.emulation();
        let (transport_opts, headers, original_headers) = emulation.into_parts();

        if let Some((tls_opts, http1_opts, http2_opts)) =
            transport_opts.map(TransportOptions::into_parts)
        {
            self.config
                .transport_options
                .set_http1_options(http1_opts)
                .set_http2_options(http2_opts)
                .set_tls_options(tls_opts);
        }
        if let Some(headers) = headers {
            self = self.default_headers(headers);
        }
        if let Some(original_headers) = original_headers {
            self = self.original_headers(original_headers);
        }
        self
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Constructs a new `Client`.
    ///
    /// # Panics
    ///
    /// This method panics if a TLS backend cannot be initialized, or the resolver
    /// cannot load the system configuration.
    ///
    /// Use `Client::builder()` if you wish to handle the failure as an `Error`
    /// instead of panicking.
    #[inline]
    pub fn new() -> Client {
        ClientBuilder::new().build().expect("Client::new()")
    }

    /// Create a `ClientBuilder` specifically configured for WebSocket connections.
    ///
    /// This method configures the `ClientBuilder` to use HTTP/1.0 only, which is required for
    /// certain WebSocket connections.
    #[inline]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Convenience method to make a `GET` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    #[inline]
    pub fn get<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    /// Convenience method to make a `POST` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    #[inline]
    pub fn post<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    /// Convenience method to make a `PUT` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    #[inline]
    pub fn put<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    /// Convenience method to make a `PATCH` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    #[inline]
    pub fn patch<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    /// Convenience method to make a `DELETE` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    #[inline]
    pub fn delete<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    /// Convenience method to make a `HEAD` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    #[inline]
    pub fn head<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    /// Convenience method to make a `OPTIONS` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    #[inline]
    pub fn options<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::OPTIONS, url)
    }

    /// Start building a `Request` with the `Method` and `Url`.
    ///
    /// Returns a `RequestBuilder`, which will allow setting headers and
    /// the request body before sending.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn request<U: IntoUrl>(&self, method: Method, url: U) -> RequestBuilder {
        let req = url.into_url().map(move |url| Request::new(method, url));
        RequestBuilder::new(self.clone(), req)
    }

    /// Upgrades the [`RequestBuilder`] to perform a
    /// websocket handshake. This returns a wrapped type, so you must do
    /// this after you set up your request, and just before you send the
    /// request.
    #[inline]
    #[cfg(feature = "ws")]
    pub fn websocket<U: IntoUrl>(&self, url: U) -> WebSocketRequestBuilder {
        WebSocketRequestBuilder::new(self.request(Method::GET, url))
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
        match request.try_into() {
            Ok((url, req)) => {
                // Prepare the future request by ensuring we use the exact same Service instance
                // for both poll_ready and call.
                match *self.inner {
                    ClientRef::Boxed(ref service) => {
                        let fut = service.clone().oneshot(req);
                        Pending::boxed_request(url, fut)
                    }
                    ClientRef::Generic(ref service) => {
                        let fut = service.clone().oneshot(req);
                        Pending::generic_request(url, fut)
                    }
                }
            }
            Err(err) => Pending::error(err),
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
