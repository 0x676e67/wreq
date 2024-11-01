use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, convert::TryInto, net::SocketAddr};
use std::{fmt, str};

#[cfg(feature = "boring-tls")]
use boring::{error::ErrorStack, x509::store::X509Store};
use bytes::Bytes;
use http::header::{
    Entry, HeaderMap, HeaderValue, ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH,
    CONTENT_TYPE, LOCATION, PROXY_AUTHORIZATION, RANGE, REFERER, TRANSFER_ENCODING, USER_AGENT,
};
use http::uri::Scheme;
use http::{HeaderName, Uri};
use hyper::client::{HttpConnector, ResponseFuture as HyperResponseFuture};
#[cfg(feature = "boring-tls")]
use hyper::{PseudoOrder, SettingsOrder, StreamDependency, StreamId};
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::time::Sleep;

use super::decoder::Accepts;
use super::request::{Request, RequestBuilder};
use super::response::Response;
use super::Body;
use crate::connect::Connector;
#[cfg(feature = "cookies")]
use crate::cookie;
#[cfg(feature = "hickory-dns")]
use crate::dns::hickory::HickoryDnsResolver;
use crate::dns::{gai::GaiResolver, DnsResolverWithOverrides, DynResolver, Resolve};
use crate::error;
use crate::into_url::{expect_uri, try_uri};
use crate::redirect::{self, remove_sensitive_headers};
#[cfg(feature = "boring-tls")]
use crate::tls::{self, BoringTlsConnector, Impersonate, ImpersonateSettings, TlsSettings};
use crate::{IntoUrl, Method, Proxy, StatusCode, Url};
#[cfg(feature = "hickory-dns")]
use hickory_resolver::config::LookupIpStrategy;
use log::{debug, trace};

/// An asynchronous `Client` to make Requests with.
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

/// A `ClientBuilder` can be used to create a `Client` with custom configuration.
#[must_use]
pub struct ClientBuilder {
    config: Config,
}

/// A `HttpVersionPref` is used to set the HTTP version preference.
#[derive(Debug, Clone, Copy, Default)]
pub enum HttpVersionPref {
    /// Prefer HTTP/1.1
    Http1,
    /// Prefer HTTP/2
    Http2,
    /// Prefer HTTP/1 and HTTP/2
    #[default]
    All,
}

struct Config {
    // NOTE: When adding a new field, update `fmt::Debug for ClientBuilder`
    accepts: Accepts,
    headers: HeaderMap,
    headers_order: Option<&'static [HeaderName]>,
    connect_timeout: Option<Duration>,
    connection_verbose: bool,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: usize,
    tcp_keepalive: Option<Duration>,
    proxies: Vec<Proxy>,
    auto_sys_proxy: bool,
    redirect_policy: redirect::Policy,
    referer: bool,
    timeout: Option<Duration>,
    local_address_ipv6: Option<Ipv6Addr>,
    local_address_ipv4: Option<Ipv4Addr>,
    http1_title_case_headers: bool,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    interface: Option<String>,
    nodelay: bool,
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn cookie::CookieStore>>,
    hickory_dns: bool,
    error: Option<crate::Error>,
    dns_overrides: HashMap<String, Vec<SocketAddr>>,
    dns_resolver: Option<Arc<dyn Resolve>>,
    #[cfg(feature = "hickory-dns")]
    dns_strategy: Option<LookupIpStrategy>,
    builder: hyper::client::Builder,
    https_only: bool,
    #[cfg(feature = "boring-tls")]
    tls_info: bool,
    #[cfg(feature = "boring-tls")]
    tls: TlsSettings,
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
                accepts: Accepts::default(),
                headers: HeaderMap::with_capacity(1),
                headers_order: None,
                connect_timeout: None,
                connection_verbose: false,
                pool_idle_timeout: Some(Duration::from_secs(90)),
                pool_max_idle_per_host: usize::MAX,
                // TODO: Re-enable default duration once hyper's HttpConnector is fixed
                // to no longer error when an option fails.
                tcp_keepalive: None,
                proxies: Vec::new(),
                auto_sys_proxy: true,
                redirect_policy: redirect::Policy::none(),
                referer: true,
                timeout: None,
                local_address_ipv6: None,
                local_address_ipv4: None,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                interface: None,
                nodelay: true,
                hickory_dns: cfg!(feature = "hickory-dns"),
                #[cfg(feature = "hickory-dns")]
                dns_strategy: None,
                #[cfg(feature = "cookies")]
                cookie_store: None,
                dns_overrides: HashMap::new(),
                dns_resolver: None,
                builder: hyper::Client::builder(),
                https_only: false,
                #[cfg(feature = "boring-tls")]
                tls_info: false,
                #[cfg(feature = "boring-tls")]
                tls: Default::default(),
                http1_title_case_headers: true,
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
        let mut config = self.config;

        if let Some(err) = config.error {
            return Err(err);
        }

        let mut proxies = config.proxies;
        if config.auto_sys_proxy {
            proxies.push(Proxy::system());
        }
        let proxies = Arc::new(proxies);

        let proxies_maybe_http_auth = proxies.iter().any(|p| p.maybe_has_http_auth());

        let mut connector = {
            #[cfg(feature = "boring-tls")]
            fn user_agent(headers: &HeaderMap) -> Option<HeaderValue> {
                headers.get(USER_AGENT).cloned()
            }

            let mut resolver: Arc<dyn Resolve> = match config.hickory_dns {
                false => Arc::new(GaiResolver::new()),
                #[cfg(feature = "hickory-dns")]
                true => Arc::new(HickoryDnsResolver::new(config.dns_strategy)?),
                #[cfg(not(feature = "hickory-dns"))]
                true => unreachable!("hickory-dns shouldn't be enabled unless the feature is"),
            };
            if let Some(dns_resolver) = config.dns_resolver {
                resolver = dns_resolver;
            }
            if !config.dns_overrides.is_empty() {
                resolver = Arc::new(DnsResolverWithOverrides::new(
                    resolver,
                    config.dns_overrides,
                ));
            }
            let mut http = HttpConnector::new_with_resolver(DynResolver::new(resolver));
            http.set_connect_timeout(config.connect_timeout);

            #[cfg(feature = "boring-tls")]
            {
                Connector::new_boring_tls(
                    http,
                    BoringTlsConnector::new(config.tls)?,
                    proxies,
                    user_agent(&config.headers),
                    config.local_address_ipv4,
                    config.local_address_ipv6,
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    config.interface.as_deref(),
                    config.nodelay,
                    config.tls_info,
                )
            }

            #[cfg(not(feature = "boring-tls"))]
            {
                Connector::new(
                    http,
                    proxies.clone(),
                    config.local_address_ipv4,
                    config.local_address_ipv6,
                    config.nodelay,
                )
            }
        };

        connector.set_timeout(config.connect_timeout);
        connector.set_verbose(config.connection_verbose);
        connector.set_keepalive(config.tcp_keepalive);

        config
            .builder
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .http1_title_case_headers(config.http1_title_case_headers);

        Ok(Client {
            inner: Arc::new(ClientRef {
                accepts: config.accepts,
                #[cfg(feature = "cookies")]
                cookie_store: config.cookie_store,
                hyper: config.builder.build(connector),
                headers: config.headers,
                headers_order: config.headers_order,
                redirect_policy: Arc::new(config.redirect_policy),
                referer: config.referer,
                request_timeout: config.timeout,
                https_only: config.https_only,
                proxies_maybe_http_auth,
            }),
        })
    }

    /// Sets the necessary values to mimic the specified impersonate version.
    /// This will set the necessary headers and TLS settings.
    #[cfg(feature = "boring-tls")]
    pub fn impersonate(self, impersonate: Impersonate) -> ClientBuilder {
        self.configure_impersonate(impersonate, true)
    }

    /// Sets the necessary values to mimic the specified impersonate version (without headers).
    /// This will set the necessary headers and TLS settings.
    #[cfg(feature = "boring-tls")]
    pub fn impersonate_without_headers(self, impersonate: Impersonate) -> ClientBuilder {
        self.configure_impersonate(impersonate, false)
    }

    /// Use the preconfigured TLS settings.
    #[cfg(feature = "boring-tls")]
    pub fn use_preconfigured_tls(self, settings: ImpersonateSettings) -> ClientBuilder {
        self.apply_tls_settings(settings, true)
    }

    /// Private helper to configure impersonation.
    #[cfg(feature = "boring-tls")]
    fn configure_impersonate(self, impersonate: Impersonate, with_headers: bool) -> ClientBuilder {
        if let Ok(settings) = tls::tls_settings(impersonate) {
            return self.apply_tls_settings(settings, with_headers);
        }
        self
    }

    /// Apply the given TLS settings and header function.
    #[cfg(feature = "boring-tls")]
    fn apply_tls_settings(
        mut self,
        settings: ImpersonateSettings,
        set_headers: bool,
    ) -> ClientBuilder {
        if set_headers {
            if let Some(headers) = settings.headers {
                (headers)(&mut self.config.headers);
            }
        }
        self.config.tls = settings.tls;
        let http2_headers_priority = settings
            .http2
            .headers_priority
            .map(|(a, b, c)| StreamDependency::new(StreamId::from(a), b, c));

        // Set the http2 version preference
        self.http2_initial_stream_window_size(settings.http2.initial_stream_window_size)
            .http2_initial_connection_window_size(settings.http2.initial_connection_window_size)
            .http2_max_concurrent_streams(settings.http2.max_concurrent_streams)
            .http2_max_header_list_size(settings.http2.max_header_list_size)
            .http2_header_table_size(settings.http2.header_table_size)
            .http2_enable_push(settings.http2.enable_push)
            .http2_max_frame_size(settings.http2.max_frame_size)
            .http2_headers_priority(http2_headers_priority)
            .http2_headers_pseudo_order(settings.http2.headers_pseudo_order)
            .http2_settings_order(settings.http2.settings_order)
            .http2_unknown_setting8(settings.http2.unknown_setting8)
            .http2_unknown_setting9(settings.http2.unknown_setting9)
    }

    /// Enable Encrypted Client Hello (Secure SNI)
    #[cfg(feature = "boring-tls")]
    pub fn enable_ech_grease(mut self, enabled: bool) -> ClientBuilder {
        self.config.tls.enable_ech_grease = enabled;
        self
    }

    /// Enable TLS permute_extensions
    #[cfg(feature = "boring-tls")]
    pub fn permute_extensions(mut self, enabled: bool) -> ClientBuilder {
        self.config.tls.permute_extensions = enabled;
        self
    }

    /// Enable TLS pre_shared_key
    #[cfg(feature = "boring-tls")]
    pub fn pre_shared_key(mut self, enabled: bool) -> ClientBuilder {
        self.config.tls.pre_shared_key = enabled;
        self
    }

    // Higher-level options

    /// Sets the `User-Agent` header to be used by this client.
    ///
    /// # Example
    ///
    /// ```rust
    /// # async fn doc() -> Result<(), rquest::Error> {
    /// // Name your user agent after your app?
    /// static APP_USER_AGENT: &str = concat!(
    ///     env!("CARGO_PKG_NAME"),
    ///     "/",
    ///     env!("CARGO_PKG_VERSION"),
    /// );
    ///
    /// let client = rquest::Client::builder()
    ///     .user_agent(APP_USER_AGENT)
    ///     .build()?;
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
            Err(e) => {
                self.config.error = Some(crate::error::builder(e.into()));
            }
        };
        self
    }

    /// Sets the default headers for every request.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rquest::header;
    /// # async fn doc() -> Result<(), rquest::Error> {
    /// let mut headers = header::HeaderMap::new();
    /// headers.insert("X-MY-HEADER", header::HeaderValue::from_static("value"));
    ///
    /// // Consider marking security-sensitive headers with `set_sensitive`.
    /// let mut auth_value = header::HeaderValue::from_static("secret");
    /// auth_value.set_sensitive(true);
    /// headers.insert(header::AUTHORIZATION, auth_value);
    ///
    /// // get a client builder
    /// let client = rquest::Client::builder()
    ///     .default_headers(headers)
    ///     .build()?;
    /// let res = client.get("https://www.rust-lang.org").send().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Override the default headers:
    ///
    /// ```rust
    /// use rquest::header;
    /// # async fn doc() -> Result<(), rquest::Error> {
    /// let mut headers = header::HeaderMap::new();
    /// headers.insert("X-MY-HEADER", header::HeaderValue::from_static("value"));
    ///
    /// // get a client builder
    /// let client = rquest::Client::builder()
    ///     .default_headers(headers)
    ///     .build()?;
    /// let res = client
    ///     .get("https://www.rust-lang.org")
    ///     .header("X-MY-HEADER", "new_value")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn default_headers(mut self, headers: HeaderMap) -> ClientBuilder {
        for (key, value) in headers.iter() {
            self.config.headers.insert(key, value.clone());
        }
        self
    }

    /// Change the order in which headers will be sent
    ///
    /// Warning
    ///
    /// The host header needs to be manually inserted if you want to modify its order.
    /// Otherwise it will be inserted by hyper after sorting.
    pub fn headers_order(mut self, order: &'static [HeaderName]) -> ClientBuilder {
        self.config.headers_order = Some(order);
        self
    }

    /// Default accpet
    pub fn default_accpet(mut self) -> ClientBuilder {
        self.config
            .headers
            .insert(ACCEPT, HeaderValue::from_static("*/*"));
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
    #[cfg(feature = "cookies")]
    #[cfg_attr(docsrs, doc(cfg(feature = "cookies")))]
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
    /// - When sending a request and if the request's headers do not already contain
    ///   an `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to `gzip`.
    ///   The request body is **not** automatically compressed.
    /// - When receiving a response, if its headers contain a `Content-Encoding` value of
    ///   `gzip`, both `Content-Encoding` and `Content-Length` are removed from the
    ///   headers' set. The response body is automatically decompressed.
    ///
    /// If the `gzip` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `gzip` feature to be enabled
    #[cfg(feature = "gzip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gzip")))]
    pub fn gzip(mut self, enable: bool) -> ClientBuilder {
        self.config.accepts.gzip = enable;
        self
    }

    /// Enable auto brotli decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto brotli decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already contain
    ///   an `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to `br`.
    ///   The request body is **not** automatically compressed.
    /// - When receiving a response, if its headers contain a `Content-Encoding` value of
    ///   `br`, both `Content-Encoding` and `Content-Length` are removed from the
    ///   headers' set. The response body is automatically decompressed.
    ///
    /// If the `brotli` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `brotli` feature to be enabled
    #[cfg(feature = "brotli")]
    #[cfg_attr(docsrs, doc(cfg(feature = "brotli")))]
    pub fn brotli(mut self, enable: bool) -> ClientBuilder {
        self.config.accepts.brotli = enable;
        self
    }

    /// Enable auto zstd decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto zstd decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already contain
    ///   an `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to `zstd`.
    ///   The request body is **not** automatically compressed.
    /// - When receiving a response, if its headers contain a `Content-Encoding` value of
    ///   `zstd`, both `Content-Encoding` and `Content-Length` are removed from the
    ///   headers' set. The response body is automatically decompressed.
    ///
    /// If the `zstd` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `zstd` feature to be enabled
    #[cfg(feature = "zstd")]
    #[cfg_attr(docsrs, doc(cfg(feature = "zstd")))]
    pub fn zstd(mut self, enable: bool) -> ClientBuilder {
        self.config.accepts.zstd = enable;
        self
    }

    /// Enable auto deflate decompression by checking the `Content-Encoding` response header.
    ///
    /// If auto deflate decompression is turned on:
    ///
    /// - When sending a request and if the request's headers do not already contain
    ///   an `Accept-Encoding` **and** `Range` values, the `Accept-Encoding` header is set to `deflate`.
    ///   The request body is **not** automatically compressed.
    /// - When receiving a response, if it's headers contain a `Content-Encoding` value that
    ///   equals to `deflate`, both values `Content-Encoding` and `Content-Length` are removed from the
    ///   headers' set. The response body is automatically decompressed.
    ///
    /// If the `deflate` feature is turned on, the default option is enabled.
    ///
    /// # Optional
    ///
    /// This requires the optional `deflate` feature to be enabled
    #[cfg(feature = "deflate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
    pub fn deflate(mut self, enable: bool) -> ClientBuilder {
        self.config.accepts.deflate = enable;
        self
    }

    /// Disable auto response body zstd decompression.
    ///
    /// This method exists even if the optional `zstd` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use zstd decompression
    /// even if another dependency were to enable the optional `zstd` feature.
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
    pub fn redirect(mut self, policy: redirect::Policy) -> ClientBuilder {
        self.config.redirect_policy = policy;
        self
    }

    /// Enable or disable automatic setting of the `Referer` header.
    ///
    /// Default is `true`.
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
    pub fn proxy(mut self, proxy: Proxy) -> ClientBuilder {
        self.config.proxies.push(proxy);
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
    pub fn timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.config.timeout = Some(timeout);
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
    pub fn pool_idle_timeout<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.pool_idle_timeout = val.into();
        self
    }

    /// Sets the maximum idle connection per host allowed in the pool.
    pub fn pool_max_idle_per_host(mut self, max: usize) -> ClientBuilder {
        self.config.pool_max_idle_per_host = max;
        self
    }

    /// Send headers as title case instead of lowercase.
    pub fn http1_title_case_headers(mut self, enabled: bool) -> ClientBuilder {
        self.config.http1_title_case_headers = enabled;
        self
    }

    /// Set whether HTTP/1 connections will accept obsolete line folding for
    /// header values.
    ///
    /// Newline codepoints (`\r` and `\n`) will be transformed to spaces when
    /// parsing.
    pub fn http1_allow_obsolete_multiline_headers_in_responses(
        mut self,
        value: bool,
    ) -> ClientBuilder {
        self.config
            .builder
            .http1_allow_obsolete_multiline_headers_in_responses(value);
        self
    }

    /// Sets whether invalid header lines should be silently ignored in HTTP/1 responses.
    pub fn http1_ignore_invalid_headers_in_responses(mut self, value: bool) -> ClientBuilder {
        self.config
            .builder
            .http1_ignore_invalid_headers_in_responses(value);
        self
    }

    /// Set whether HTTP/1 connections will accept spaces between header
    /// names and the colon that follow them in responses.
    ///
    /// Newline codepoints (`\r` and `\n`) will be transformed to spaces when
    /// parsing.
    pub fn http1_allow_spaces_after_header_name_in_responses(
        mut self,
        value: bool,
    ) -> ClientBuilder {
        self.config
            .builder
            .http1_allow_spaces_after_header_name_in_responses(value);
        self
    }

    /// Only use HTTP/1.
    /// Default is Http/1.
    pub fn http1_only(mut self) -> ClientBuilder {
        #[cfg(feature = "boring-tls")]
        {
            self.config.tls.http_version_pref = HttpVersionPref::Http1;
        }

        self.config.builder.http2_only(false);
        self
    }

    /// Allow HTTP/0.9 responses
    pub fn http09_responses(mut self) -> ClientBuilder {
        self.config.builder.http09_responses(true);
        self
    }

    /// Only use HTTP/2.
    pub fn http2_only(mut self) -> ClientBuilder {
        #[cfg(feature = "boring-tls")]
        {
            self.config.tls.http_version_pref = HttpVersionPref::Http2;
        }

        self.config.builder.http2_only(true);
        self
    }

    /// Sets the `SETTINGS_INITIAL_WINDOW_SIZE` option for HTTP2 stream-level flow control.
    ///
    /// Default is currently 65,535 but may change internally to optimize for common uses.
    pub fn http2_initial_stream_window_size(mut self, sz: impl Into<Option<u32>>) -> ClientBuilder {
        self.config
            .builder
            .http2_initial_stream_window_size(sz.into());
        self
    }

    /// Sets the max connection-level flow control for HTTP2
    ///
    /// Default is currently 65,535 but may change internally to optimize for common uses.
    pub fn http2_initial_connection_window_size(
        mut self,
        sz: impl Into<Option<u32>>,
    ) -> ClientBuilder {
        self.config
            .builder
            .http2_initial_connection_window_size(sz.into());
        self
    }

    /// Sets whether to use an adaptive flow control.
    ///
    /// Enabling this will override the limits set in `http2_initial_stream_window_size` and
    /// `http2_initial_connection_window_size`.
    pub fn http2_adaptive_window(mut self, enabled: bool) -> ClientBuilder {
        self.config.builder.http2_adaptive_window(enabled);
        self
    }

    /// Sets the maximum frame size to use for HTTP2.
    ///
    /// Default is currently 16,384 but may change internally to optimize for common uses.
    pub fn http2_max_frame_size(mut self, sz: impl Into<Option<u32>>) -> ClientBuilder {
        self.config.builder.http2_max_frame_size(sz.into());
        self
    }

    /// Sets the maximum concurrent streams to use for HTTP2.
    ///
    /// Passing `None` will do nothing.
    pub fn http2_max_concurrent_streams(mut self, sz: impl Into<Option<u32>>) -> ClientBuilder {
        if let Some(max) = sz.into() {
            self.config.builder.http2_max_concurrent_streams(max);
        }
        self
    }

    /// Sets the max header list size to use for HTTP2.
    ///
    /// Passing `None` will do nothing.
    pub fn http2_max_header_list_size(mut self, sz: impl Into<Option<u32>>) -> ClientBuilder {
        if let Some(sz) = sz.into() {
            self.config.builder.http2_max_header_list_size(sz);
        }
        self
    }

    /// Enables and disables the push feature for HTTP2.
    ///
    /// Passing `None` will do nothing.
    pub fn http2_enable_push(mut self, sz: impl Into<Option<bool>>) -> ClientBuilder {
        if let Some(sz) = sz.into() {
            self.config.builder.http2_enable_push(sz);
        }
        self
    }

    /// Http2 unknown_setting8
    pub fn http2_unknown_setting8(mut self, sz: impl Into<Option<bool>>) -> ClientBuilder {
        if let Some(sz) = sz.into() {
            self.config.builder.http2_unknown_setting8(sz);
        }
        self
    }

    /// Http2 unknown_setting9
    pub fn http2_unknown_setting9(mut self, sz: impl Into<Option<bool>>) -> ClientBuilder {
        if let Some(sz) = sz.into() {
            self.config.builder.http2_unknown_setting9(sz);
        }
        self
    }

    /// Sets the header table size to use for HTTP2.
    ///
    /// Passing `None` will do nothing.
    pub fn http2_header_table_size(mut self, sz: impl Into<Option<u32>>) -> ClientBuilder {
        if let Some(sz) = sz.into() {
            self.config.builder.http2_header_table_size(sz);
        }
        self
    }

    /// Sets the pseudo header order for HTTP2.
    /// This is an array of 4 elements, each element is a `PseudoOrder` enum.
    /// Default is `None`.
    pub fn http2_headers_pseudo_order(
        mut self,
        order: impl Into<Option<[PseudoOrder; 4]>>,
    ) -> ClientBuilder {
        self.config.builder.http2_headers_pseudo_order(order.into());
        self
    }

    /// Sets the priority for HTTP2 headers.
    /// Default is `None`.
    pub fn http2_headers_priority(
        mut self,
        priority: impl Into<Option<StreamDependency>>,
    ) -> ClientBuilder {
        self.config.builder.http2_headers_priority(priority.into());
        self
    }

    /// Sets the settings order for HTTP2.
    /// This is an array of 2 elements, each element is a `SettingsOrder` enum.
    /// Default is `None`.
    pub fn http2_settings_order(
        mut self,
        order: impl Into<Option<[SettingsOrder; 8]>>,
    ) -> ClientBuilder {
        self.config.builder.http2_settings_order(order.into());
        self
    }

    /// Sets an interval for HTTP2 Ping frames should be sent to keep a connection alive.
    ///
    /// Pass `None` to disable HTTP2 keep-alive.
    /// Default is currently disabled.
    pub fn http2_keep_alive_interval(
        mut self,
        interval: impl Into<Option<Duration>>,
    ) -> ClientBuilder {
        self.config
            .builder
            .http2_keep_alive_interval(interval.into());
        self
    }

    /// Sets a timeout for receiving an acknowledgement of the keep-alive ping.
    ///
    /// If the ping is not acknowledged within the timeout, the connection will be closed.
    /// Does nothing if `http2_keep_alive_interval` is disabled.
    /// Default is currently disabled.
    pub fn http2_keep_alive_timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.config.builder.http2_keep_alive_timeout(timeout);
        self
    }

    /// Sets whether HTTP2 keep-alive should apply while the connection is idle.
    ///
    /// If disabled, keep-alive pings are only sent while there are open request/responses streams.
    /// If enabled, pings are also sent when no streams are active.
    /// Does nothing if `http2_keep_alive_interval` is disabled.
    /// Default is `false`.
    pub fn http2_keep_alive_while_idle(mut self, enabled: bool) -> ClientBuilder {
        self.config.builder.http2_keep_alive_while_idle(enabled);
        self
    }

    // TCP options

    /// Set whether sockets have `TCP_NODELAY` enabled.
    ///
    /// Default is `true`.
    pub fn tcp_nodelay(mut self, enabled: bool) -> ClientBuilder {
        self.config.nodelay = enabled;
        self
    }

    /// Bind to a local IP Address.
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::IpAddr;
    /// let local_addr = IpAddr::from([12, 4, 1, 8]);
    /// let client = rquest::Client::builder()
    ///     .local_address(local_addr)
    ///     .build().unwrap();
    /// ```
    pub fn local_address<T>(mut self, addr: T) -> ClientBuilder
    where
        T: Into<Option<IpAddr>>,
    {
        match addr.into() {
            Some(IpAddr::V4(v4)) => {
                self.config.local_address_ipv4 = Some(v4);
            }
            Some(IpAddr::V6(v6)) => {
                self.config.local_address_ipv6 = Some(v6);
            }
            _ => {}
        }
        self
    }

    /// Set that all sockets are bound to the configured IPv4 or IPv6 address (depending on host's
    /// preferences) before connection.
    pub fn local_addresses(mut self, addr_ipv4: Ipv4Addr, addr_ipv6: Ipv6Addr) -> ClientBuilder {
        self.config.local_address_ipv4 = Some(addr_ipv4);
        self.config.local_address_ipv6 = Some(addr_ipv6);
        self
    }

    /// Bind to an interface by `SO_BINDTODEVICE`.
    ///
    /// # Example
    ///
    /// ```
    /// let interface = "lo";
    /// let client = reqwest::Client::builder()
    ///     .interface(interface)
    ///     .build().unwrap();
    /// ```
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn interface(mut self, interface: &str) -> ClientBuilder {
        self.config.interface = Some(interface.to_string());
        self
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied duration.
    ///
    /// If `None`, the option will not be set.
    pub fn tcp_keepalive<D>(mut self, val: D) -> ClientBuilder
    where
        D: Into<Option<Duration>>,
    {
        self.config.tcp_keepalive = val.into();
        self
    }

    /// Controls the use of certificate validation.
    ///
    /// Defaults to `false`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If
    /// invalid certificates are trusted, *any* certificate for *any* site
    /// will be trusted for use. This includes expired certificates. This
    /// introduces significant vulnerabilities, and should only be used
    /// as a last resort.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    #[cfg(feature = "boring-tls")]
    pub fn danger_accept_invalid_certs(mut self, accept_invalid_certs: bool) -> ClientBuilder {
        self.config.tls.certs_verification = !accept_invalid_certs;
        self
    }

    /// Controls the use of TLS server name indication.
    ///
    /// Defaults to `true`.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    #[cfg(feature = "boring-tls")]
    pub fn tls_sni(mut self, tls_sni: bool) -> ClientBuilder {
        self.config.tls.tls_sni = tls_sni;
        self
    }

    /// Set the minimum required TLS version for connections.
    ///
    /// By default the TLS backend's own default is used.
    ///
    /// # Errors
    ///
    /// A value of `tls::Version::TLS_1_3` will cause an error with the
    /// `native-tls`/`default-tls` backend. This does not mean the version
    /// isn't supported, just that it can't be set as a minimum due to
    /// technical limitations.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    #[cfg(feature = "boring-tls")]
    pub fn min_tls_version(mut self, version: tls::Version) -> ClientBuilder {
        self.config.tls.min_tls_version = Some(version);
        self
    }

    /// Set the maximum allowed TLS version for connections.
    ///
    /// By default there's no maximum.
    ///
    /// # Errors
    ///
    /// A value of `tls::Version::TLS_1_3` will cause an error with the
    /// `native-tls`/`default-tls` backend. This does not mean the version
    /// isn't supported, just that it can't be set as a maximum due to
    /// technical limitations.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    #[cfg(feature = "boring-tls")]
    pub fn max_tls_version(mut self, version: tls::Version) -> ClientBuilder {
        self.config.tls.max_tls_version = Some(version);
        self
    }

    /// Add TLS information as `TlsInfo` extension to responses.
    ///
    /// # Optional
    ///
    /// feature to be enabled.
    #[cfg(feature = "boring-tls")]
    pub fn tls_info(mut self, tls_info: bool) -> ClientBuilder {
        self.config.tls_info = tls_info;
        self
    }

    /// Restrict the Client to be used with HTTPS only requests.
    ///
    /// Defaults to false.
    pub fn https_only(mut self, enabled: bool) -> ClientBuilder {
        self.config.https_only = enabled;
        self
    }

    /// Set CA certificate store.
    #[cfg(feature = "boring-tls")]
    pub fn ca_cert_store<F>(mut self, store: F) -> ClientBuilder
    where
        F: Fn() -> Result<X509Store, ErrorStack> + Send + Sync + 'static,
    {
        self.config.tls.ca_cert_store = Some(Box::new(store));
        self
    }

    /// Enables the `hickory-dns` asynchronous resolver instead of the default threadpool-based `getaddrinfo`.
    ///
    /// By default, if the `hickory-dns` feature is enabled, this option is used.
    ///
    /// # Optional
    ///
    /// Requires the `hickory-dns` feature to be enabled.
    #[cfg(feature = "hickory-dns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hickory-dns")))]
    pub fn hickory_dns_strategy(mut self, strategy: LookupIpStrategy) -> ClientBuilder {
        self.config.dns_strategy = Some(strategy);
        self
    }

    /// Disables the hickory-dns async resolver.
    ///
    /// This method exists even if the optional `hickory-dns` feature is not enabled.
    /// This can be used to ensure a `Client` doesn't use the hickory-dns async resolver
    /// even if another dependency were to enable the optional `hickory-dns` feature.
    #[cfg(feature = "hickory-dns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hickory-dns")))]
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
    pub fn dns_resolver<R: Resolve + 'static>(mut self, resolver: Arc<R>) -> ClientBuilder {
        self.config.dns_resolver = Some(resolver as _);
        self
    }
}

type HyperClient = hyper::Client<Connector, super::body::ImplStream>;

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
    pub fn new() -> Client {
        ClientBuilder::new().build().expect("Client::new()")
    }

    /// Create a `ClientBuilder` specifically configured for WebSocket connections.
    ///
    /// This method configures the `ClientBuilder` to use HTTP/1.0 only, which is required for certain WebSocket connections.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Convenience method to make a `GET` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn get<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    /// Upgrades the [`RequestBuilder`] to perform a
    /// websocket handshake. This returns a wrapped type, so you must do
    /// this after you set up your request, and just before you send the
    /// request.
    #[cfg(feature = "websocket")]
    pub fn websocket<U: IntoUrl>(&self, url: U) -> crate::WebSocketRequestBuilder {
        crate::WebSocketRequestBuilder::new(self.request(Method::GET, url))
    }

    /// Convenience method to make a `POST` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn post<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    /// Convenience method to make a `PUT` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn put<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    /// Convenience method to make a `PATCH` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn patch<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    /// Convenience method to make a `DELETE` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn delete<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    /// Convenience method to make a `HEAD` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn head<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::HEAD, url)
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
    pub fn execute(
        &self,
        request: Request,
    ) -> impl Future<Output = Result<Response, crate::Error>> {
        self.execute_request(request)
    }

    pub(super) fn execute_request(&self, req: Request) -> Pending {
        let (method, url, mut headers, body, timeout, version) = req.pieces();
        if url.scheme() != "http"
            && url.scheme() != "https"
            && url.scheme() != "ws"
            && url.scheme() != "wss"
        {
            return Pending::new_err(error::url_bad_scheme(url));
        }

        // check if we're in https_only mode and check the scheme of the current URL
        if self.inner.https_only && url.scheme() != "https" && url.scheme() != "wss" {
            return Pending::new_err(error::url_bad_scheme(url));
        }

        // insert default headers in the request headers
        // without overwriting already appended headers.
        for (key, value) in &self.inner.headers {
            if let Entry::Vacant(entry) = headers.entry(key) {
                entry.insert(value.clone());
            }
        }

        // Add cookies from the cookie store.
        #[cfg(feature = "cookies")]
        {
            if let Some(cookie_store) = self.inner.cookie_store.as_ref() {
                if headers.get(crate::header::COOKIE).is_none() {
                    add_cookie_header(&mut headers, &**cookie_store, &url);
                }
            }
        }

        let accept_encoding = self.inner.accepts.as_str();

        if let Some(accept_encoding) = accept_encoding {
            if !headers.contains_key(ACCEPT_ENCODING) && !headers.contains_key(RANGE) {
                headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(accept_encoding));
            }
        }

        let uri = expect_uri(&url);

        let (reusable, body) = match body {
            Some(body) => {
                let (reusable, body) = body.try_reuse();
                (Some(reusable), body)
            }
            None => (None, Body::empty()),
        };

        self.proxy_auth(&uri, &mut headers);

        // Insert headers in order if enabled
        if let Some(headers_order) = self.inner.headers_order {
            let mut sorted_headers = HeaderMap::with_capacity(headers.keys_len());

            // First insert headers in the specified order
            for key in headers_order {
                if let Some(value) = headers.remove(key) {
                    sorted_headers.insert(key, value);
                }
            }

            // Then insert any remaining headers that were not ordered
            for (key, value) in headers.drain() {
                if let Some(key) = key {
                    sorted_headers.insert(key, value);
                }
            }

            headers = sorted_headers;
        }

        let builder = hyper::Request::builder()
            .method(method.clone())
            .uri(uri)
            .version(version);

        let in_flight = {
            let mut req = builder
                .body(body.into_stream())
                .expect("valid request parts");
            *req.headers_mut() = headers.clone();
            ResponseFuture::Default(self.inner.hyper.request(req))
        };

        let timeout = timeout
            .or(self.inner.request_timeout)
            .map(tokio::time::sleep)
            .map(Box::pin);

        Pending {
            inner: PendingInner::Request(PendingRequest {
                method,
                url,
                headers,
                body: reusable,
                urls: Vec::new(),
                retry_count: 0,
                client: self.inner.clone(),
                in_flight,
                timeout,
            }),
        }
    }

    fn proxy_auth(&self, dst: &Uri, headers: &mut HeaderMap) {
        if !self.inner.proxies_maybe_http_auth {
            return;
        }

        // Only set the header here if the destination scheme is 'http',
        // since otherwise, the header will be included in the CONNECT tunnel
        // request instead.
        if dst.scheme() != Some(&Scheme::HTTP) {
            return;
        }

        if headers.contains_key(PROXY_AUTHORIZATION) {
            return;
        }

        for proxy in self.inner.hyper.get_proxies().iter() {
            if proxy.is_match(dst) {
                if let Some(header) = proxy.http_basic_auth(dst) {
                    headers.insert(PROXY_AUTHORIZATION, header);
                }

                break;
            }
        }
    }

    /// Get the client user agent
    pub fn user_agent(&self) -> Option<&HeaderValue> {
        self.inner.headers.get(USER_AGENT)
    }

    /// Returns a `String` of the header-value of all `Cookie` in a `Url`.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error parsing the cookies.
    #[cfg(feature = "cookies")]
    pub fn get_cookies<U: IntoUrl>(&self, url: U) -> Result<Option<String>, error::Error> {
        // Parse the URL
        let target_url = url.into_url()?;

        // Check if the cookie_store is set
        let result = self
            .inner
            .cookie_store
            .as_ref()
            .and_then(|cookie_store| cookie_store.cookies(&target_url))
            .and_then(|header| header.to_str().map(ToOwned::to_owned).ok());

        Ok(result)
    }

    /// Injects a 'Cookie' into the 'CookieStore' for the specified URL.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error parsing the cookies.
    #[cfg(feature = "cookies")]
    pub fn set_cookies<U: IntoUrl>(
        &self,
        cookies: Vec<HeaderValue>,
        url: U,
    ) -> Result<(), error::Error> {
        // Parse the URL
        let target_url = url.into_url()?;

        // Check if the cookie_store is set
        if let Some(cookie_store) = &self.inner.cookie_store {
            let mut iter = cookies.iter();
            cookie_store.set_cookies(&mut iter, &target_url);
        }

        Ok(())
    }

    /// Set the proxies for this client.
    #[inline]
    pub fn set_proxies(&mut self, proxies: &[Proxy]) {
        Arc::make_mut(&mut self.inner).hyper.set_proxies(proxies);
        self.inner.hyper.reset_pool_idle();
    }

    /// Set that all sockets are bound to the configured address before connection.
    ///
    /// If `None`, the sockets will not be bound.
    ///
    /// Default is `None`.
    #[inline]
    pub fn set_local_address<T>(&mut self, addr: T)
    where
        T: Into<Option<IpAddr>>,
    {
        Arc::make_mut(&mut self.inner)
            .hyper
            .set_local_address(addr.into());
        self.inner.hyper.reset_pool_idle();
    }

    /// Set that all sockets are bound to the configured IPv4 or IPv6 address (depending on host's
    /// preferences) before connection.
    #[inline]
    pub fn set_local_addresses(&mut self, addr_ipv4: Ipv4Addr, addr_ipv6: Ipv6Addr) {
        Arc::make_mut(&mut self.inner)
            .hyper
            .set_local_addresses(addr_ipv4, addr_ipv6);
        self.inner.hyper.reset_pool_idle();
    }

    /// Bind to an interface by `SO_BINDTODEVICE`.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[inline]
    pub fn set_interface(&mut self, interface: &str) {
        Arc::make_mut(&mut self.inner)
            .hyper
            .set_interface(interface);
        self.inner.hyper.reset_pool_idle();
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("Client");
        self.inner.fmt_fields(&mut builder);
        builder.finish()
    }
}

impl tower_service::Service<Request> for Client {
    type Response = Response;
    type Error = crate::Error;
    type Future = Pending;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        self.execute_request(req)
    }
}

impl tower_service::Service<Request> for &'_ Client {
    type Response = Response;
    type Error = crate::Error;
    type Future = Pending;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        self.execute_request(req)
    }
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("ClientBuilder");
        self.config.fmt_fields(&mut builder);
        builder.finish()
    }
}

impl Config {
    fn fmt_fields(&self, f: &mut fmt::DebugStruct<'_, '_>) {
        // Instead of deriving Debug, only print fields when their output
        // would provide relevant or interesting data.

        #[cfg(feature = "cookies")]
        {
            if let Some(_) = self.cookie_store {
                f.field("cookie_store", &true);
            }
        }

        f.field("accepts", &self.accepts);

        if !self.proxies.is_empty() {
            f.field("proxies", &self.proxies);
        }

        if !self.redirect_policy.is_default() {
            f.field("redirect_policy", &self.redirect_policy);
        }

        if self.referer {
            f.field("referer", &true);
        }

        f.field("default_headers", &self.headers);

        if let Some(ref d) = self.connect_timeout {
            f.field("connect_timeout", d);
        }

        if let Some(ref d) = self.timeout {
            f.field("timeout", d);
        }

        if let Some(ref v) = self.local_address_ipv4 {
            f.field("local_address_4", v);
        }

        if let Some(ref v) = self.local_address_ipv6 {
            f.field("local_address_6", v);
        }

        if self.nodelay {
            f.field("tcp_nodelay", &true);
        }

        #[cfg(feature = "boring-tls")]
        {
            if !self.tls.certs_verification {
                f.field("danger_accept_invalid_certs", &true);
            }

            f.field("tls_info", &self.tls_info);
        }

        if self.https_only {
            f.field("https_only", &true);
        }

        if !self.dns_overrides.is_empty() {
            f.field("dns_overrides", &self.dns_overrides);
        }

        f.field("builder", &self.builder);
    }
}

#[derive(Clone)]
struct ClientRef {
    accepts: Accepts,
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn cookie::CookieStore>>,
    headers: HeaderMap,
    headers_order: Option<&'static [HeaderName]>,
    hyper: HyperClient,
    redirect_policy: Arc<redirect::Policy>,
    referer: bool,
    request_timeout: Option<Duration>,
    proxies_maybe_http_auth: bool,
    https_only: bool,
}

impl ClientRef {
    fn fmt_fields(&self, f: &mut fmt::DebugStruct<'_, '_>) {
        // Instead of deriving Debug, only print fields when their output
        // would provide relevant or interesting data.

        #[cfg(feature = "cookies")]
        {
            if let Some(_) = self.cookie_store {
                f.field("cookie_store", &true);
            }
        }

        f.field("accepts", &self.accepts);

        let proxies = self.hyper.get_proxies();
        if !proxies.is_empty() {
            f.field("proxies", &proxies);
        }

        if !self.redirect_policy.is_default() {
            f.field("redirect_policy", &self.redirect_policy);
        }

        if self.referer {
            f.field("referer", &true);
        }

        f.field("default_headers", &self.headers);

        if let Some(ref d) = self.request_timeout {
            f.field("timeout", d);
        }
    }
}

pin_project! {
    pub struct Pending {
        #[pin]
        inner: PendingInner,
    }
}

enum PendingInner {
    Request(PendingRequest),
    Error(Option<crate::Error>),
}

pin_project! {
    struct PendingRequest {
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Option<Bytes>>,

        urls: Vec<Url>,

        retry_count: usize,

        client: Arc<ClientRef>,

        #[pin]
        in_flight: ResponseFuture,
        #[pin]
        timeout: Option<Pin<Box<Sleep>>>,
    }
}

enum ResponseFuture {
    Default(HyperResponseFuture),
}

impl PendingRequest {
    fn in_flight(self: Pin<&mut Self>) -> Pin<&mut ResponseFuture> {
        self.project().in_flight
    }

    fn timeout(self: Pin<&mut Self>) -> Pin<&mut Option<Pin<Box<Sleep>>>> {
        self.project().timeout
    }

    fn urls(self: Pin<&mut Self>) -> &mut Vec<Url> {
        self.project().urls
    }

    fn headers(self: Pin<&mut Self>) -> &mut HeaderMap {
        self.project().headers
    }

    fn retry_error(mut self: Pin<&mut Self>, err: &(dyn std::error::Error + 'static)) -> bool {
        if !is_retryable_error(err) {
            return false;
        }

        trace!("can retry {:?}", err);

        let body = match self.body {
            Some(Some(ref body)) => Body::reusable(body.clone()),
            Some(None) => {
                debug!("error was retryable, but body not reusable");
                return false;
            }
            None => Body::empty(),
        };

        if self.retry_count >= 2 {
            trace!("retry count too high");
            return false;
        }
        self.retry_count += 1;

        let uri = expect_uri(&self.url);

        *self.as_mut().in_flight().get_mut() = match *self.as_mut().in_flight().as_ref() {
            _ => {
                let mut req = hyper::Request::builder()
                    .method(self.method.clone())
                    .uri(uri)
                    .body(body.into_stream())
                    .expect("valid request parts");
                *req.headers_mut() = self.headers.clone();
                ResponseFuture::Default(self.client.hyper.request(req))
            }
        };

        true
    }
}

fn is_retryable_error(err: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(cause) = err.source() {
        if let Some(err) = cause.downcast_ref::<hyper::h2::Error>() {
            // They sent us a graceful shutdown, try with a new connection!
            return err.is_go_away()
                && err.is_remote()
                && err.reason() == Some(hyper::h2::Reason::NO_ERROR);
        }
    }
    false
}

impl Pending {
    pub(super) fn new_err(err: crate::Error) -> Pending {
        Pending {
            inner: PendingInner::Error(Some(err)),
        }
    }

    fn inner(self: Pin<&mut Self>) -> Pin<&mut PendingInner> {
        self.project().inner
    }
}

impl Future for Pending {
    type Output = Result<Response, crate::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.inner();
        match inner.get_mut() {
            PendingInner::Request(ref mut req) => Pin::new(req).poll(cx),
            PendingInner::Error(ref mut err) => Poll::Ready(Err(err
                .take()
                .expect("Pending error polled more than once"))),
        }
    }
}

impl Future for PendingRequest {
    type Output = Result<Response, crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(delay) = self.as_mut().timeout().as_mut().as_pin_mut() {
            if let Poll::Ready(()) = delay.poll(cx) {
                return Poll::Ready(Err(
                    crate::error::request(crate::error::TimedOut).with_url(self.url.clone())
                ));
            }
        }

        loop {
            let res = match self.as_mut().in_flight().get_mut() {
                ResponseFuture::Default(r) => match Pin::new(r).poll(cx) {
                    Poll::Ready(Err(e)) => {
                        if self.as_mut().retry_error(&e) {
                            continue;
                        }
                        return Poll::Ready(Err(
                            crate::error::request(e).with_url(self.url.clone())
                        ));
                    }
                    Poll::Ready(Ok(res)) => res,
                    Poll::Pending => return Poll::Pending,
                },
            };

            #[cfg(feature = "cookies")]
            {
                if let Some(ref cookie_store) = self.client.cookie_store {
                    let mut cookies =
                        cookie::extract_response_cookie_headers(&res.headers()).peekable();
                    if cookies.peek().is_some() {
                        cookie_store.set_cookies(&mut cookies, &self.url);
                    }
                }
            }
            let should_redirect = match res.status() {
                StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER => {
                    self.body = None;
                    for header in &[
                        TRANSFER_ENCODING,
                        CONTENT_ENCODING,
                        CONTENT_TYPE,
                        CONTENT_LENGTH,
                    ] {
                        self.headers.remove(header);
                    }

                    match self.method {
                        Method::GET | Method::HEAD => {}
                        _ => {
                            self.method = Method::GET;
                        }
                    }
                    true
                }
                StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {
                    match self.body {
                        Some(Some(_)) | None => true,
                        Some(None) => false,
                    }
                }
                _ => false,
            };
            if should_redirect {
                let loc = res.headers().get(LOCATION).and_then(|val| {
                    let loc = (|| -> Option<Url> {
                        // Some sites may send a utf-8 Location header,
                        // even though we're supposed to treat those bytes
                        // as opaque, we'll check specifically for utf8.
                        self.url.join(str::from_utf8(val.as_bytes()).ok()?).ok()
                    })();

                    // Check that the `url` is also a valid `http::Uri`.
                    //
                    // If not, just log it and skip the redirect.
                    let loc = loc.and_then(|url| {
                        if try_uri(&url).is_some() {
                            Some(url)
                        } else {
                            None
                        }
                    });

                    if loc.is_none() {
                        debug!("Location header had invalid URI: {:?}", val);
                    }
                    loc
                });
                if let Some(loc) = loc {
                    if self.client.referer {
                        if let Some(referer) = make_referer(&loc, &self.url) {
                            self.headers.insert(REFERER, referer);
                        }
                    }
                    let url = self.url.clone();
                    self.as_mut().urls().push(url);
                    let action = self
                        .client
                        .redirect_policy
                        .check(res.status(), &loc, &self.urls);

                    match action {
                        redirect::ActionKind::Follow => {
                            debug!("redirecting '{}' to '{}'", self.url, loc);

                            if loc.scheme() != "http" && loc.scheme() != "https" {
                                return Poll::Ready(Err(error::url_bad_scheme(loc)));
                            }

                            if self.client.https_only && loc.scheme() != "https" {
                                return Poll::Ready(Err(error::redirect(
                                    error::url_bad_scheme(loc.clone()),
                                    loc,
                                )));
                            }

                            self.url = loc;
                            let mut headers =
                                std::mem::replace(self.as_mut().headers(), HeaderMap::new());

                            remove_sensitive_headers(&mut headers, &self.url, &self.urls);
                            let uri = expect_uri(&self.url);
                            let body = match self.body {
                                Some(Some(ref body)) => Body::reusable(body.clone()),
                                _ => Body::empty(),
                            };

                            // Add cookies from the cookie store.
                            #[cfg(feature = "cookies")]
                            {
                                if let Some(ref cookie_store) = self.client.cookie_store {
                                    add_cookie_header(&mut headers, &**cookie_store, &self.url);
                                }
                            }

                            *self.as_mut().in_flight().get_mut() =
                                match *self.as_mut().in_flight().as_ref() {
                                    _ => {
                                        let mut req = hyper::Request::builder()
                                            .method(self.method.clone())
                                            .uri(uri.clone())
                                            .body(body.into_stream())
                                            .expect("valid request parts");
                                        *req.headers_mut() = headers.clone();
                                        std::mem::swap(self.as_mut().headers(), &mut headers);
                                        ResponseFuture::Default(self.client.hyper.request(req))
                                    }
                                };

                            continue;
                        }
                        redirect::ActionKind::Stop => {
                            debug!("redirect policy disallowed redirection to '{}'", loc);
                        }
                        redirect::ActionKind::Error(err) => {
                            return Poll::Ready(Err(crate::error::redirect(err, self.url.clone())));
                        }
                    }
                }
            }

            let res = Response::new(
                res,
                self.url.clone(),
                self.client.accepts,
                self.timeout.take(),
            );
            return Poll::Ready(Ok(res));
        }
    }
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.inner {
            PendingInner::Request(ref req) => f
                .debug_struct("Pending")
                .field("method", &req.method)
                .field("url", &req.url)
                .finish(),
            PendingInner::Error(ref err) => f.debug_struct("Pending").field("error", err).finish(),
        }
    }
}

fn make_referer(next: &Url, previous: &Url) -> Option<HeaderValue> {
    if next.scheme() == "http" && previous.scheme() == "https" {
        return None;
    }

    let mut referer = previous.clone();
    let _ = referer.set_username("");
    let _ = referer.set_password(None);
    referer.set_fragment(None);
    referer.as_str().parse().ok()
}

#[cfg(feature = "cookies")]
fn add_cookie_header(headers: &mut HeaderMap, cookie_store: &dyn cookie::CookieStore, url: &Url) {
    if let Some(header) = cookie_store.cookies(url) {
        headers.insert(crate::header::COOKIE, header);
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn execute_request_rejects_invald_urls() {
        let url_str = "hxxps://www.rust-lang.org/";
        let url = url::Url::parse(url_str).unwrap();
        let result = crate::get(url.clone()).await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.is_builder());
        assert_eq!(url_str, err.url().unwrap().as_str());
    }
}
