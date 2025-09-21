#[cfg(unix)]
use std::path::Path;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::Uri;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{
    Service, ServiceBuilder, ServiceExt,
    timeout::TimeoutLayer,
    util::{BoxCloneSyncService, MapRequestLayer},
};

use super::{
    super::{BoxedConnectorLayer, BoxedConnectorService, HttpConnector},
    Unnameable,
    conn::{Conn, TlsConn},
    verbose::Verbose,
};
#[cfg(unix)]
use crate::core::client::connect::UnixConnector;
use crate::{
    core::client::{
        ConnectExtra, ConnectRequest,
        connect::{Connection, proxy},
    },
    dns::DynResolver,
    error::{BoxError, TimedOut, map_timeout_to_connector_error},
    ext::UriExt,
    proxy::{Intercepted, Matcher as ProxyMatcher},
    tls::{
        TlsOptions,
        conn::{
            EstablishedConn, HttpsConnector, MaybeHttpsStream, TlsConnector, TlsConnectorBuilder,
        },
    },
};

type Connecting = Pin<Box<dyn Future<Output = Result<Conn, BoxError>> + Send>>;

/// Configuration for the connector service.
#[derive(Clone)]
struct Config {
    proxies: Arc<Vec<ProxyMatcher>>,
    verbose: Verbose,
    tcp_nodelay: bool,
    tls_info: bool,
    /// When there is a single timeout layer and no other layers,
    /// we embed it directly inside our base Service::call().
    /// This lets us avoid an extra `Box::pin` indirection layer
    /// since `tokio::time::Timeout` is `Unpin`
    timeout: Option<Duration>,
}

/// Builder for `Connector`.
pub struct ConnectorBuilder {
    config: Config,
    #[cfg(feature = "socks")]
    resolver: DynResolver,
    http: HttpConnector,
    tls_options: TlsOptions,
    tls_builder: TlsConnectorBuilder,
}

/// Connector service that establishes connections.
#[derive(Clone)]
pub enum Connector {
    Simple(ConnectorService),
    WithLayers(BoxedConnectorService),
}

/// Service that establishes connections to HTTP servers.
#[derive(Clone)]
pub struct ConnectorService {
    config: Config,
    #[cfg(feature = "socks")]
    resolver: DynResolver,
    http: HttpConnector,
    tls: TlsConnector,
    tls_builder: Arc<TlsConnectorBuilder>,
}

// ===== impl ConnectorBuilder =====

impl ConnectorBuilder {
    /// Set the HTTP connector to use.
    #[inline]
    pub fn with_http<F>(mut self, call: F) -> ConnectorBuilder
    where
        F: FnOnce(&mut HttpConnector),
    {
        call(&mut self.http);
        self
    }

    /// Set the TLS connector builder to use.
    #[inline]
    pub fn with_tls<F>(mut self, call: F) -> ConnectorBuilder
    where
        F: FnOnce(TlsConnectorBuilder) -> TlsConnectorBuilder,
    {
        self.tls_builder = call(self.tls_builder);
        self
    }

    /// Set the connect timeout.
    ///
    /// If a domain resolves to multiple IP addresses, the timeout will be
    /// evenly divided across them.
    #[inline]
    pub fn timeout(mut self, timeout: Option<Duration>) -> ConnectorBuilder {
        self.config.timeout = timeout;
        self
    }

    /// Set connecting verbose mode.
    #[inline]
    pub fn verbose(mut self, enabled: bool) -> ConnectorBuilder {
        self.config.verbose.0 = enabled;
        self
    }

    /// Sets the TLS info flag.
    #[inline]
    pub fn tls_info(mut self, enabled: bool) -> ConnectorBuilder {
        self.config.tls_info = enabled;
        self
    }

    /// Sets the TLS options to use.
    #[inline]
    pub fn tls_options(mut self, opts: Option<TlsOptions>) -> ConnectorBuilder {
        if let Some(opts) = opts {
            self.tls_options = opts;
        }
        self
    }

    /// Build a [`Connector`] with the provided layers.
    pub fn build(self, layers: Vec<BoxedConnectorLayer>) -> crate::Result<Connector> {
        let mut service = ConnectorService {
            config: self.config,
            #[cfg(feature = "socks")]
            resolver: self.resolver.clone(),
            http: self.http,
            tls: self.tls_builder.build(&self.tls_options)?,
            tls_builder: Arc::new(self.tls_builder),
        };

        // we have no user-provided layers, only use concrete types
        if layers.is_empty() {
            return Ok(Connector::Simple(service));
        }

        // user-provided layers exist, the timeout will be applied as an additional layer.
        let timeout = service.config.timeout.take();

        // otherwise we have user provided layers
        // so we need type erasure all the way through
        // as well as mapping the unnameable type of the layers back to ConnectRequest for the
        // inner service
        let service = layers.into_iter().fold(
            BoxCloneSyncService::new(
                ServiceBuilder::new()
                    .layer(MapRequestLayer::new(|request: Unnameable| request.0))
                    .service(service),
            ),
            |service, layer| ServiceBuilder::new().layer(layer).service(service),
        );

        // now we handle the concrete stuff - any `connect_timeout`,
        // plus a final map_err layer we can use to cast default tower layer
        // errors to internal errors
        match timeout {
            Some(timeout) => {
                let service = ServiceBuilder::new()
                    .layer(TimeoutLayer::new(timeout))
                    .service(service)
                    .map_err(map_timeout_to_connector_error);

                Ok(Connector::WithLayers(BoxCloneSyncService::new(service)))
            }
            None => {
                // no timeout, but still map err
                // no named timeout layer but we still map errors since
                // we might have user-provided timeout layer
                let service = ServiceBuilder::new()
                    .service(service)
                    .map_err(map_timeout_to_connector_error);

                Ok(Connector::WithLayers(BoxCloneSyncService::new(service)))
            }
        }
    }
}

// ===== impl Connector =====

impl Connector {
    /// Creates a new [`Connector`] with the provided configuration and optional layers.
    pub(crate) fn builder(
        proxies: Arc<Vec<ProxyMatcher>>,
        resolver: DynResolver,
    ) -> ConnectorBuilder {
        ConnectorBuilder {
            config: Config {
                proxies,
                verbose: Verbose::OFF,
                tcp_nodelay: false,
                tls_info: false,
                timeout: None,
            },
            #[cfg(feature = "socks")]
            resolver: resolver.clone(),
            http: HttpConnector::new_with_resolver(resolver),
            tls_options: TlsOptions::default(),
            tls_builder: TlsConnector::builder(),
        }
    }
}

impl Service<ConnectRequest> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Connector::Simple(service) => service.poll_ready(cx),
            Connector::WithLayers(service) => service.poll_ready(cx),
        }
    }

    #[inline]
    fn call(&mut self, req: ConnectRequest) -> Self::Future {
        match self {
            Connector::Simple(service) => service.call(req),
            Connector::WithLayers(service) => service.call(Unnameable(req)),
        }
    }
}

// ===== impl ConnectorService =====

impl ConnectorService {
    /// Automatically selects direct or proxy connection.
    async fn connect_auto(self, req: ConnectRequest) -> Result<Conn, BoxError> {
        debug!("starting new connection: {:?}", req.uri());

        let timeout = self.config.timeout;

        // Determine if a proxy should be used for this request.
        let fut = async {
            let intercepted = req
                .extra()
                .proxy_matcher()
                .and_then(|prox| prox.intercept(req.uri()))
                .or_else(|| {
                    self.config
                        .proxies
                        .iter()
                        .find_map(|prox| prox.intercept(req.uri()))
                });

            // If a proxy is matched, connect via proxy; otherwise, connect directly.
            if let Some(intercepted) = intercepted {
                self.connect_with_proxy(req, intercepted).await
            } else {
                self.connect_direct(req, false).await
            }
        };

        // Apply timeout if configured.
        if let Some(to) = timeout {
            tokio::time::timeout(to, fut)
                .await
                .map_err(|_| BoxError::from(TimedOut))?
        } else {
            fut.await
        }
    }

    /// Establishes a direct connection to the target URI without using a proxy.
    async fn connect_direct(self, req: ConnectRequest, is_proxy: bool) -> Result<Conn, BoxError> {
        trace!("connect with maybe proxy: {:?}", is_proxy);

        let mut connector = self.build_https_connector(req.extra())?;

        // If the connection is HTTPS, wrap the TLS stream in a TlsConn for unified handling.
        // For plain HTTP, use the stream directly without additional wrapping.
        match connector.call(req).await? {
            MaybeHttpsStream::Http(io) => Ok(Conn {
                inner: self.config.verbose.wrap(MaybeHttpsStream::Http(io)),
                tls_info: false,
                is_proxy,
            }),
            MaybeHttpsStream::Https(stream) => {
                // Re-enable Nagle's algorithm if it was disabled earlier
                if !self.config.tcp_nodelay {
                    stream.get_ref().set_nodelay(false)?;
                }

                Ok(Conn {
                    inner: self.config.verbose.wrap(TlsConn::new(stream)),
                    tls_info: self.config.tls_info,
                    is_proxy,
                })
            }
        }
    }

    /// Establishes a connection through a specified proxy.
    async fn connect_with_proxy(
        self,
        mut req: ConnectRequest,
        proxy: Intercepted,
    ) -> Result<Conn, BoxError> {
        let uri = req.uri().clone();

        match proxy {
            Intercepted::Proxy(proxy) => {
                let proxy_uri = proxy.uri().clone();

                #[cfg(feature = "socks")]
                use proxy::socks::{DnsResolve, SocksConnector, Version};

                #[cfg(feature = "socks")]
                if let Some((version, dns_resolve)) = match proxy.uri().scheme_str() {
                    Some("socks4") => Some((Version::V4, DnsResolve::Local)),
                    Some("socks4a") => Some((Version::V4, DnsResolve::Remote)),
                    Some("socks5") => Some((Version::V5, DnsResolve::Local)),
                    Some("socks5h") => Some((Version::V5, DnsResolve::Remote)),
                    _ => None,
                } {
                    trace!("connecting via SOCKS proxy: {:?}", proxy_uri);

                    // Build a SOCKS connector, configuring authentication, version, and DNS
                    // resolution mode.
                    let mut socks = {
                        let mut socks = SocksConnector::new_with_resolver(
                            proxy_uri,
                            self.http.clone(),
                            self.resolver.clone(),
                        );
                        socks.set_auth(proxy.raw_auth());
                        socks.set_version(version);
                        socks.set_dns_mode(dns_resolve);
                        socks
                    };

                    let is_https = uri.is_https();
                    let conn = socks.call(uri).await?;

                    let conn = if is_https {
                        // If the target is HTTPS, wrap the SOCKS stream with TLS.
                        let mut connector = self.build_https_connector(req.extra())?;
                        let established_conn = EstablishedConn::new(req, conn);
                        let io = connector.call(established_conn).await?;

                        // Re-enable Nagle's algorithm if it was disabled earlier
                        if !self.config.tcp_nodelay {
                            io.get_ref().set_nodelay(false)?;
                        }

                        Conn {
                            inner: self.config.verbose.wrap(TlsConn::new(io)),
                            tls_info: self.config.tls_info,
                            is_proxy: true,
                        }
                    } else {
                        // For HTTP, return the SOCKS connection directly.
                        Conn {
                            inner: self.config.verbose.wrap(conn),
                            tls_info: false,
                            is_proxy: false,
                        }
                    };

                    return Ok(conn);
                }

                // Handle HTTPS proxy tunneling connection
                if uri.is_https() {
                    trace!("tunneling HTTPS over HTTP proxy: {:?}", proxy_uri);

                    // Create a tunnel connector that establishes a CONNECT tunnel through the HTTP
                    // proxy, then upgrades the tunneled stream to TLS.
                    let mut connector = self.build_https_connector(req.extra())?;
                    let mut tunnel =
                        proxy::tunnel::TunnelConnector::new(proxy_uri, connector.clone());

                    // If the proxy requires basic authentication, add it to the tunnel.
                    if let Some(auth) = proxy.basic_auth() {
                        tunnel = tunnel.with_auth(auth.clone());
                    }

                    // If the proxy has custom headers, add them to the tunnel.
                    if let Some(headers) = proxy.custom_headers() {
                        tunnel = tunnel.with_headers(headers.clone());
                    }

                    // The tunnel connector will first establish a CONNECT tunnel,
                    // then perform the TLS handshake over the tunneled stream.
                    let tunneled = tunnel.call(uri).await?;

                    // Wrap the established tunneled stream with TLS.
                    let established_conn = EstablishedConn::new(req, tunneled);
                    let io = connector.call(established_conn).await?;

                    // Re-enable Nagle's algorithm if it was disabled earlier
                    if !self.config.tcp_nodelay {
                        io.get_ref().get_ref().set_nodelay(false)?;
                    }

                    return Ok(Conn {
                        inner: self.config.verbose.wrap(TlsConn::new(io)),
                        tls_info: self.config.tls_info,
                        is_proxy: false,
                    });
                }

                *req.uri_mut() = proxy_uri;
                self.connect_direct(req, true).await
            }
            #[cfg(unix)]
            Intercepted::Unix(unix_socket) => {
                trace!("connecting via Unix socket: {:?}", unix_socket);

                // Create a Unix connector with the specified socket path.
                let mut connector = self.build_unix_connector(unix_socket, req.extra())?;
                let is_proxy = false;

                // If the target URI is HTTPS, establish a CONNECT tunnel over the Unix socket,
                // then upgrade the tunneled stream to TLS.
                if uri.is_https() {
                    // Use a dummy HTTP URI so the HTTPS connector works over the Unix socket.
                    let proxy_uri = Uri::from_static("http://localhost");

                    // Create a tunnel connector using the Unix socket and the HTTPS connector.
                    let mut tunnel =
                        proxy::tunnel::TunnelConnector::new(proxy_uri, connector.clone());

                    // The tunnel connector will first establish a CONNECT tunnel,
                    // then perform the TLS handshake over the tunneled stream.
                    let tunneled = tunnel.call(uri).await?;

                    // Wrap the established tunneled stream with TLS.
                    let established_conn = EstablishedConn::new(req, tunneled);
                    let io = connector.call(established_conn).await?;

                    return Ok(Conn {
                        inner: self.config.verbose.wrap(TlsConn::new(io)),
                        tls_info: self.config.tls_info,
                        is_proxy,
                    });
                }

                // For plain HTTP, use the Unix connector directly.
                let io = connector.call(req).await?;

                // If the connection is HTTPS, wrap the TLS stream in a TlsConn for unified
                // handling. For plain HTTP, use the stream directly without
                // additional wrapping.
                if let MaybeHttpsStream::Https(stream) = io {
                    return Ok(Conn {
                        inner: self.config.verbose.wrap(TlsConn::new(stream)),
                        tls_info: self.config.tls_info,
                        is_proxy,
                    });
                }

                Ok(Conn {
                    inner: self.config.verbose.wrap(io),
                    tls_info: false,
                    is_proxy,
                })
            }
        }
    }

    /// Builds an [`HttpsConnector<HttpConnector>`] from a basic [`HttpConnector`],
    /// applying TCP and TLS configuration from the provided [`ConnectExtra`].
    fn build_https_connector(
        &self,
        extra: &ConnectExtra,
    ) -> Result<HttpsConnector<HttpConnector>, BoxError> {
        let mut http = self.http.clone();

        // Disable Nagle's algorithm for TLS handshake
        //
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
        if !self.config.tcp_nodelay {
            http.set_nodelay(true);
        }

        // Apply TCP options if provided in metadata
        if let Some(opts) = extra.tcp_options() {
            http.set_connect_options(opts.clone());
        }

        self.build_tls_connector_generic(http, extra)
    }

    /// Builds an [`HttpsConnector<UnixConnector>`] for secure communication over a Unix domain
    /// socket.
    #[cfg(unix)]
    fn build_unix_connector(
        &self,
        unix_socket: Arc<Path>,
        extra: &ConnectExtra,
    ) -> Result<HttpsConnector<UnixConnector>, BoxError> {
        // Create a Unix connector with the specified socket path
        self.build_tls_connector_generic(UnixConnector(unix_socket), extra)
    }

    /// Creates an [`HttpsConnector`] from a given connector and TLS configuration.
    fn build_tls_connector_generic<S, T>(
        &self,
        connector: S,
        extra: &ConnectExtra,
    ) -> Result<HttpsConnector<S>, BoxError>
    where
        S: Service<Uri, Response = T> + Send,
        S::Error: Into<BoxError>,
        S::Future: Unpin + Send + 'static,
        T: AsyncRead + AsyncWrite + Connection + Unpin + std::fmt::Debug + Sync + Send + 'static,
    {
        // Prefer TLS options from metadata, fallback to default
        let tls = extra
            .tls_options()
            .map(|opts| self.tls_builder.build(opts))
            .transpose()?
            .unwrap_or_else(|| self.tls.clone());

        Ok(HttpsConnector::with_connector(connector, tls))
    }
}

impl Service<ConnectRequest> for ConnectorService {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    #[inline(always)]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline(always)]
    fn call(&mut self, req: ConnectRequest) -> Self::Future {
        Box::pin(self.clone().connect_auto(req))
    }
}
