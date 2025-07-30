use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::uri::Scheme;
use tower::{
    Service, ServiceBuilder,
    timeout::TimeoutLayer,
    util::{BoxCloneSyncService, MapRequestLayer},
};

use super::{
    super::{BoxedConnectorLayer, BoxedConnectorService, HttpConnector},
    Unnameable,
    conn::{Conn, TlsConn},
    verbose::Verbose,
};
use crate::{
    core::{
        client::{ConnectMeta, ConnectRequest, connect::proxy},
        rt::TokioIo,
    },
    dns::DynResolver,
    error::{BoxError, TimedOut, map_timeout_to_connector_error},
    proxy::{Intercepted, Matcher as ProxyMatcher},
    tls::{
        EstablishedConn, HttpsConnector, MaybeHttpsStream, TlsConnector, TlsConnectorBuilder,
        TlsOptions,
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
    tls_options: Option<TlsOptions>,
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
        self.tls_options = opts;
        self
    }

    /// Builds the connector with the provided layers.
    pub fn build(self, layers: Vec<BoxedConnectorLayer>) -> crate::Result<Connector> {
        let mut service = ConnectorService {
            config: self.config,
            #[cfg(feature = "socks")]
            resolver: self.resolver.clone(),
            http: self.http,
            tls: self
                .tls_builder
                .build(self.tls_options.unwrap_or_default())?,
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
                    .service(service);
                let service = ServiceBuilder::new()
                    .map_err(map_timeout_to_connector_error)
                    .service(service);
                let service = BoxCloneSyncService::new(service);
                Ok(Connector::WithLayers(service))
            }
            None => {
                // no timeout, but still map err
                // no named timeout layer but we still map errors since
                // we might have user-provided timeout layer
                let service = ServiceBuilder::new()
                    .map_err(map_timeout_to_connector_error)
                    .service(service);
                let service = BoxCloneSyncService::new(service);
                Ok(Connector::WithLayers(service))
            }
        }
    }
}

// ===== impl Connector =====

impl Connector {
    /// Creates a new `Connector` with the provided configuration and optional layers.
    pub fn builder(proxies: Arc<Vec<ProxyMatcher>>, resolver: DynResolver) -> ConnectorBuilder {
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
            tls_options: None,
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
    /// Constructs an HTTPS connector by wrapping an `HttpConnector`
    fn build_tls_connector(
        &self,
        mut http: HttpConnector,
        meta: &ConnectMeta,
    ) -> Result<HttpsConnector<HttpConnector>, BoxError> {
        http.set_connect_options(meta.tcp_options().cloned());
        let tls = match meta.tls_options() {
            Some(opts) => self.tls_builder.build(opts)?,
            None => self.tls.clone(),
        };
        Ok(HttpsConnector::with_connector(http, tls))
    }

    /// Establishes a direct connection to the target URI without using a proxy.
    /// May perform a plain TCP or a TLS handshake depending on the URI scheme.
    async fn connect_direct(self, req: ConnectRequest, is_proxy: bool) -> Result<Conn, BoxError> {
        trace!("connect with maybe proxy: {:?}", is_proxy);

        let uri = req.uri().clone();
        let mut http = self.http.clone();

        // Disable Nagle's algorithm for TLS handshake
        //
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
        if !self.config.tcp_nodelay && (uri.scheme() == Some(&Scheme::HTTPS)) {
            http.set_nodelay(true);
        }

        let mut connector = self.build_tls_connector(http, req.metadata())?;
        let io = connector.call(req).await?;

        // If the connection is HTTPS, wrap the TLS stream in a TlsConn for unified handling.
        // For plain HTTP, use the stream directly without additional wrapping.
        let inner = if let MaybeHttpsStream::Https(stream) = io {
            if !self.config.tcp_nodelay {
                stream.get_ref().set_nodelay(false)?;
            }
            self.config.verbose.wrap(TlsConn::new(stream))
        } else {
            self.config.verbose.wrap(io)
        };

        Ok(Conn::new(inner, is_proxy, self.config.tls_info))
    }

    /// Establishes a connection through a specified proxy.
    /// Supports both SOCKS and HTTP tunneling proxies.
    async fn connect_with_proxy(
        self,
        mut req: ConnectRequest,
        proxy: Intercepted,
    ) -> Result<Conn, BoxError> {
        let uri = req.uri().clone();
        let proxy_uri = proxy.uri().clone();

        #[cfg(feature = "socks")]
        {
            use proxy::socks::{DnsResolve, SocksConnector, Version};

            if let Some((version, dns_resolve)) = match proxy.uri().scheme_str() {
                Some("socks4") => Some((Version::V4, DnsResolve::Local)),
                Some("socks4a") => Some((Version::V4, DnsResolve::Remote)),
                Some("socks5") => Some((Version::V5, DnsResolve::Local)),
                Some("socks5h") => Some((Version::V5, DnsResolve::Remote)),
                _ => None,
            } {
                trace!("connecting via SOCKS proxy: {:?}", proxy_uri);

                // Create a SOCKS connector with the specified version and DNS resolution strategy.
                let mut socks = SocksConnector::new_with_resolver(
                    proxy_uri,
                    self.http.clone(),
                    self.resolver.clone(),
                )
                .with_auth(proxy.raw_auth())
                .with_version(version)
                .with_dns_mode(dns_resolve);

                let is_https = uri.scheme() == Some(&Scheme::HTTPS);
                let conn = socks.call(uri).await?;

                let conn = if is_https {
                    trace!("socks HTTPS over proxy");

                    // Create a TLS connector for the established connection.
                    let mut connector =
                        self.build_tls_connector(self.http.clone(), req.metadata())?;
                    let established_conn = EstablishedConn::new(req, conn);
                    let io = connector.call(established_conn).await?;

                    Conn::new(
                        self.config.verbose.wrap(TlsConn::new(io)),
                        false,
                        self.config.tls_info,
                    )
                } else {
                    Conn::new(self.config.verbose.wrap(conn), false, false)
                };

                return Ok(conn);
            }
        }

        // Handle HTTPS proxy tunneling connection
        if uri.scheme() == Some(&Scheme::HTTPS) {
            trace!("tunneling HTTPS over HTTP proxy: {:?}", proxy_uri);

            // Create a tunnel connector with the proxy URI and the HTTP connector.
            let mut connector = self.build_tls_connector(self.http.clone(), req.metadata())?;
            let mut tunnel = proxy::tunnel::TunnelConnector::new(proxy_uri, connector.clone());

            // If the proxy has basic authentication, add it to the tunnel.
            if let Some(auth) = proxy.basic_auth() {
                tunnel = tunnel.with_auth(auth.clone());
            }

            // If the proxy has custom headers, add them to the tunnel.
            if let Some(headers) = proxy.custom_headers() {
                tunnel = tunnel.with_headers(headers.clone());
            }

            // We don't wrap this again in an HttpsConnector since that uses Maybe,
            // and we know this is definitely HTTPS.
            let tunneled = tunnel.call(uri).await?;
            let tunneled = TokioIo::new(tunneled);
            let tunneled = TokioIo::new(tunneled);

            // Create established connection with the tunneled stream.
            let established_conn = EstablishedConn::new(req, tunneled);
            let io = connector.call(established_conn).await?;

            let conn = Conn::new(
                self.config.verbose.wrap(TlsConn::new(io)),
                false,
                self.config.tls_info,
            );
            return Ok(conn);
        }

        *req.uri_mut() = proxy_uri;
        self.connect_direct(req, true).await
    }

    /// Automatically selects between a direct or proxied connection
    /// based on the request and configured proxy matchers.
    /// Applies a timeout if configured.
    async fn connect_auto(self, req: ConnectRequest) -> Result<Conn, BoxError> {
        debug!("starting new connection: {:?}", req.uri());

        let intercepted = req
            .metadata()
            .proxy_matcher()
            .and_then(|prox| prox.intercept(req.uri()))
            .or_else(|| {
                self.config
                    .proxies
                    .iter()
                    .find_map(|prox| prox.intercept(req.uri()))
            });

        let timeout = self.config.timeout;
        let fut = async {
            if let Some(intercepted) = intercepted {
                self.connect_with_proxy(req, intercepted).await
            } else {
                self.connect_direct(req, false).await
            }
        };

        if let Some(to) = timeout {
            tokio::time::timeout(to, fut)
                .await
                .map_err(|_| BoxError::from(TimedOut))?
        } else {
            fut.await
        }
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
