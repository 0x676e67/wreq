use std::{
    borrow::Cow,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio_btls::SslStream;
use tower::{
    BoxError, Service, ServiceBuilder, ServiceExt,
    timeout::TimeoutLayer,
    util::{BoxCloneSyncService, MapRequestLayer},
};

#[cfg(unix)]
use super::uds::UnixConnector;
use super::{
    AsyncConnWithInfo, BoxedConnectorLayer, BoxedConnectorService, Conn, Connection, HttpConnector,
    TlsConn, TlsInfoFactory, Unnameable, http::HttpTransport, proxy, verbose::Verbose,
};
use crate::{
    conn::{TokioTcpConnector, descriptor::ConnectionDescriptor},
    dns::DynResolver,
    error::{ProxyConnect, TimedOut, map_timeout_to_connector_error},
    ext::UriExt,
    proxy::{Intercepted, Matcher as ProxyMatcher, matcher::Intercept},
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
    nodelay: bool,
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
    builder: TlsConnectorBuilder,
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
    tls: TlsConnector,
    http: HttpConnector,
    builder: Arc<TlsConnectorBuilder>,
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
        self.builder = call(self.builder);
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

    /// Sets the TCP_NODELAY option for connections.
    #[inline]
    pub fn tcp_nodelay(mut self, enabled: bool) -> ConnectorBuilder {
        self.config.nodelay = enabled;
        self
    }

    /// Build a [`Connector`] with the provided layers.
    pub fn build(
        self,
        tls_options: Option<TlsOptions>,
        layers: Vec<BoxedConnectorLayer>,
    ) -> crate::Result<Connector> {
        let mut service = ConnectorService {
            config: self.config,
            #[cfg(feature = "socks")]
            resolver: self.resolver.clone(),
            http: self.http,
            tls: self
                .builder
                .build(tls_options.map(Cow::Owned).unwrap_or_default())?,
            builder: Arc::new(self.builder),
        };

        // we have no user-provided layers, only use concrete types
        if layers.is_empty() {
            return Ok(Connector::Simple(service));
        }

        // user-provided layers exist, the timeout will be applied as an additional layer.
        let timeout = service.config.timeout.take();

        // otherwise we have user provided layers
        // so we need type erasure all the way through
        // as well as mapping the unnameable type of the layers back to ConnectionDescriptor for the
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
    pub(crate) fn builder(proxies: Vec<ProxyMatcher>, resolver: DynResolver) -> ConnectorBuilder {
        ConnectorBuilder {
            config: Config {
                proxies: Arc::new(proxies),
                verbose: Verbose::OFF,
                nodelay: true,
                tls_info: false,
                timeout: None,
            },
            #[cfg(feature = "socks")]
            resolver: resolver.clone(),
            http: HttpConnector::new(resolver, TokioTcpConnector::new()),
            builder: TlsConnector::builder(),
        }
    }
}

impl Service<ConnectionDescriptor> for Connector {
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
    fn call(&mut self, descriptor: ConnectionDescriptor) -> Self::Future {
        match self {
            Connector::Simple(service) => service.call(descriptor),
            Connector::WithLayers(service) => service.call(Unnameable(descriptor)),
        }
    }
}

// ===== impl ConnectorService =====

impl ConnectorService {
    fn build_https_connector(
        &self,
        https: bool,
        descriptor: &ConnectionDescriptor,
    ) -> Result<HttpsConnector<HttpConnector>, BoxError> {
        let mut http = self.http.clone();

        // Disable Nagle's algorithm for TLS handshake
        //
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
        if https && !self.config.nodelay {
            http.set_nodelay(true);
        }

        // Apply TCP options if provided in metadata
        if let Some(socket_opts) = descriptor.socket_bind_options() {
            http.set_local_addresses(socket_opts.ipv4_address, socket_opts.ipv6_address);
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
            if let Some(interface) = &socket_opts.interface {
                http.set_interface(interface.clone());
            }
        }

        // Prefer TLS options from metadata, fallback to default
        let tls = descriptor
            .tls_options()
            .map(|opts| self.builder.build(Cow::Borrowed(opts)))
            .transpose()?
            .unwrap_or_else(|| self.tls.clone());

        Ok(HttpsConnector::new(http, tls))
    }

    fn tunnel_conn_from_stream<IO>(&self, io: MaybeHttpsStream<IO>) -> Result<Conn, BoxError>
    where
        IO: AsyncConnWithInfo,
        TlsConn<IO>: Connection,
        SslStream<IO>: TlsInfoFactory,
    {
        let conn = match io {
            MaybeHttpsStream::Http(stream) => Conn {
                stream: self.config.verbose.wrap(stream),
                tls_info: false,
                proxy: None,
            },
            MaybeHttpsStream::Https(stream) => Conn {
                stream: self.config.verbose.wrap(TlsConn { stream }),
                tls_info: self.config.tls_info,
                proxy: None,
            },
        };

        Ok(conn)
    }

    fn conn_from_stream<IO, P>(&self, io: MaybeHttpsStream<IO>, proxy: P) -> Result<Conn, BoxError>
    where
        IO: AsyncConnWithInfo,
        TlsConn<IO>: Connection,
        SslStream<IO>: TlsInfoFactory,
        P: Into<Option<Intercept>>,
    {
        let conn = match io {
            MaybeHttpsStream::Http(stream) => self.config.verbose.wrap(stream),
            MaybeHttpsStream::Https(stream) => self.config.verbose.wrap(TlsConn { stream }),
        };

        Ok(Conn {
            stream: conn,
            tls_info: self.config.tls_info,
            proxy: proxy.into(),
        })
    }

    async fn connect_auto_proxy<P: Into<Option<Intercept>>>(
        self,
        descriptor: ConnectionDescriptor,
        proxy: P,
    ) -> Result<Conn, BoxError> {
        let is_https = descriptor.uri().is_https();
        let proxy = proxy.into();

        trace!("connect with maybe proxy: {:?}", proxy);

        let mut connector = self.build_https_connector(is_https, &descriptor)?;

        // When using a proxy for HTTPS targets, disable ALPN to avoid protocol negotiation issues
        if proxy.is_some() && is_https {
            connector.no_alpn();
        }

        let io = connector.call(descriptor).await?;

        // Re-enable Nagle's algorithm if it was disabled earlier
        if is_https && !self.config.nodelay {
            io.as_ref().set_nodelay(false)?;
        }

        self.conn_from_stream(io, proxy)
    }

    async fn connect_via_proxy(
        self,
        mut descriptor: ConnectionDescriptor,
        proxy: Intercepted,
    ) -> Result<Conn, BoxError> {
        let uri = descriptor.uri().clone();

        match proxy {
            Intercepted::Proxy(proxy) => {
                let is_https = uri.is_https();
                let proxy_uri = proxy.uri().clone();

                #[cfg(feature = "socks")]
                {
                    use proxy::socks::{DnsResolve, SocksConnector, Version};

                    if let Some((version, dns_resolve)) = match proxy_uri.scheme_str() {
                        Some("socks4") => Some((Version::V4, DnsResolve::Local)),
                        Some("socks4a") => Some((Version::V4, DnsResolve::Remote)),
                        Some("socks5") => Some((Version::V5, DnsResolve::Local)),
                        Some("socks5h") => Some((Version::V5, DnsResolve::Remote)),
                        _ => None,
                    } {
                        trace!("connecting via SOCKS proxy: {:?}", proxy_uri);

                        // Connect to the proxy and establish the SOCKS connection.
                        let conn = {
                            // Build a SOCKS connector.
                            let mut socks = SocksConnector::new(
                                proxy_uri,
                                self.http.clone(),
                                self.resolver.clone(),
                            );
                            socks.set_auth(proxy.raw_auth());
                            socks.set_version(version);
                            socks.set_dns_mode(dns_resolve);
                            socks.call(uri).await?
                        };

                        // Build an HTTPS connector.
                        let mut connector = self.build_https_connector(is_https, &descriptor)?;

                        // Wrap the established SOCKS connection with TLS if needed.
                        let io = connector
                            .call(EstablishedConn::new(conn, descriptor))
                            .await?;

                        // Re-enable Nagle's algorithm if it was disabled earlier
                        if is_https && !self.config.nodelay {
                            io.as_ref().set_nodelay(false)?;
                        }

                        return self.tunnel_conn_from_stream(io);
                    }
                }

                if is_https {
                    trace!("tunneling over HTTP(s) proxy: {:?}", proxy_uri);

                    // Build an HTTPS connector.
                    let mut connector = self.build_https_connector(is_https, &descriptor)?;

                    // Build a tunnel connector to establish the CONNECT tunnel.
                    let tunneled = {
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

                        // Connect to the proxy and establish the tunnel.
                        tunnel.call(uri).await?
                    };

                    // Wrap the established tunneled stream with TLS.
                    let io = connector
                        .call(EstablishedConn::new(tunneled, descriptor))
                        .await?;

                    // Re-enable Nagle's algorithm if it was disabled earlier
                    if !self.config.nodelay {
                        io.as_ref().as_ref().set_nodelay(false)?;
                    }

                    return self.tunnel_conn_from_stream(io);
                }

                *descriptor.uri_mut() = proxy_uri;
                self.connect_auto_proxy(descriptor, proxy)
                    .await
                    .map_err(ProxyConnect)
                    .map_err(Into::into)
            }
            #[cfg(unix)]
            Intercepted::Unix(unix_socket) => {
                trace!("connecting via Unix socket: {:?}", unix_socket);

                // Create a Unix connector with the specified socket path.
                let mut connector =
                    HttpsConnector::new(UnixConnector::new(unix_socket), self.tls.clone());

                // If the target URI is HTTPS, establish a CONNECT tunnel over the Unix socket,
                // then upgrade the tunneled stream to TLS.
                if uri.is_https() {
                    // Use a dummy HTTP URI so the HTTPS connector works over the Unix socket.
                    let proxy_uri = http::Uri::from_static("http://localhost");

                    // The tunnel connector will first establish a CONNECT tunnel,
                    // then perform the TLS handshake over the tunneled stream.
                    let tunneled = {
                        // Create a tunnel connector using the Unix socket and the HTTPS connector.
                        let mut tunnel =
                            proxy::tunnel::TunnelConnector::new(proxy_uri, connector.clone());

                        tunnel.call(uri).await?
                    };

                    // Wrap the established tunneled stream with TLS.
                    let io = connector
                        .call(EstablishedConn::new(tunneled, descriptor))
                        .await?;

                    return self.tunnel_conn_from_stream(io);
                }

                // For plain HTTP, use the Unix connector directly.
                let io = connector.call(descriptor).await?;

                self.conn_from_stream(io, None)
            }
        }
    }

    async fn connect_auto(self, req: ConnectionDescriptor) -> Result<Conn, BoxError> {
        debug!("starting new connection: {:?}", req.uri());

        let timeout = self.config.timeout;

        // Determine if a proxy should be used for this request.
        let fut = async {
            let intercepted = req
                .proxy()
                .and_then(|prox| prox.intercept(req.uri()))
                .or_else(|| {
                    self.config
                        .proxies
                        .iter()
                        .find_map(|prox| prox.intercept(req.uri()))
                });

            // If a proxy is matched, connect via proxy; otherwise, connect directly.
            if let Some(intercepted) = intercepted {
                self.connect_via_proxy(req, intercepted).await
            } else {
                self.connect_auto_proxy(req, None).await
            }
        };

        // Apply timeout if configured.
        if let Some(to) = timeout {
            tokio::time::timeout(to, fut).await.map_err(|_| TimedOut)?
        } else {
            fut.await
        }
    }
}

impl Service<ConnectionDescriptor> for ConnectorService {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn call(&mut self, descriptor: ConnectionDescriptor) -> Self::Future {
        Box::pin(self.clone().connect_auto(descriptor))
    }
}
