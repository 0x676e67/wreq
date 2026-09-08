use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures_util::future::BoxFuture;
use tokio_btls::SslStream;
use tower::{
    BoxError, Layer, Service, ServiceBuilder, ServiceExt,
    util::{BoxCloneSyncService, Either, MapRequest, MapRequestLayer},
};

#[cfg(unix)]
use super::net::UnixConnector;
use super::{
    AsyncConnWithInfo, BoxedConnectorLayer, BoxedTransportConnector, Conn, Connection,
    HttpConnector, TlsConn, TlsInfoFactory, Unnameable,
    descriptor::ConnectionDescriptor,
    http::HttpConnect,
    proxy,
    timeout::{Timeout, TimeoutLayer},
    verbose::Verbose,
};
#[cfg(feature = "socks")]
use crate::dns::DynResolver;
use crate::{
    error::{ProxyConnect, map_timeout_to_connector_error},
    ext::UriExt,
    proxy::{Intercepted, Matcher as ProxyMatcher, matcher::Intercept},
    rt::Timer,
    tls::conn::{EstablishedConn, HttpsConnector, MaybeHttpsStream, TlsConnector},
};

/// Client-wide connection settings retained by each transport connector.
/// Controls proxy selection, connection instrumentation, and post-handshake socket policy.
/// Request-local socket and TLS options remain in the connection descriptor.
#[derive(Clone)]
pub(crate) struct Config {
    pub proxies: Arc<Vec<ProxyMatcher>>,
    pub verbose: bool,
    pub nodelay: bool,
    pub tls_info: bool,
}

/// The connector graph produced by [`ConnectorLayer`] and retained by the client.
/// Uses a concrete timeout wrapper without custom layers, otherwise a type-erased stack.
/// Both branches accept connection descriptors and time each connection attempt separately.
pub type Stack = Either<
    Timeout<Connector>,
    MapRequest<BoxedTransportConnector, fn(ConnectionDescriptor) -> Unnameable>,
>;

/// Composes user connector layers inside the complete connection timeout.
/// The uncustomized path remains concrete; only user layers require type erasure.
/// Applying the layer does not configure sockets or build TLS contexts.
#[derive(Clone)]
pub struct ConnectorLayer {
    layers: Vec<BoxedConnectorLayer>,
    timeout: TimeoutLayer,
}

/// Establishes the transport consumed by the HTTP protocol layer.
/// Selects the proxy path and composes the configured HTTP and TLS connectors.
/// Clones share TLS state; this service owns no initialization builder or pool state.
#[derive(Clone)]
pub struct Connector {
    config: Config,
    #[cfg(feature = "socks")]
    resolver: DynResolver,
    tls: TlsConnector,
    http: HttpConnector,
}

// ===== impl ConnectorLayer =====

impl ConnectorLayer {
    /// Retains middleware and timeout policy until the transport graph is assembled.
    pub fn new(layers: Vec<BoxedConnectorLayer>, timer: Timer, timeout: Option<Duration>) -> Self {
        Self {
            layers,
            timeout: TimeoutLayer::new(timer, timeout),
        }
    }
}

impl Layer<Connector> for ConnectorLayer {
    type Service = Stack;

    fn layer(&self, service: Connector) -> Self::Service {
        if self.layers.is_empty() {
            return Either::Left(self.timeout.layer(service));
        }

        let service = self.layers.iter().fold(
            BoxCloneSyncService::new(
                ServiceBuilder::new()
                    .layer(MapRequestLayer::new(|request: Unnameable| request.0))
                    .service(service),
            ),
            |service, layer| layer.layer(service),
        );

        // Keep the built-in timeout outside user layers so it covers their work too.
        // The final mapping also handles a tower timeout supplied by the caller.
        let service = self
            .timeout
            .layer(service)
            .map_err(map_timeout_to_connector_error);

        let service = MapRequest::new(
            BoxCloneSyncService::new(service),
            Unnameable as fn(ConnectionDescriptor) -> Unnameable,
        );

        Either::Right(service)
    }
}

// ===== impl Connector =====

impl Connector {
    /// Combines initialized HTTP and TLS components with transport policy.
    pub(crate) fn new(
        config: Config,
        http: HttpConnector,
        tls: TlsConnector,
        #[cfg(feature = "socks")] resolver: DynResolver,
    ) -> Self {
        Self {
            config,
            http,
            tls,
            #[cfg(feature = "socks")]
            resolver,
        }
    }

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

        self.tls
            .layer(http)
            .with_options(descriptor.tls_options())
            .map_err(Into::into)
    }

    fn tunnel_conn_from_stream<IO>(&self, io: MaybeHttpsStream<IO>) -> Result<Conn, BoxError>
    where
        IO: AsyncConnWithInfo,
        TlsConn<IO>: Connection,
        SslStream<IO>: TlsInfoFactory,
    {
        let conn = match io {
            MaybeHttpsStream::Http(stream) => Conn {
                stream: Verbose(self.config.verbose).wrap(stream),
                tls_info: false,
                proxy: None,
            },
            MaybeHttpsStream::Https(stream) => Conn {
                stream: Verbose(self.config.verbose).wrap(TlsConn { stream }),
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
            MaybeHttpsStream::Http(stream) => Verbose(self.config.verbose).wrap(stream),
            MaybeHttpsStream::Https(stream) => {
                Verbose(self.config.verbose).wrap(TlsConn { stream })
            }
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
        if_tokio_rt!(block:{
            if is_https && !self.config.nodelay {
                io.as_ref().set_nodelay(false)?;
            }
        });

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
                        if_tokio_rt!(block:{
                            if is_https && !self.config.nodelay {
                                io.as_ref().set_nodelay(false)?;
                            }
                        });

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
                    if_tokio_rt!(block:{
                        if !self.config.nodelay {
                            io.as_ref().as_ref().set_nodelay(false)?;
                        }
                    });

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
                let mut connector = self.tls.layer(UnixConnector::new(unix_socket));

                // If the target URI is HTTPS, establish a CONNECT tunnel over the Unix socket,
                // then upgrade the tunneled stream to TLS.
                if uri.is_https() {
                    // Use a dummy HTTP URI so the HTTPS connector works over the Unix socket.
                    let proxy_uri = http::Uri::from_static("http://localhost");

                    // The tunnel connector will first establish a CONNECT tunnel,
                    // then perform the TLS handshake over the tunneled stream.
                    let tunneled = {
                        // Create a tunnel connector using the Unix socket and the HTTPS
                        // connector.
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

        // Determine if a proxy should be used for this request.
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
    }
}

impl Service<ConnectionDescriptor> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Conn, BoxError>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn call(&mut self, descriptor: ConnectionDescriptor) -> Self::Future {
        Box::pin(self.clone().connect_auto(descriptor))
    }
}
