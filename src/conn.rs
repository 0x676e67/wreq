//! Transport connector composition and established stream adapters.
//! Connection metadata is exposed through [`Connected`]; protocol pools live in the client.

mod extra;
pub(crate) mod request;
mod timeout;
mod tls_info;
mod verbose;

pub(super) mod http;
pub(super) mod net;
pub(super) mod proxy;

use std::{
    fmt::{self, Debug, Formatter},
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use ::http::{Extensions, HeaderMap, HeaderValue};
pub(crate) use extra::Extra;
use futures_util::future::BoxFuture;
use http::HttpConnect;
#[cfg(any(feature = "tokio-rt", feature = "compio-rt"))]
use net::TcpConnector;
#[cfg(unix)]
use net::UnixConnector;
use pin_project_lite::pin_project;
pub(crate) use request::{ConnectRequest, ConnectionKey, SocketOptions};
use timeout::{Timeout, TimeoutLayer};
use tls_info::TlsInfoFactory;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream;
use tower::{
    BoxError, Layer, Service, ServiceBuilder, ServiceExt,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, Either, MapRequest, MapRequestLayer},
};
use verbose::Verbose;

use crate::{
    dns::DynResolver,
    error::{ProxyConnect, map_timeout_to_connector_error},
    ext::UriExt,
    proxy::{Intercepted, Matcher as ProxyMatcher, matcher::Intercept},
    rt::Timer,
    tls::{
        AlpnProtocol, TlsInfo, TlsOptions,
        conn::{EstablishedConn, HttpsConnector, MaybeHttpsStream, TlsConnector},
    },
};

/// Client-wide connection settings retained by each transport connector.
/// Controls proxy selection, connection instrumentation, and post-handshake socket policy.
/// Request-local socket and TLS options remain in the connection context.
#[derive(Clone)]
pub(crate) struct Config {
    pub proxies: Arc<Vec<ProxyMatcher>>,
    pub verbose: bool,
    pub nodelay: bool,
    pub tls_info: bool,
}

/// The connector graph produced by [`ConnectorLayer`] and retained by the client.
/// Uses a concrete timeout wrapper without custom layers, otherwise a type-erased stack.
/// Both branches accept connection inputs and time each connection attempt separately.
pub type Stack = Either<
    Timeout<Connector>,
    MapRequest<BoxedTransportConnector, fn(ConnectRequest) -> Unnameable>,
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

/// HTTP connector with dynamic DNS resolver.
pub type HttpConnector = http::HttpConnector<DynResolver, TcpConnector>;

/// Type-erased transport service retained after custom connector layers are composed.
pub type BoxedTransportConnector = BoxCloneSyncService<Unnameable, Conn, BoxError>;

/// Type-erased layer applied while assembling a [`BoxedTransportConnector`].
pub type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedTransportConnector, Unnameable, Conn, BoxError>;

/// A wrapper type for [`ConnectRequest`] used to erase its concrete type.
///
/// [`Unnameable`] allows passing connection requests through trait objects or
/// type-erased interfaces where the concrete type of the request is not important.
/// This is mainly used internally to simplify service composition and dynamic dispatch.
pub struct Unnameable(pub(super) ConnectRequest);

/// A trait alias for types that can be used as async connections.
///
/// This trait is automatically implemented for any type that satisfies the required bounds:
/// - [`AsyncRead`] + [`AsyncWrite`]: For I/O operations
/// - [`Connection`]: For connection metadata
/// - [`Send`] + [`Sync`] + [`Unpin`] + `'static`: For async/await compatibility
trait AsyncConn: AsyncRead + AsyncWrite + Connection + Send + Sync + Unpin + 'static {}

/// An async connection that can also provide TLS information.
///
/// This extends [`AsyncConn`] with the ability to extract TLS certificate information
/// when available. Useful for connections that may be either plain TCP or TLS-encrypted.
trait AsyncConnWithInfo: AsyncConn + TlsInfoFactory {}

impl<T> AsyncConn for T where T: AsyncRead + AsyncWrite + Connection + Send + Sync + Unpin + 'static {}

impl<T> AsyncConnWithInfo for T where T: AsyncConn + TlsInfoFactory {}

pin_project! {
    /// Note: the `is_proxy` member means *is plain text HTTP proxy*.
    /// This tells core whether the URI should be written in
    /// * origin-form (`GET /just/a/path HTTP/1.1`), when `proxy == None`, or
    /// * absolute-form (`GET http://foo.bar/and/a/path HTTP/1.1`), otherwise.
    pub struct Conn {
        tls_info: bool,
        proxy: Option<Intercept>,
        #[pin]
        stream: Box<dyn AsyncConnWithInfo>,
    }
}

pin_project! {
    /// A wrapper around `SslStream` that adapts it for use as a generic async connection.
    ///
    /// This type enables unified handling of plain TCP and TLS-encrypted streams by providing
    /// implementations of `Connection`, `Read`, `Write`, and `TlsInfoFactory`.
    /// It is mainly used internally to abstract over different connection types.
    pub struct TlsConn<T> {
        #[pin]
        stream: SslStream<T>,
    }
}

/// Indicates the negotiated ALPN protocol.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Alpn {
    H2,
    None,
}

/// Shared reuse status for an established connection.
/// Poisoning any clone prevents the transport from returning to the pool.
/// The flag stays alive while connection metadata still references it.
#[derive(Clone)]
struct PoisonPill(Arc<AtomicBool>);

/// Information about an HTTP proxy identity.
/// Carries forward-proxy status, credentials, and headers for request preparation.
/// Connection clones share it; updates use copy-on-write to preserve other clones.
#[derive(Debug, Default, Clone)]
struct ProxyIdentity {
    is_proxied: bool,
    auth: Option<HeaderValue>,
    headers: Option<HeaderMap>,
}

/// Metadata describing the established transport and its negotiated protocol.
/// Carries proxy details and extra values copied into response extensions.
/// Clones share the poison flag so reuse can be disabled from any response.
#[derive(Debug, Clone)]
pub struct Connected {
    alpn: Alpn,
    proxy: Arc<ProxyIdentity>,
    extra: Extra,
    poisoned: PoisonPill,
}

/// Describes a type returned by a connector.
pub trait Connection {
    /// Return metadata describing the connection.
    fn connected(&self) -> Connected;
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
            Unnameable as fn(ConnectRequest) -> Unnameable,
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

    fn http_for_connection(&self, https: bool, req: &ConnectRequest) -> HttpConnector {
        let mut http = self.http.clone();

        // Disable Nagle's algorithm for TLS handshake
        //
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
        if https && !self.config.nodelay {
            http.set_nodelay(true);
        }

        // Apply request-local socket configuration before connecting.
        if let Some(socket_options) = req.extra().get::<SocketOptions>() {
            http.set_local_addresses(socket_options.ipv4_address, socket_options.ipv6_address);
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
            if let Some(interface) = &socket_options.interface {
                http.set_interface(interface.clone());
            }
        }

        http
    }

    fn build_https_connector(
        &self,
        https: bool,
        req: &ConnectRequest,
    ) -> Result<HttpsConnector<HttpConnector>, BoxError> {
        self.tls
            .layer(self.http_for_connection(https, req))
            .with_options(req.extra().get::<TlsOptions>())
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
        req: ConnectRequest,
        proxy: P,
    ) -> Result<Conn, BoxError> {
        let is_https = req.route_uri().is_https();
        let proxy = proxy.into();

        trace!("connect with maybe proxy: {:?}", proxy);

        let mut connector = self.build_https_connector(is_https, &req)?;

        // When using a proxy for HTTPS targets, disable ALPN to avoid protocol negotiation issues
        if proxy.is_some() && is_https {
            connector.no_alpn();
        }

        let io = connector.call(req).await?;

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
        req: ConnectRequest,
        proxy: Intercepted,
    ) -> Result<Conn, BoxError> {
        let uri = req.uri().clone();

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
                                self.http_for_connection(is_https, &req),
                                self.resolver.clone(),
                            );
                            socks.set_auth(proxy.raw_auth());
                            socks.set_version(version);
                            socks.set_dns_mode(dns_resolve);
                            socks.call(uri).await?
                        };

                        // Build an HTTPS connector.
                        let mut connector = self.build_https_connector(is_https, &req)?;

                        // Wrap the established SOCKS connection with TLS if needed.
                        let io = connector.call(EstablishedConn::new(conn, req)).await?;

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
                    let mut connector = self.build_https_connector(is_https, &req)?;

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
                    let io = connector.call(EstablishedConn::new(tunneled, req)).await?;

                    // Re-enable Nagle's algorithm if it was disabled earlier
                    if_tokio_rt!(block:{
                        if !self.config.nodelay {
                            io.as_ref().as_ref().set_nodelay(false)?;
                        }
                    });

                    return self.tunnel_conn_from_stream(io);
                }

                self.connect_auto_proxy(req.with_route_uri(proxy_uri), proxy)
                    .await
                    .map_err(ProxyConnect)
                    .map_err(Into::into)
            }
            #[cfg(unix)]
            Intercepted::Unix(unix_socket) => {
                trace!("connecting via Unix socket: {:?}", unix_socket);

                // Create a Unix connector with the specified socket path.
                let mut connector = self
                    .tls
                    .layer(UnixConnector::new(unix_socket))
                    .with_options(req.extra().get::<TlsOptions>())?;

                // If the target URI is HTTPS, establish a CONNECT tunnel over the Unix socket,
                // then upgrade the tunneled stream to TLS.
                if uri.is_https() {
                    // Use a dummy HTTP URI so the HTTPS connector works over the Unix socket.
                    let proxy_uri = ::http::Uri::from_static("http://localhost");

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
                    let io = connector.call(EstablishedConn::new(tunneled, req)).await?;

                    return self.tunnel_conn_from_stream(io);
                }

                // For plain HTTP, use the Unix connector directly.
                let io = connector.call(req).await?;

                self.conn_from_stream(io, None)
            }
        }
    }

    async fn connect_auto(self, req: ConnectRequest) -> Result<Conn, BoxError> {
        debug!("starting new connection: {:?}", req.uri());

        // Determine if a proxy should be used for this request.
        let intercepted = req
            .extra()
            .get::<ProxyMatcher>()
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

impl Service<ConnectRequest> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Conn, BoxError>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn call(&mut self, req: ConnectRequest) -> Self::Future {
        Box::pin(self.clone().connect_auto(req))
    }
}

// ===== impl Conn =====

impl Connection for Conn {
    fn connected(&self) -> Connected {
        let mut connected = self.stream.connected();

        if let Some(proxy) = &self.proxy {
            connected = connected.proxy(proxy.clone());
        }

        if self.tls_info {
            if let Some(tls_info) = self.stream.tls_info() {
                connected.extra(tls_info)
            } else {
                connected
            }
        } else {
            connected
        }
    }
}

impl AsyncRead for Conn {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self.project().stream, cx, buf)
    }
}

impl AsyncWrite for Conn {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write(self.project().stream, cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write_vectored(self.project().stream, cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_flush(self.project().stream, cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_shutdown(self.project().stream, cx)
    }
}

// ===== impl TlsConn =====

impl<T> Connection for TlsConn<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        let connected = self.stream.get_ref().connected();
        if self
            .stream
            .ssl()
            .selected_alpn_protocol()
            .is_some_and(|alpn| AlpnProtocol::HTTP2.eq(alpn))
        {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsConn<T> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        AsyncRead::poll_read(self.project().stream, cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsConn<T> {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        AsyncWrite::poll_write(self.project().stream, cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write_vectored(self.project().stream, cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), tokio::io::Error>> {
        AsyncWrite::poll_flush(self.project().stream, cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), tokio::io::Error>> {
        AsyncWrite::poll_shutdown(self.project().stream, cx)
    }
}

impl<T> TlsInfoFactory for TlsConn<T>
where
    SslStream<T>: TlsInfoFactory,
{
    #[inline]
    fn tls_info(&self) -> Option<TlsInfo> {
        self.stream.tls_info()
    }
}

// ===== impl PoisonPill =====

impl fmt::Debug for PoisonPill {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // print the address of the pill—this makes debugging issues much easier
        write!(
            f,
            "PoisonPill@{:p} {{ poisoned: {} }}",
            self.0,
            self.0.load(Ordering::Relaxed)
        )
    }
}

impl PoisonPill {
    /// Create a healthy (not poisoned) pill.
    #[inline]
    fn healthy() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
}

// ===== impl Connected =====

impl Connected {
    /// Create new `Connected` type with empty metadata.
    pub fn new() -> Connected {
        Connected {
            alpn: Alpn::None,
            proxy: Arc::new(ProxyIdentity::default()),
            extra: Extra::default(),
            poisoned: PoisonPill::healthy(),
        }
    }

    /// Attaches metadata copied into the extensions of every response.
    /// A later value replaces an earlier value of the same Rust type.
    /// Other connection clones retain their existing metadata.
    pub fn extra<T: Clone + Send + Sync + 'static>(mut self, extra: T) -> Connected {
        self.extra.insert(extra);
        self
    }

    /// Copies attached metadata into response extensions by concrete Rust type.
    /// Each stored metadata value is cloned once; connection configuration is omitted.
    #[inline]
    pub fn set_extras(&self, extensions: &mut Extensions) {
        self.extra.copy_metadata_to(extensions);
    }

    /// Set that the proxy was used for this connected transport.
    pub fn proxy(mut self, proxy: Intercept) -> Connected {
        let identity = Arc::make_mut(&mut self.proxy);
        identity.is_proxied = true;

        if let Some(auth) = proxy.basic_auth() {
            identity.auth.replace(auth.clone());
        }

        if let Some(headers) = proxy.custom_headers() {
            identity.headers.replace(headers.clone());
        }

        self
    }

    /// Determines if the connected transport is to an HTTP proxy.
    #[inline]
    pub fn is_proxied(&self) -> bool {
        self.proxy.is_proxied
    }

    /// Get the proxy identity information for the connected transport.
    #[inline]
    pub fn proxy_auth(&self) -> Option<&HeaderValue> {
        self.proxy.auth.as_ref()
    }

    /// Get the custom proxy headers for the connected transport.
    #[inline]
    pub fn proxy_headers(&self) -> Option<&HeaderMap> {
        self.proxy.headers.as_ref()
    }

    /// Set that the connected transport negotiated HTTP/2 as its next protocol.
    #[inline]
    pub fn negotiated_h2(mut self) -> Connected {
        self.alpn = Alpn::H2;
        self
    }

    /// Determines if the connected transport negotiated HTTP/2 as its next protocol.
    #[inline]
    pub fn is_negotiated_h2(&self) -> bool {
        self.alpn == Alpn::H2
    }

    /// Determine if this connection is poisoned
    #[inline]
    pub fn poisoned(&self) -> bool {
        self.poisoned.0.load(Ordering::Relaxed)
    }

    /// Poison this connection
    ///
    /// A poisoned connection will not be reused for subsequent requests by the pool
    #[allow(unused)]
    #[inline]
    pub fn poison(&self) {
        self.poisoned.0.store(true, Ordering::Relaxed);
        debug!(
            "connection was poisoned. this connection will not be reused for subsequent requests"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::atomic::AtomicUsize,
    };

    use ::http::{Uri, header::VIA};

    use super::*;
    use crate::{
        conn::net::TcpConnector,
        dns::{DynResolver, GaiResolver},
    };

    #[test]
    fn request_socket_options_configure_each_tcp_attempt() {
        let resolver = DynResolver::new(Arc::new(GaiResolver::new()));
        let connector = Connector::new(
            Config {
                proxies: Arc::new(Vec::new()),
                verbose: false,
                nodelay: false,
                tls_info: false,
            },
            HttpConnector::new(resolver.clone(), TcpConnector::new()),
            TlsConnector::builder().build(None).unwrap(),
            #[cfg(feature = "socks")]
            resolver,
        );
        let mut socket_options = SocketOptions::default();
        socket_options.set_local_addresses(Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST);
        let mut extra = Extra::default();
        extra.insert_config(socket_options.clone());
        let req =
            ConnectRequest::new(Uri::from_static("https://example.test/"), None, extra).unwrap();

        let http = connector.http_for_connection(true, &req);
        assert_eq!(http.socket_options(), &socket_options);
        assert!(http.nodelay());
        assert_eq!(connector.http.socket_options(), &SocketOptions::default());
    }

    /// Counts copies of user metadata, excluding shared handle clones.
    /// Acts as a response extra whose Clone increments the test's counter.
    /// The counter survives metadata drops so each insertion remains observable.
    #[derive(Debug)]
    struct CloneCount(Arc<AtomicUsize>);

    impl Clone for CloneCount {
        fn clone(&self) -> Self {
            self.0.fetch_add(1, Ordering::Relaxed);
            Self(self.0.clone())
        }
    }

    #[test]
    fn connected_shares_metadata_without_changing_response_extras() {
        let clones = Arc::new(AtomicUsize::new(0));
        let original = Connected::new()
            .extra(CloneCount(clones.clone()))
            .extra(String::from("original"));
        let changed = original
            .clone()
            .extra(CloneCount(clones.clone()))
            .extra(String::from("changed"));
        let proxy = crate::Proxy::http("http://localhost:8080")
            .unwrap()
            .basic_auth("user", "password")
            .custom_http_headers(HeaderMap::from_iter([(
                VIA,
                HeaderValue::from_static("1.1 localhost"),
            )]))
            .into_matcher();
        let proxy = match proxy.intercept(&"http://localhost/".parse().unwrap()) {
            Some(crate::proxy::Intercepted::Proxy(proxy)) => proxy,
            _ => unreachable!("expected HTTP proxy"),
        };
        let changed = changed.proxy(proxy).negotiated_h2();
        assert_eq!(clones.load(Ordering::Relaxed), 0);
        assert!(!original.is_proxied());
        assert!(!original.is_negotiated_h2());
        assert_eq!(original.proxy_auth(), None);
        assert_eq!(original.proxy_headers(), None);
        assert!(changed.is_proxied());
        assert!(changed.proxy_auth().is_some());
        assert_eq!(changed.proxy_headers().unwrap()[VIA], "1.1 localhost");

        for (connected, value) in [(&original, "original"), (&changed, "changed")] {
            let mut extensions = Extensions::new();
            connected.set_extras(&mut extensions);
            assert_eq!(extensions.get::<String>().unwrap(), value);
            assert!(extensions.get::<CloneCount>().is_some());
        }
        assert_eq!(clones.load(Ordering::Relaxed), 2);
        changed.poison();
        assert!(original.poisoned());
    }
}
