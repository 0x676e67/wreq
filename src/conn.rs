//! Connector composition, established connections and response metadata.
//! [`layer`] handles proxy routing, stream TLS and connection timeouts;
//! [`transport`] handles dialing and QUIC endpoints. Protocol pools live in the client.

pub(crate) mod config;
pub(crate) mod request;

mod layer;
mod verbose;

pub(super) mod transport;

use std::{
    any::{TypeId, type_name},
    fmt::{self, Debug, Formatter},
    future::Future,
    io::{self, IoSlice},
    iter,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use ::http::{Extensions, HeaderMap, HeaderValue};
use bytes::Bytes;
use config::ConfigSet;
use futures_util::future::BoxFuture;
use layer::{
    proxy::{ProxyConnector, ProxyLayer},
    timeout::{Timeout, TimeoutLayer},
    tls::{TlsConnector, TlsLayer},
};
use pin_project_lite::pin_project;
use request::ConnectRequest;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream;
use tower::{
    BoxError, Layer, Service, ServiceBuilder, ServiceExt,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, MapRequestLayer},
};
use transport::{BindOptions, SocketConnector};
#[cfg(feature = "http3")]
use {
    crate::Protocol,
    futures_util::future::Either,
    layer::proxy::{QuicProxyConnector, QuicProxyLayer},
};

use crate::{
    dns::DynResolver,
    error::map_timeout_to_connector_error,
    proxy::{Matcher as ProxyMatcher, matcher::Intercept},
    rt::RuntimeHandle,
    tls::{AlpnProtocol, TlsInfo, config::TlsConnectorBuilder, connector::MaybeHttpsStream},
};

/// Concrete stream path; [`Connector`] wraps both transports in any user layers.
type Stack = Timeout<TlsConnector<ProxyConnector<SocketConnector>>>;

/// Type-erased transport service retained after custom connector layers are composed.
pub type BoxedTransportConnector = BoxCloneSyncService<Unnameable, Conn, BoxError>;

/// Type-erased layer applied while assembling a [`BoxedTransportConnector`].
pub type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedTransportConnector, Unnameable, Conn, BoxError>;

/// Client settings for proxy selection, tracing and post-handshake socket policy.
/// Request-specific bindings and protocol configuration travel in [`ConnectRequest`].
#[derive(Clone)]
pub(crate) struct Config {
    pub proxies: Arc<Vec<ProxyMatcher>>,
    pub verbose: bool,
    pub nodelay: bool,
    pub tls_info: bool,
}

/// Establishes stream and QUIC transports through one shared middleware stack.
/// Without user layers, each transport retains its concrete connection service.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Connector {
    Direct {
        stream: Stack,
        #[cfg(feature = "http3")]
        quic: Timeout<QuicProxyConnector>,
    },
    Layered(BoxedTransportConnector),
}

/// Builds the stream and QUIC paths from common client settings.
/// Client TLS contexts are compiled before connection middleware is initialized.
#[must_use]
pub(crate) struct ConnectorBuilder {
    config: Config,
    runtime: RuntimeHandle,
    tls: TlsConnectorBuilder,
    timeout: Option<Duration>,
    bind_options: BindOptions,
    layers: Vec<BoxedConnectorLayer>,
}

/// Drives one selected transport or the shared middleware stack without extra boxing.
pub(crate) enum Connecting {
    Stream {
        future: <Stack as Service<ConnectRequest>>::Future,
    },
    #[cfg(feature = "http3")]
    Quic {
        future: <Timeout<QuicProxyConnector> as Service<ConnectRequest>>::Future,
    },
    Layered {
        future: BoxFuture<'static, Result<Conn, BoxError>>,
    },
}

// ===== impl Connector =====

impl Connector {
    /// Starts configuring both transports with common runtime, TLS and connection policy.
    pub(crate) fn builder(
        runtime: RuntimeHandle,
        tls: TlsConnectorBuilder,
        config: Config,
    ) -> ConnectorBuilder {
        ConnectorBuilder {
            runtime,
            tls,
            config,
            timeout: None,
            bind_options: BindOptions::default(),
            layers: Vec::new(),
        }
    }
}

impl Service<ConnectRequest> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::Direct {
                stream,
                #[cfg(feature = "http3")]
                quic,
            } => {
                // Both built-in paths are always ready; user layers reserve capacity outside.
                ready!(stream.poll_ready(cx))?;
                #[cfg(feature = "http3")]
                ready!(quic.poll_ready(cx))?;
                Poll::Ready(Ok(()))
            }
            Self::Layered(service) => service.poll_ready(cx),
        }
    }

    fn call(&mut self, request: ConnectRequest) -> Self::Future {
        match self {
            Self::Direct {
                stream,
                #[cfg(feature = "http3")]
                quic,
            } => {
                #[cfg(feature = "http3")]
                if request.resolved_protocol() == Protocol::Http3 {
                    return Connecting::Quic {
                        future: quic.call(request),
                    };
                }
                Connecting::Stream {
                    future: stream.call(request),
                }
            }
            Self::Layered(service) => Connecting::Layered {
                future: service.call(Unnameable(request)),
            },
        }
    }
}

// ===== impl Connecting =====

impl Future for Connecting {
    type Output = Result<Conn, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Stream { future } => Pin::new(future).poll(cx),
            #[cfg(feature = "http3")]
            Self::Quic { future } => Pin::new(future).poll(cx),
            Self::Layered { future } => future.as_mut().poll(cx),
        }
    }
}

// ===== impl ConnectorBuilder =====

impl ConnectorBuilder {
    /// Sets the connection deadline for both transport paths.
    #[inline]
    pub(crate) fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the local addresses and interface inherited by TCP and QUIC sockets.
    #[inline]
    pub(crate) fn bind_options(mut self, bind_options: BindOptions) -> Self {
        self.bind_options = bind_options;
        self
    }

    /// Adds middleware shared by stream and QUIC connection attempts.
    #[inline]
    pub(crate) fn layers(mut self, layers: Vec<BoxedConnectorLayer>) -> Self {
        self.layers = layers;
        self
    }

    /// Attaches DNS and compiles client TLS contexts, then assembles both transport paths.
    /// QUIC endpoints remain lazy until a connection future is polled.
    /// Returns the socket bindings used to normalize request pool identities.
    pub(crate) fn build(
        self,
        tcp: transport::TcpConnector<()>,
        resolver: DynResolver,
        config_set: ConfigSet,
    ) -> Result<(Connector, BindOptions), crate::Error> {
        // With user layers, one outer timeout covers the complete middleware call.
        let transport_timeout = self.layers.is_empty().then_some(self.timeout).flatten();
        let tcp = tcp
            .enforce_http(false)
            .set_connect_timeout(self.timeout)
            .set_bind_options(&self.bind_options)
            .build(resolver.clone());

        #[cfg(feature = "http3")]
        let quic = {
            let tls = self.tls.clone().build_quic(config_set.clone())?;
            ServiceBuilder::new()
                .layer(TimeoutLayer::new(self.runtime.clone(), transport_timeout))
                .layer(QuicProxyLayer::new(
                    self.runtime.clone(),
                    self.config.proxies.clone(),
                    #[cfg(feature = "socks")]
                    tcp.clone(),
                    #[cfg(feature = "socks")]
                    resolver.clone(),
                ))
                .service(
                    transport::QuicConnector::builder(
                        self.runtime.clone(),
                        tls,
                        self.config.tls_info,
                    )
                    .bind_options(self.bind_options.clone())
                    .build(resolver.clone()),
                )
        };

        let stream = {
            let tls = self.tls.build(config_set)?;
            ServiceBuilder::new()
                .layer(TimeoutLayer::new(self.runtime.clone(), transport_timeout))
                .layer(TlsLayer::new(
                    self.config.verbose,
                    self.config.nodelay,
                    self.config.tls_info,
                ))
                .layer(ProxyLayer::new(self.config.proxies, tls, resolver))
                .service(SocketConnector::new(
                    #[cfg(unix)]
                    self.runtime.clone(),
                    tcp,
                ))
        };

        let connector = Connector::Direct {
            stream,
            #[cfg(feature = "http3")]
            quic,
        };

        if self.layers.is_empty() {
            return Ok((connector, self.bind_options));
        }

        let service = self.layers.iter().fold(
            BoxCloneSyncService::new(
                ServiceBuilder::new()
                    .layer(MapRequestLayer::new(|request: Unnameable| request.0))
                    .service(connector),
            ),
            |service, layer| layer.layer(service),
        );

        // Keep the built-in timeout outside user layers so it covers their work too.
        // The final mapping also handles a tower timeout supplied by the caller.
        let service = TimeoutLayer::new(self.runtime, self.timeout)
            .layer(service)
            .map_err(map_timeout_to_connector_error);

        Ok((
            Connector::Layered(BoxCloneSyncService::new(service)),
            self.bind_options,
        ))
    }
}

/// Opaque request passed through user-supplied connector layers.
/// Keeps transport selection and connection configuration internal.
pub struct Unnameable(pub(super) ConnectRequest);

/// Byte-stream I/O passed to HTTP/1 or HTTP/2 after connection setup.
pub(crate) trait AsyncConn: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

/// An async connection with optional TLS certificate information.
trait AsyncConnWithInfo: AsyncConn + Connection + TlsInfoFactory {}

impl<T> AsyncConn for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

impl<T> AsyncConnWithInfo for T where T: AsyncConn + Connection + TlsInfoFactory {}

/// Established connection and metadata returned through connector middleware.
/// Protocol handshakes take the stream or QUIC resources together with their metadata.
/// A QUIC endpoint remains owned until it can move into the HTTP/3 driver.
pub struct Conn {
    #[cfg(feature = "http3")]
    pub(crate) inner: Either<Box<dyn AsyncConn>, (::quic::Connection, ::quic::Endpoint)>,
    #[cfg(not(feature = "http3"))]
    pub(crate) inner: Box<dyn AsyncConn>,
    pub(crate) connected: Connected,
}

pin_project! {
    /// TLS stream that adds negotiated ALPN to the underlying connection metadata.
    /// Forwards async I/O and exposes the peer's TLS certificate information.
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

/// Local and remote socket addresses captured after connecting a transport.
/// Stored in connection metadata and attached to response extensions.
/// Custom transports may omit this information.
#[derive(Clone, Debug)]
pub(crate) struct HttpInfo {
    pub(crate) remote_addr: SocketAddr,
    pub(crate) local_addr: SocketAddr,
}

/// Metadata describing the established transport and its negotiated protocol.
/// Carries proxy details and extra values copied into response extensions.
/// Clones share the poison flag so reuse can be disabled from any response.
#[derive(Debug, Clone)]
pub struct Connected {
    alpn: Alpn,
    proxy: Arc<ProxyIdentity>,
    metadata: Metadata,
    poisoned: PoisonPill,
}

/// Shared response metadata, ordered by concrete type.
/// Edits copy shared handles; values are cloned only when exported to a response.
#[derive(Clone, Default)]
#[expect(
    clippy::type_complexity,
    reason = "Keep the single-use metadata entry representation inline"
)]
struct Metadata(Option<Arc<[(TypeId, Arc<dyn MetadataValue>)]>>);

trait MetadataValue: Send + Sync {
    fn copy_to(&self, extensions: &mut Extensions);
    fn type_name(&self) -> &'static str;
}

/// Describes a type returned by a connector.
pub trait Connection {
    /// Return metadata describing the connection.
    fn connected(&self) -> Connected;

    /// Returns the socket's remote address; a proxied stream reports the proxy.
    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }
}

/// A trait for extracting TLS information from a connection.
pub trait TlsInfoFactory {
    #[inline]
    fn tls_info(&self) -> Option<TlsInfo> {
        None
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

// ===== impl SslStream =====

impl<T> TlsInfoFactory for SslStream<T> {
    #[inline]
    fn tls_info(&self) -> Option<TlsInfo> {
        Some(extract_tls_info(self))
    }
}

fn extract_tls_info<S>(ssl_stream: &SslStream<S>) -> TlsInfo {
    let ssl = ssl_stream.ssl();
    TlsInfo {
        peer_certificate: ssl
            .peer_certificate()
            .and_then(|cert| cert.to_der().ok())
            .map(Bytes::from),
        peer_certificate_chain: ssl.peer_cert_chain().map(|chain| {
            chain
                .iter()
                .filter_map(|cert| cert.to_der().ok())
                .map(Bytes::from)
                .collect()
        }),
    }
}

// ===== impl MaybeHttpsStream =====

impl<T: TlsInfoFactory> TlsInfoFactory for MaybeHttpsStream<T> {
    fn tls_info(&self) -> Option<TlsInfo> {
        match self {
            MaybeHttpsStream::Https(tls) => tls.tls_info(),
            MaybeHttpsStream::Http(_) => None,
        }
    }
}

// ===== impl quic::Connection =====

#[cfg(feature = "http3")]
impl TlsInfoFactory for quic::Connection {
    fn tls_info(&self) -> Option<TlsInfo> {
        let chain = self
            .peer_identity()?
            .downcast::<Vec<btls::x509::X509>>()
            .ok()?;
        Some(TlsInfo {
            peer_certificate: chain
                .first()
                .and_then(|cert| cert.to_der().ok())
                .map(Bytes::from),
            peer_certificate_chain: Some(
                chain
                    .iter()
                    .filter_map(|cert| cert.to_der().ok())
                    .map(Bytes::from)
                    .collect(),
            ),
        })
    }
}

// ===== impl PoisonPill =====

impl fmt::Debug for PoisonPill {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // print the address of the pill鈥攖his makes debugging issues much easier
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

// ===== impl HttpInfo =====

impl HttpInfo {
    /// Get the remote address of the transport used.
    pub(crate) fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the local address of the transport used.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

// ===== impl Connected =====

impl Connected {
    /// Create new `Connected` type with empty metadata.
    pub fn new() -> Connected {
        Connected {
            alpn: Alpn::None,
            proxy: Arc::new(ProxyIdentity::default()),
            metadata: Metadata::default(),
            poisoned: PoisonPill::healthy(),
        }
    }

    /// Attaches metadata copied into the extensions of every response.
    /// A later value replaces an earlier value of the same Rust type.
    /// Other connection clones retain their existing metadata.
    pub fn extra<T: Clone + Send + Sync + 'static>(mut self, extra: T) -> Connected {
        self.metadata.insert(extra);
        self
    }

    /// Copies attached metadata into response extensions by concrete Rust type.
    /// Each stored metadata value is cloned once.
    #[inline]
    pub fn set_extras(&self, extensions: &mut Extensions) {
        self.metadata.copy_to(extensions);
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

// ===== impl Metadata =====

impl Metadata {
    fn insert<T: Clone + Send + Sync + 'static>(&mut self, value: T) {
        let entries = self.0.as_deref().unwrap_or_default();
        let id = TypeId::of::<T>();
        let (index, replaced) = match entries.binary_search_by_key(&id, |entry| entry.0) {
            Ok(index) => (index, 1),
            Err(index) => (index, 0),
        };
        let value: Arc<dyn MetadataValue> = Arc::new(value);
        self.0 = Some(
            entries[..index]
                .iter()
                .cloned()
                .chain(iter::once((id, value)))
                .chain(entries[index + replaced..].iter().cloned())
                .collect(),
        );
    }

    fn copy_to(&self, extensions: &mut Extensions) {
        for (_, value) in self.0.as_deref().unwrap_or_default() {
            value.as_ref().copy_to(extensions);
        }
    }
}

impl Debug for Metadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(
                self.0
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(|(_, value)| value.as_ref().type_name()),
            )
            .finish()
    }
}

// ===== impl MetadataValue =====

impl<T: Clone + Send + Sync + 'static> MetadataValue for T {
    fn copy_to(&self, extensions: &mut Extensions) {
        extensions.insert(self.clone());
    }

    fn type_name(&self) -> &'static str {
        type_name::<T>()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use ::http::header::VIA;

    use super::*;

    impl Conn {
        #[cfg(feature = "tokio-rt")]
        pub(crate) fn test(stream: tokio::io::DuplexStream) -> Self {
            Self {
                #[cfg(feature = "http3")]
                inner: Either::Left(Box::new(stream)),
                #[cfg(not(feature = "http3"))]
                inner: Box::new(stream),
                connected: Connected::new(),
            }
        }
    }

    impl TlsInfoFactory for tokio::io::DuplexStream {}
    impl Connection for tokio::io::DuplexStream {
        fn connected(&self) -> Connected {
            Connected::new()
        }
    }

    /// Counts metadata value clones independently of shared handle clones.
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
            .extra(42_u32)
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
            assert_eq!(
                extensions.get::<u32>().copied(),
                (value == "changed").then_some(42)
            );
        }
        assert_eq!(clones.load(Ordering::Relaxed), 2);
        changed.poison();
        assert!(original.poisoned());
    }
}
