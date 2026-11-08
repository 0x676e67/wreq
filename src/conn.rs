//! Connector composition, established connections and response metadata.
//! [`ConnectorBuilder`] stacks [`layer`] middleware (deadline, proxy routes, stream TLS) on the
//! [`transport`] dialers with `ServiceBuilder`, as the client does. Protocol pools live in the
//! client.

mod layer;
mod verbose;

pub(crate) mod config;
pub(crate) mod request;
pub(super) mod transport;

use std::{
    any::{TypeId, type_name},
    fmt::{self, Debug, Formatter},
    io::{self, IoSlice},
    iter,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use ::http::{Extensions, HeaderMap, HeaderValue};
use btls::x509::X509Ref;
use bytes::Bytes;
use config::ConfigSet;
use layer::{
    proxy::{ProxyConnector, ProxyLayer},
    timeout::{Timeout, TimeoutLayer},
};
use pin_project_lite::pin_project;
use request::ConnectRequest;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream;
use tower::{
    BoxError, Layer, ServiceBuilder, ServiceExt,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, Either},
};
use transport::{BindOptions, SocketConnector, TcpConnectorBuilder};
#[cfg(feature = "http3")]
use {
    crate::protocol::TransportKind,
    btls::x509::X509,
    layer::proxy::quic::{QuicProxyConnector, QuicProxyLayer},
    std::ops::Deref,
    transport::{QuicConnector, Transports},
};

use crate::{
    dns::DynResolver,
    error::map_timeout_to_connector_error,
    proxy::{Matcher as ProxyMatcher, matcher::Intercept},
    rt::DynRuntime,
    tls::{AlpnProtocol, TlsInfo, config::TlsBuilder, connector::MaybeHttpsStream},
};

/// Type-erased transport service retained after custom connector layers are composed.
pub type BoxedTransportConnector = BoxCloneSyncService<Unnameable, Conn, BoxError>;

/// Type-erased layer applied while assembling a [`BoxedTransportConnector`].
pub type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedTransportConnector, Unnameable, Conn, BoxError>;

cfg_select! {
    feature = "http3" => {
        type Direct =
            Transports<ProxyConnector<SocketConnector>, QuicProxyConnector<QuicConnector>>;
    }
    _ => {
        type Direct = ProxyConnector<SocketConnector>;
    }
}

/// Establishes stream and QUIC transports under one connection deadline.
/// Without user layers the built-in transports are called directly; user layers see them
/// behind [`Unnameable`]. Clones share the transports' state.
pub(crate) type Connector =
    Timeout<Either<Direct, BoxCloneSyncService<ConnectRequest, Conn, BoxError>>>;

/// Client settings for proxy selection, tracing and post-handshake socket policy.
/// Request-specific bindings and protocol configuration travel in [`ConnectRequest`].
#[derive(Clone)]
pub(crate) struct Config {
    pub proxies: Arc<Vec<ProxyMatcher>>,
    pub verbose: bool,
    pub nodelay: bool,
    pub tls_info: bool,
}

/// Builds the stream and QUIC paths from common client settings.
/// Client TLS contexts are compiled before connection middleware is initialized.
#[must_use]
pub(crate) struct ConnectorBuilder {
    config: Config,
    runtime: DynRuntime,
    tls: TlsBuilder,
    connect_timeout: Option<Duration>,
    bind_options: BindOptions,
    happy_eyeballs_timeout: Option<Duration>,
    layers: Vec<BoxedConnectorLayer>,
}

// ===== impl ConnectorBuilder =====

impl ConnectorBuilder {
    /// Starts configuring both transports with common runtime, TLS and connection policy.
    pub(crate) fn new(runtime: DynRuntime, tls: TlsBuilder, config: Config) -> Self {
        Self {
            runtime,
            tls,
            config,
            connect_timeout: None,
            bind_options: BindOptions::default(),
            happy_eyeballs_timeout: Some(transport::HAPPY_EYEBALLS_TIMEOUT),
            layers: Vec::new(),
        }
    }

    /// Sets the deadline of each connector call, covering user layers and both transports.
    #[inline]
    pub(crate) fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the Happy Eyeballs delay shared by TCP and QUIC address races.
    #[inline]
    pub(crate) fn happy_eyeballs_timeout(
        mut self,
        happy_eyeballs_timeout: Option<Duration>,
    ) -> Self {
        self.happy_eyeballs_timeout = happy_eyeballs_timeout;
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
    pub(crate) fn build(
        self,
        tcp: TcpConnectorBuilder,
        resolver: DynResolver,
        config_set: ConfigSet,
    ) -> Result<Connector, crate::Error> {
        let tcp = tcp
            .set_bind_options(&self.bind_options)
            .set_happy_eyeballs_timeout(self.happy_eyeballs_timeout)
            .build(resolver.clone());

        #[cfg(feature = "http3")]
        let quic = {
            let tls = self.tls.clone().build_quic(config_set.clone())?;
            QuicConnector::builder(self.runtime.clone(), tls, self.config.tls_info)
                .bind_options(self.bind_options)
                .happy_eyeballs_timeout(self.happy_eyeballs_timeout)
                .build(resolver.clone())?
        };

        let socket = SocketConnector::new(
            #[cfg(unix)]
            self.runtime.clone(),
            tcp,
        );

        #[cfg(feature = "http3")]
        let quic = ServiceBuilder::new()
            .layer(QuicProxyLayer::new(
                self.config.proxies.clone(),
                #[cfg(feature = "socks")]
                socket.clone(),
            ))
            .service(quic);

        let stream = ServiceBuilder::new()
            .layer(ProxyLayer::new(
                self.config,
                self.tls.build(config_set)?,
                resolver,
            ))
            .service(socket);

        #[cfg(feature = "http3")]
        let direct = Transports::new(stream, quic);
        #[cfg(not(feature = "http3"))]
        let direct = stream;

        let service = if self.layers.is_empty() {
            Either::Left(direct)
        } else {
            let service = self.layers.iter().fold(
                BoxCloneSyncService::new(direct.map_request(|Unnameable(request)| request)),
                |service, layer| layer.layer(service),
            );
            // The connector's deadline also covers user layers; this maps a tower timeout
            // supplied among them.
            Either::Right(BoxCloneSyncService::new(
                service
                    .map_err(map_timeout_to_connector_error)
                    .map_request(Unnameable),
            ))
        };

        Ok(ServiceBuilder::new()
            .layer(TimeoutLayer::new(self.connect_timeout, self.runtime))
            .service(service))
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
/// Protocol handshakes take the transport through `into_stream` or `into_quic`,
/// together with its metadata.
pub struct Conn {
    pub(crate) transport: Transport,
    pub(crate) connected: Connected,
}

/// Transport carried by a [`Conn`]: a byte stream for HTTP/1 and HTTP/2, or QUIC for HTTP/3.
/// A QUIC endpoint remains owned until it can move into the HTTP/3 driver.
pub(crate) enum Transport {
    /// A TCP or Unix stream after any proxy handshake and TLS.
    Stream(Box<dyn AsyncConn>),
    /// A QUIC connection and the endpoint that drives it.
    #[cfg(feature = "http3")]
    Quic {
        connection: ::quic::Connection,
        endpoint: ::quic::Endpoint,
    },
}

/// A connector returned a transport other than the one the selected protocol runs over.
#[cfg(feature = "http3")]
#[derive(Debug)]
pub(crate) struct TransportMismatch {
    expected: TransportKind,
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
#[expect(clippy::type_complexity)]
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
    fn remote_addr(&self) -> Option<SocketAddr>;
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

    #[inline]
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.stream.get_ref().remote_addr()
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
        let ssl = self.ssl();
        Some(tls_info(
            ssl.peer_certificate().as_deref(),
            ssl.peer_cert_chain(),
        ))
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
        let chain = self.peer_identity()?.downcast::<Vec<X509>>().ok()?;
        Some(tls_info(
            chain.first().map(Deref::deref),
            Some(chain.iter().map(Deref::deref)),
        ))
    }
}

/// Converts the peer's leaf certificate and chain to DER, skipping certificates that fail.
fn tls_info<'a>(
    leaf: Option<&X509Ref>,
    chain: Option<impl IntoIterator<Item = &'a X509Ref>>,
) -> TlsInfo {
    let der = |cert: &X509Ref| cert.to_der().ok().map(Bytes::from);
    TlsInfo {
        peer_certificate: leaf.and_then(der),
        peer_certificate_chain: chain.map(|chain| chain.into_iter().filter_map(der).collect()),
    }
}

// ===== impl Transport =====

impl Transport {
    /// Takes the byte stream for an HTTP/1 or HTTP/2 handshake.
    pub(crate) fn into_stream(self) -> Result<Box<dyn AsyncConn>, BoxError> {
        match self {
            Self::Stream(io) => Ok(io),
            #[cfg(feature = "http3")]
            Self::Quic { .. } => Err(TransportMismatch {
                expected: TransportKind::Stream,
            }
            .into()),
        }
    }

    /// Takes the QUIC connection and its endpoint for an HTTP/3 handshake.
    #[cfg(feature = "http3")]
    pub(crate) fn into_quic(self) -> Result<(::quic::Connection, ::quic::Endpoint), BoxError> {
        match self {
            Self::Quic {
                connection,
                endpoint,
            } => Ok((connection, endpoint)),
            Self::Stream(_) => Err(TransportMismatch {
                expected: TransportKind::Quic,
            }
            .into()),
        }
    }
}

// ===== impl TransportMismatch =====

#[cfg(feature = "http3")]
impl std::error::Error for TransportMismatch {}

#[cfg(feature = "http3")]
impl fmt::Display for TransportMismatch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self.expected {
            TransportKind::Stream => "stream connection returned QUIC",
            TransportKind::Quic => "QUIC connection returned a stream",
        })
    }
}

// ===== impl PoisonPill =====

impl fmt::Debug for PoisonPill {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // print the address of the pill, which makes debugging issues much easier
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
        pub(crate) fn test(stream: tokio::io::DuplexStream) -> Self {
            Self {
                transport: Transport::Stream(Box::new(stream)),
                connected: Connected::new(),
            }
        }
    }

    impl TlsInfoFactory for tokio::io::DuplexStream {}
    impl Connection for tokio::io::DuplexStream {
        fn connected(&self) -> Connected {
            Connected::new()
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            None
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

    /// QUIC dials race addresses with the connector's Happy Eyeballs delay, and try them in order
    /// without one.
    #[cfg(feature = "http3")]
    #[tokio::test]
    async fn quic_dials_follow_the_happy_eyeballs_delay() {
        use std::net::{Ipv4Addr, UdpSocket};

        struct Fixed(Vec<SocketAddr>);

        impl crate::dns::Resolve for Fixed {
            fn resolve(&self, _: crate::dns::Name) -> crate::dns::Resolving {
                let addrs: crate::dns::Addrs = Box::new(self.0.clone().into_iter());
                Box::pin(std::future::ready(Ok(addrs)))
            }
        }

        let (server_config, cert) = transport::test_server_config();
        let server =
            ::quic::Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        // Bound without replying, so a dial to it stays pending until the deadline.
        let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let resolver = DynResolver::new(Arc::new(Fixed(vec![
            blackhole.local_addr().unwrap(),
            server.local_addr().unwrap(),
        ])));
        let runtime = DynRuntime::new(crate::rt::tokio::TokioRuntime);
        for delay in [Some(Duration::from_millis(10)), None] {
            let tls = TlsBuilder::new()
                .cert_store(crate::tls::trust::CertStore::from_der_certs([&cert]).unwrap());
            let config = Config {
                proxies: Arc::new(Vec::new()),
                verbose: false,
                nodelay: false,
                tls_info: false,
            };
            let connector = ConnectorBuilder::new(runtime.clone(), tls, config)
                .connect_timeout(Some(Duration::from_millis(500)))
                .happy_eyeballs_timeout(delay)
                .build(
                    transport::TcpConnector::builder(runtime.clone()),
                    resolver.clone(),
                    ConfigSet::default(),
                )
                .unwrap();
            let request = ConnectRequest::test(
                ::http::Uri::from_static("https://localhost/"),
                Some(crate::Protocol::Http3),
                ConfigSet::default(),
            );
            let serve = async {
                let _accepted = server.accept().await.unwrap().await;
                std::future::pending::<()>().await
            };
            let result = tokio::select! {
                result = connector.oneshot(request) => result,
                () = serve => unreachable!(),
            };
            match delay {
                Some(_) => {
                    let (connection, _) = result.unwrap().transport.into_quic().unwrap();
                    assert_eq!(connection.remote_address(), server.local_addr().unwrap());
                }
                None => assert!(result.err().unwrap().is::<crate::error::TimedOut>()),
            }
        }
    }

    /// Client rules and request overrides that QUIC cannot use fail before any DNS lookup.
    #[cfg(feature = "http3")]
    #[tokio::test]
    async fn quic_rejects_unsupported_proxy_routes_before_dns() {
        struct NoDns;

        impl crate::dns::Resolve for NoDns {
            fn resolve(&self, name: crate::dns::Name) -> crate::dns::Resolving {
                panic!("an unsupported proxy route resolved {name}")
            }
        }

        let runtime = DynRuntime::new(crate::rt::tokio::TokioRuntime);
        let proxy = || {
            crate::Proxy::all("http://proxy:8080")
                .unwrap()
                .into_matcher()
        };
        let mut overridden = ConfigSet::default();
        overridden.insert(proxy());
        for (proxies, config_set) in [
            (vec![proxy()], ConfigSet::default()),
            (Vec::new(), overridden),
        ] {
            let config = Config {
                proxies: Arc::new(proxies),
                verbose: false,
                nodelay: false,
                tls_info: false,
            };
            let connector = ConnectorBuilder::new(runtime.clone(), TlsBuilder::new(), config)
                .build(
                    transport::TcpConnector::builder(runtime.clone()),
                    DynResolver::new(Arc::new(NoDns)),
                    ConfigSet::default(),
                )
                .unwrap();
            let request = ConnectRequest::test(
                ::http::Uri::from_static("https://localhost/"),
                Some(crate::Protocol::Http3),
                config_set,
            );
            let error = connector
                .oneshot(request)
                .await
                .err()
                .expect("QUIC must reject a proxy route");
            assert!(error.is::<crate::error::ProxyMismatch>());
            assert_eq!(
                error.to_string(),
                "HTTP/3 requires a quic:// proxy or SOCKS5 with the socks feature"
            );
        }
    }
}
