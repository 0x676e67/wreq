//! Outbound connection establishment for TCP, Unix, and QUIC transports.
//!
//! [`ConnectService`] applies user-supplied connector layers and a connection timeout, returning
//! a [`Conn`] with the established [`Transport`] and [`Connected`] metadata.

mod connected;
mod dialer;
mod layer;
#[cfg(feature = "http3")]
mod quic;
mod stream;

use std::{
    hash::Hash,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use dialer::{Dialer, tcp};
#[cfg(feature = "http3")]
use futures_util::future;
use http::Uri;
use layer::{
    timeout::{Timeout, TimeoutLayer},
    verbose::{self, Verbose},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{
    BoxError, Layer, Service, ServiceBuilder, ServiceExt,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, Either, MapErr},
};

pub(crate) use self::connected::{Connected, HttpInfo};
#[cfg(feature = "http2")]
use crate::http2::Http2Options;
use crate::{
    config::ConnectConfig,
    dns::DynResolver,
    error::map_timeout_to_connector_error,
    group::Group,
    http1::Http1Options,
    identity::Identity,
    protocol::Protocol,
    proxy::{Intercepted, Matcher as ProxyMatcher},
    rt::DynRuntime,
    tls,
};
#[cfg(feature = "http3")]
use crate::{http3::Http3Options, quic::QuicOptions};

/// Type-erased connection service passed through user-supplied layers.
pub type BoxedConnectService = BoxCloneSyncService<Unnameable, Conn, BoxError>;

/// Type-erased layer that wraps a [`BoxedConnectService`].
pub type BoxedConnectLayer =
    BoxCloneSyncServiceLayer<BoxedConnectService, Unnameable, Conn, BoxError>;

/// Connection service with optional user middleware and a total connection timeout.
pub(crate) type ConnectService =
    Timeout<Either<Connect, MapErr<BoxedConnectService, fn(BoxError) -> BoxError>>>;

/// Matches proxy rules and dispatches connection requests to the stream or QUIC service.
///
/// Request-level proxy overrides take precedence over the client's shared proxy list.
/// Clones share the proxy list and both transport services.
#[derive(Clone)]
pub(crate) struct Connect {
    proxies: Arc<Vec<ProxyMatcher>>,
    stream: Verbose<stream::Connect>,
    #[cfg(feature = "http3")]
    quic: quic::Connect,
}

/// Client-wide transport, TLS, proxy, and timeout settings assembled at client build time.
///
/// Consumed by [`Connect::new`] to initialize the shared TCP dialer, TLS contexts, and
/// outer timeout layer.
pub(crate) struct Config {
    pub(crate) tcp_config: tcp::Config,
    pub(crate) tls_config: tls::Config,
    pub(crate) proxies: Vec<ProxyMatcher>,
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) happy_eyeballs_timeout: Option<Duration>,
    pub(crate) verbose: bool,
}

/// Connection request carrying the normalized origin URI, selected [`Protocol`], and options.
///
/// Prepared before pool lookup, used to derive reuse [`Identity`] keys, and wrapped in
/// [`Unnameable`] when dialing through connector layers on a pool miss.
#[derive(Clone)]
pub(crate) struct Request<T> {
    uri: Uri,
    protocol: Protocol,
    body: T,
}

/// Opaque connection request passed through user-supplied connector layers.
///
/// Wraps the internal [`Request`] so protocol selection and connection options stay private.
pub struct Unnameable(pub(super) Request<ConnectConfig>);

/// Connection request paired with the proxy rule matched for its target URI, if any.
///
/// Handed off from [`Connect`] to the selected stream or QUIC connector.
pub(crate) struct Routed {
    request: Request<ConnectConfig>,
    proxy: Option<Intercepted>,
}

/// Established transport paired with its [`Connected`] metadata.
///
/// Returned by [`ConnectService`] and passed through any user-supplied connector layers
/// before handing the transport to the HTTP/1, HTTP/2, or HTTP/3 handshake.
pub struct Conn {
    pub(crate) transport: Transport,
    pub(crate) connected: Connected,
}

/// Established transport carried by a [`Conn`].
///
/// For QUIC, the `Endpoint` stays attached until ownership moves into the HTTP/3 driver.
pub(crate) enum Transport {
    /// A TCP or Unix stream after any proxy handshake and TLS.
    Stream(Box<dyn Io>),
    /// A QUIC connection and the endpoint that drives it.
    #[cfg(feature = "http3")]
    Quic {
        connection: ::quic::Connection,
        endpoint: ::quic::Endpoint,
    },
}

/// Type-erased byte stream handed to HTTP/1 or HTTP/2 after proxy and TLS handshakes.
///
/// Socket controls stay on [`rt::Connection`](crate::rt::Connection); local and remote
/// addresses are captured in [`Connected`] before boxing.
pub(crate) trait Io: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

impl<T> Io for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

// ===== impl Config =====

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_config: tcp::Config::default(),
            tls_config: tls::Config::default(),
            proxies: Vec::new(),
            connect_timeout: None,
            happy_eyeballs_timeout: Some(Duration::from_millis(300)),
            verbose: false,
        }
    }
}

// ===== impl Connect =====

impl Connect {
    /// Builds the connection service with user layers and the total timeout.
    pub(crate) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        Config {
            tcp_config,
            tls_config,
            proxies,
            connect_timeout,
            happy_eyeballs_timeout,
            verbose,
        }: Config,
        connect_config: &ConnectConfig,
        layers: Vec<BoxedConnectLayer>,
    ) -> crate::Result<ConnectService> {
        let dialer = Dialer::new(
            runtime.clone(),
            resolver.clone(),
            tcp_config,
            connect_timeout,
            happy_eyeballs_timeout,
        );

        let connect = Self {
            proxies: Arc::new(proxies),
            #[cfg(feature = "http3")]
            quic: quic::Connect::new(
                runtime.clone(),
                resolver.clone(),
                tls_config.clone(),
                connect_config,
                #[cfg(feature = "socks")]
                dialer.clone(),
                happy_eyeballs_timeout,
            )?,
            stream: ServiceBuilder::new()
                .option_layer(verbose::layer(verbose))
                .service(stream::Connect::new(
                    dialer,
                    tls_config,
                    connect_config,
                    #[cfg(feature = "socks")]
                    resolver,
                )?),
        };

        let service = if layers.is_empty() {
            Either::Left(connect)
        } else {
            let service = layers
                .iter()
                .fold(BoxCloneSyncService::new(connect), |service, layer| {
                    layer.layer(service)
                });
            Either::Right(service.map_err(map_timeout_to_connector_error as _))
        };

        Ok(ServiceBuilder::new()
            .layer(TimeoutLayer::new(connect_timeout, runtime))
            .service(service))
    }
}

impl Service<Unnameable> for Connect {
    type Response = Conn;
    type Error = BoxError;
    type Future = cfg_select! {
        feature = "http3" => {
            future::Either<
                <Verbose<stream::Connect> as Service<Routed>>::Future,
                <quic::Connect as Service<Routed>>::Future,
            >
        }
        _ => { <Verbose<stream::Connect> as Service<Routed>>::Future }
    };

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.stream.poll_ready(cx))?;
        #[cfg(feature = "http3")]
        ready!(self.quic.poll_ready(cx))?;
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, Unnameable(request): Unnameable) -> Self::Future {
        let proxy = request
            .body()
            .get_ref::<ProxyMatcher>()
            .and_then(|proxy| proxy.intercept(request.uri()))
            .or_else(|| {
                self.proxies
                    .iter()
                    .find_map(|proxy| proxy.intercept(request.uri()))
            });
        let routed = Routed { request, proxy };

        cfg_select! {
            feature = "http3" => {
                if routed.request.protocol() == Protocol::Http3 {
                    future::Either::Right(self.quic.call(routed))
                } else {
                    future::Either::Left(self.stream.call(routed))
                }
            }
            _ => self.stream.call(routed),
        }
    }
}

// ===== impl Request =====

impl<T> Request<T> {
    /// Pairs a normalized origin and selected protocol with the connection options.
    #[must_use]
    pub(crate) fn new(uri: Uri, protocol: Protocol, body: T) -> Self {
        Self {
            uri,
            protocol,
            body,
        }
    }

    /// Returns the origin URI for this connection.
    #[must_use]
    fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Borrows the request body.
    #[must_use]
    pub(crate) fn body(&self) -> &T {
        &self.body
    }

    /// Returns the protocol selected for this connection attempt.
    #[must_use]
    pub(crate) fn protocol(&self) -> Protocol {
        self.protocol
    }
}

impl Request<ConnectConfig> {
    /// Captures non-protocol overrides shared by connection pool and TLS session keys.
    #[must_use]
    pub(crate) fn reuse_scope(config: &ConnectConfig) -> impl Eq + Hash + Send + Sync + 'static {
        (
            config
                .override_if_different::<Group>(PartialEq::eq)
                .cloned(),
            config
                .override_if_different::<ProxyMatcher>(PartialEq::eq)
                .cloned(),
            config
                .override_if_different::<Ipv4Addr>(PartialEq::eq)
                .cloned(),
            config
                .override_if_different::<Ipv6Addr>(PartialEq::eq)
                .cloned(),
            config
                .override_if_different::<Arc<str>>(PartialEq::eq)
                .cloned(),
        )
    }

    /// Builds a pool or QUIC address-token [`Identity`] for `protocol` without consuming `self`.
    ///
    /// Only overrides relevant to `protocol` that differ from client defaults participate in the
    /// key.
    #[must_use]
    pub(crate) fn to_identity(&self, protocol: Protocol) -> Identity {
        macro_rules! key {
            ($($(#[$attr:meta])* $option:ty),+ $(,)?) => {
                Identity::new((
                    self.uri.clone(),
                    protocol,
                    Self::reuse_scope(self.body()),
                    $(
                        $(#[$attr])*
                        self.body().override_if_different::<$option>(PartialEq::eq).cloned(),
                    )+
                ))
            };
        }

        match protocol {
            Protocol::Auto => key!(
                tls::TlsOptions,
                Http1Options,
                #[cfg(feature = "http2")]
                Http2Options,
            ),
            Protocol::Http1 => key!(tls::TlsOptions, Http1Options),
            #[cfg(feature = "http2")]
            Protocol::Http2 => key!(tls::TlsOptions, Http2Options),
            #[cfg(feature = "http3")]
            Protocol::Http3 => key!(Http3Options, QuicOptions),
        }
    }
}

// ===== impl Transport =====

impl Transport {
    /// Extracts the byte stream for HTTP/1 or HTTP/2.
    ///
    /// Only fails if a connector layer returned a QUIC connection for a stream protocol.
    pub(crate) fn into_stream(self) -> Result<Box<dyn Io>, BoxError> {
        match self {
            Self::Stream(io) => Ok(io),
            #[cfg(feature = "http3")]
            Self::Quic { .. } => Err("stream connection returned QUIC".into()),
        }
    }

    /// Extracts the QUIC connection and endpoint for HTTP/3.
    ///
    /// Only fails if a connector layer returned a byte stream for HTTP/3.
    #[cfg(feature = "http3")]
    pub(crate) fn into_quic(self) -> Result<(::quic::Connection, ::quic::Endpoint), BoxError> {
        match self {
            Self::Quic {
                connection,
                endpoint,
            } => Ok((connection, endpoint)),
            Self::Stream(_) => Err("QUIC connection returned a stream".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "http3")]
    use crate::ext::UriExt;

    #[cfg(feature = "http3")]
    fn test_connect_request(
        uri: Uri,
        protocol: Protocol,
        connect_config: ConnectConfig,
    ) -> Unnameable {
        Unnameable(Request::new(
            uri.origin().unwrap(),
            protocol,
            connect_config,
        ))
    }

    impl Conn {
        pub(crate) fn test(stream: tokio::io::DuplexStream) -> Self {
            Self {
                transport: Transport::Stream(Box::new(stream)),
                connected: Connected::new(),
            }
        }
    }

    /// QUIC dials race addresses with the connector's Happy Eyeballs delay, and try them in order
    /// without one.
    #[cfg(feature = "http3")]
    #[tokio::test]
    async fn quic_dials_follow_the_happy_eyeballs_delay() {
        use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

        struct Fixed(Vec<SocketAddr>);

        impl crate::dns::Resolve for Fixed {
            fn resolve(&self, _: crate::dns::Name) -> crate::dns::Resolving {
                let addrs: crate::dns::Addrs = Box::new(self.0.clone().into_iter());
                Box::pin(std::future::ready(Ok(addrs)))
            }
        }

        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".into(),
            "127.0.0.1".into(),
            "::1".into(),
        ])
        .unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_config = ::quic::ServerConfig::with_crypto(Arc::new(
            ::quic::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        let cert = cert.cert.der().to_vec();
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
            let config = Config {
                tls_config: tls::Config {
                    cert_store: Some(
                        crate::tls::trust::CertStore::from_der_certs([&cert]).unwrap(),
                    ),
                    ..Default::default()
                },
                connect_timeout: Some(Duration::from_millis(500)),
                happy_eyeballs_timeout: delay,
                ..Default::default()
            };
            let connector = Connect::new(
                runtime.clone(),
                resolver.clone(),
                config,
                &ConnectConfig::default(),
                Vec::new(),
            )
            .unwrap();
            let request = test_connect_request(
                Uri::from_static("https://localhost/"),
                Protocol::Http3,
                ConnectConfig::default(),
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
        let mut overridden = ConnectConfig::default();
        overridden.insert(proxy());
        for (proxies, connect_config) in [
            (vec![proxy()], ConnectConfig::default()),
            (Vec::new(), overridden),
        ] {
            let config = Config {
                proxies,
                ..Default::default()
            };
            let connector = Connect::new(
                runtime.clone(),
                DynResolver::new(Arc::new(NoDns)),
                config,
                &ConnectConfig::default(),
                Vec::new(),
            )
            .unwrap();
            let request = test_connect_request(
                Uri::from_static("https://localhost/"),
                Protocol::Http3,
                connect_config,
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
