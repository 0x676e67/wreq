//! Connector contract and composition: [`Connector::new`] puts [`Builtin`] under one
//! [`deadline`], which routes each request to the [`stream`] or QUIC path. Both paths reach hosts
//! through the shared [`dialer`] and return a [`Conn`] with the [`Connected`] metadata they build.

mod connected;
mod deadline;
#[cfg(feature = "http3")]
mod quic;
mod stream;

pub(crate) mod config;
pub(super) mod dialer;
pub(crate) mod request;

use std::{
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use config::ConfigSet;
pub(crate) use connected::{Connected, HttpInfo};
use deadline::{Deadline, DeadlineLayer};
use dialer::{BindOptions, Dialer, TcpConfig};
#[cfg(all(test, feature = "http3"))]
pub(crate) use quic::test_server_config;
use request::ConnectRequest;
use stream::StreamConnector;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{
    BoxError, Layer, Service, ServiceBuilder, ServiceExt,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, Either as ServiceEither},
};
#[cfg(feature = "http3")]
use {
    crate::protocol::TransportKind,
    futures_util::future::Either,
    quic::QuicConnector,
    std::fmt::{self, Formatter},
};

use crate::{
    dns::DynResolver,
    error::map_timeout_to_connector_error,
    proxy::{Intercepted, Matcher as ProxyMatcher},
    rt::DynRuntime,
    tls::TlsConfig,
};

/// Type-erased transport service retained after custom connector layers are composed.
pub type BoxedTransportConnector = BoxCloneSyncService<Unnameable, Conn, BoxError>;

/// Type-erased layer applied while assembling a [`BoxedTransportConnector`].
pub type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedTransportConnector, Unnameable, Conn, BoxError>;

/// Establishes stream and QUIC transports under one connection deadline.
/// Without user layers the built-in transports are called directly; user layers see them
/// behind [`Unnameable`]. Clones share the transports' state.
pub(crate) type Connector =
    Deadline<ServiceEither<Builtin, BoxCloneSyncService<ConnectRequest, Conn, BoxError>>>;

/// The built-in transports: routes each request to the stream or QUIC path its protocol
/// runs over. Clones share each path's state.
#[derive(Clone)]
pub(crate) struct Builtin {
    stream: StreamConnector,
    #[cfg(feature = "http3")]
    quic: QuicConnector,
}

/// Client-wide connector settings, fixed at build.
pub(crate) struct ConnectorConfig {
    pub(crate) tcp: TcpConfig,
    pub(crate) tls: TlsConfig,
    pub(crate) proxies: Vec<ProxyMatcher>,
    pub(crate) bind_options: BindOptions,
    pub(crate) happy_eyeballs_timeout: Option<Duration>,
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) verbose: bool,
    pub(crate) layers: Vec<BoxedConnectorLayer>,
}

// ===== impl ConnectorConfig =====

impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            tcp: TcpConfig::default(),
            tls: TlsConfig::default(),
            proxies: Vec::new(),
            bind_options: BindOptions::default(),
            happy_eyeballs_timeout: Some(Duration::from_millis(300)),
            connect_timeout: None,
            verbose: false,
            layers: Vec::new(),
        }
    }
}

// ===== impl Connector =====

impl Connector {
    /// Compiles client TLS, attaches DNS and assembles both transport paths under one deadline.
    /// QUIC endpoints remain lazy until a connection future is polled.
    pub(crate) fn new(
        config: ConnectorConfig,
        runtime: DynRuntime,
        resolver: DynResolver,
        config_set: &ConfigSet,
    ) -> Result<Self, crate::Error> {
        let proxies = Arc::new(config.proxies);
        let dialer = Dialer::new(
            runtime.clone(),
            resolver,
            config.tcp,
            config.bind_options,
            config.happy_eyeballs_timeout,
        );

        #[cfg(feature = "http3")]
        let quic = QuicConnector::new(
            dialer.clone(),
            config.tls.clone().quic(config_set)?,
            proxies.clone(),
        )?;
        let stream = StreamConnector::new(
            dialer,
            config.tls.stream(config_set)?,
            proxies,
            config.verbose,
        );
        let builtin = Builtin {
            stream,
            #[cfg(feature = "http3")]
            quic,
        };

        let service = if config.layers.is_empty() {
            ServiceEither::Left(builtin)
        } else {
            let service = config.layers.iter().fold(
                BoxCloneSyncService::new(builtin.map_request(|Unnameable(request)| request)),
                |service, layer| layer.layer(service),
            );
            ServiceEither::Right(BoxCloneSyncService::new(
                service
                    .map_err(map_timeout_to_connector_error)
                    .map_request(Unnameable),
            ))
        };

        Ok(ServiceBuilder::new()
            .layer(DeadlineLayer::new(config.connect_timeout, runtime))
            .service(service))
    }
}

/// Tries the request's proxy rule, then the client's rules in order.
fn intercept(request: &ConnectRequest, proxies: &[ProxyMatcher]) -> Option<Intercepted> {
    request
        .config_override::<ProxyMatcher>()
        .and_then(|proxy| proxy.intercept(request.uri()))
        .or_else(|| {
            proxies
                .iter()
                .find_map(|proxy| proxy.intercept(request.uri()))
        })
}

// ===== impl Builtin =====

impl Service<ConnectRequest> for Builtin {
    type Response = Conn;
    type Error = BoxError;
    #[cfg(feature = "http3")]
    type Future = Either<
        <StreamConnector as Service<ConnectRequest>>::Future,
        <QuicConnector as Service<ConnectRequest>>::Future,
    >;
    #[cfg(not(feature = "http3"))]
    type Future = <StreamConnector as Service<ConnectRequest>>::Future;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.stream.poll_ready(cx))?;
        #[cfg(feature = "http3")]
        ready!(self.quic.poll_ready(cx))?;
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: ConnectRequest) -> Self::Future {
        cfg_select! {
            feature = "http3" => match request.resolved_protocol().transport() {
                TransportKind::Stream => Either::Left(self.stream.call(request)),
                TransportKind::Quic => Either::Right(self.quic.call(request)),
            },
            _ => self.stream.call(request),
        }
    }
}

/// Opaque request passed through user-supplied connector layers.
/// Keeps transport selection and connection configuration internal.
pub struct Unnameable(pub(super) ConnectRequest);

/// Byte-stream I/O passed to HTTP/1 or HTTP/2 after connection setup.
pub(crate) trait AsyncConn: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

impl<T> AsyncConn for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

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

#[cfg(test)]
mod tests {
    use super::*;

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

        let (server_config, cert) = test_server_config();
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
            let config = ConnectorConfig {
                tls: TlsConfig {
                    cert_store: Some(
                        crate::tls::trust::CertStore::from_der_certs([&cert]).unwrap(),
                    ),
                    ..Default::default()
                },
                happy_eyeballs_timeout: delay,
                connect_timeout: Some(Duration::from_millis(500)),
                ..Default::default()
            };
            let connector = Connector::new(
                config,
                runtime.clone(),
                resolver.clone(),
                &ConfigSet::default(),
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
            let config = ConnectorConfig {
                proxies,
                ..Default::default()
            };
            let connector = Connector::new(
                config,
                runtime.clone(),
                DynResolver::new(Arc::new(NoDns)),
                &ConfigSet::default(),
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
