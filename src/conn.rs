//! [`ConnectStack`] applies connector layers and a deadline to [`svc::Connect`].
//! It dispatches each connection request to the [`stream`] or QUIC service, which returns a
//! [`Conn`] with the established [`Transport`] and its [`Connected`] metadata.

mod connected;
mod dialer;
mod layer;
#[cfg(feature = "http3")]
mod quic;
mod stream;
mod svc;

use std::time::{Duration, Instant};

use dialer::tcp;
use http::{Method, Request, Uri};
use layer::deadline::{Deadline, DeadlineLayer};
use tower::{
    BoxError, Layer, ServiceBuilder, ServiceExt,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, Either, MapErr, MapRequest},
};

pub(crate) use self::{
    connected::{Connected, HttpInfo},
    svc::{Io, Transport},
};
use crate::{
    config::connect::ConnectConfig, dns::DynResolver, error::map_timeout_to_connector_error,
    protocol::Protocol, proxy::Matcher as ProxyMatcher, rt::DynRuntime, tls,
};

/// Type-erased connection service passed through user-supplied layers.
pub type BoxedConnectService = BoxCloneSyncService<Unnameable, Conn, BoxError>;

/// Type-erased layer that wraps a [`BoxedConnectService`].
pub type BoxedConnectLayer =
    BoxCloneSyncServiceLayer<BoxedConnectService, Unnameable, Conn, BoxError>;

type LayeredConnect = MapRequest<
    MapErr<BoxedConnectService, fn(BoxError) -> BoxError>,
    fn(Request<ConnectConfig>) -> Unnameable,
>;

/// Establishes stream and QUIC transports under one connection deadline.
/// Without user layers [`svc::Connect`] is called directly; user layers see the request
/// behind [`Unnameable`]. Clones share the transports' state.
pub(crate) type ConnectStack = Deadline<Either<svc::Connect, LayeredConnect>>;

/// Client-wide transport settings, fixed at build.
pub(crate) struct Config {
    pub(crate) tcp: tcp::Config,
    pub(crate) tls: tls::Config,
    pub(crate) proxies: Vec<ProxyMatcher>,
    pub(crate) happy_eyeballs_timeout: Option<Duration>,
    pub(crate) verbose: bool,
}

/// Deadline attached to a connection request by [`Deadline`].
#[derive(Clone, Copy)]
struct ConnectDeadline(Instant);

/// Connection-specific operations on the internal request passed through the connector.
pub(crate) trait ConnectRequestExt {
    /// Builds an internal CONNECT request with the overrides selected by
    /// [`ConnectConfig::for_protocol`] against this connector's client configuration.
    #[must_use]
    fn new_connect(origin: Uri, protocol: Protocol, config: ConnectConfig) -> Self
    where
        Self: Sized;

    /// Returns the selected HTTP protocol mode for this connection attempt.
    #[must_use]
    fn protocol(&self) -> Protocol;

    /// Returns the outer connection deadline, if any.
    #[must_use]
    fn deadline(&self) -> Option<Instant>;
}

/// Opaque request passed through user-supplied connector layers.
/// Keeps transport selection, connection configuration and the connect deadline internal.
pub struct Unnameable(pub(super) Request<ConnectConfig>);

/// Established connection and metadata returned through connector middleware.
/// Protocol handshakes take the transport through `into_stream` or `into_quic`,
/// together with its metadata.
pub struct Conn {
    pub(crate) transport: Transport,
    pub(crate) connected: Connected,
}

// ===== impl Config =====

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp: tcp::Config::default(),
            tls: tls::Config::default(),
            proxies: Vec::new(),
            happy_eyeballs_timeout: Some(Duration::from_millis(300)),
            verbose: false,
        }
    }
}

// ===== impl ConnectStack =====

impl ConnectStack {
    /// Stacks the user's layers and the connection deadline over the transport router.
    pub(crate) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        config: Config,
        connect_config: &ConnectConfig,
        connect_timeout: Option<Duration>,
        layers: Vec<BoxedConnectLayer>,
    ) -> Result<Self, crate::Error> {
        let connect = svc::Connect::new(&runtime, resolver, config, connect_config)?;
        let service = if layers.is_empty() {
            Either::Left(connect)
        } else {
            let service = layers.iter().fold(
                BoxCloneSyncService::new(connect.map_request(|Unnameable(request)| request)),
                |service, layer| layer.layer(service),
            );
            Either::Right(
                service
                    .map_err(map_timeout_to_connector_error as fn(_) -> _)
                    .map_request(Unnameable as fn(_) -> _),
            )
        };

        Ok(ServiceBuilder::new()
            .layer(DeadlineLayer::new(connect_timeout, runtime))
            .service(service))
    }
}

// ===== impl ConnectRequestExt =====

impl ConnectRequestExt for Request<ConnectConfig> {
    fn new_connect(origin: Uri, protocol: Protocol, config: ConnectConfig) -> Self {
        let mut request = Self::new(config);
        *request.method_mut() = Method::CONNECT;
        *request.uri_mut() = origin;
        if protocol != Protocol::Auto {
            request.extensions_mut().insert(protocol);
        }
        request
    }

    #[inline]
    fn protocol(&self) -> Protocol {
        self.extensions()
            .get::<Protocol>()
            .copied()
            .unwrap_or(Protocol::Auto)
    }

    #[inline]
    fn deadline(&self) -> Option<Instant> {
        self.extensions().get::<ConnectDeadline>().map(|d| d.0)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "http3")]
    use std::sync::Arc;

    use super::*;
    #[cfg(feature = "http3")]
    use crate::ext::UriExt;

    #[cfg(feature = "http3")]
    fn test_connect_request(
        uri: Uri,
        protocol: Option<Protocol>,
        config: ConnectConfig,
    ) -> Request<ConnectConfig> {
        let protocol = protocol.unwrap_or(Protocol::Auto);
        let config = config.for_protocol(protocol, &ConnectConfig::default());
        Request::new_connect(uri.origin().unwrap(), protocol, config)
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
                tls: tls::Config {
                    cert_store: Some(
                        crate::tls::trust::CertStore::from_der_certs([&cert]).unwrap(),
                    ),
                    ..Default::default()
                },
                happy_eyeballs_timeout: delay,
                ..Default::default()
            };
            let connector = ConnectStack::new(
                runtime.clone(),
                resolver.clone(),
                config,
                &ConnectConfig::default(),
                Some(Duration::from_millis(500)),
                Vec::new(),
            )
            .unwrap();
            let request = test_connect_request(
                Uri::from_static("https://localhost/"),
                Some(Protocol::Http3),
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
        for (proxies, request_config) in [
            (vec![proxy()], ConnectConfig::default()),
            (Vec::new(), overridden),
        ] {
            let config = Config {
                proxies,
                ..Default::default()
            };
            let connector = ConnectStack::new(
                runtime.clone(),
                DynResolver::new(Arc::new(NoDns)),
                config,
                &ConnectConfig::default(),
                None,
                Vec::new(),
            )
            .unwrap();
            let request = test_connect_request(
                Uri::from_static("https://localhost/"),
                Some(Protocol::Http3),
                request_config,
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
