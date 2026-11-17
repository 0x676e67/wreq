//! [`ConnectStack`] applies connector layers and a deadline to [`svc::Connect`].
//! It routes each attempt to the [`stream`] or QUIC service, which returns a [`Conn`]
//! with the established [`Transport`] and its [`Connected`] metadata.

mod connected;
mod key;
mod layer;
#[cfg(feature = "http3")]
mod quic;
mod stream;
mod svc;

pub(super) mod dialer;

use std::time::{Duration, Instant};

pub(crate) use connected::{Connected, HttpInfo};
use dialer::tcp;
use http::{Method, Request};
pub(crate) use key::{CommonOverrides, ConnectionKey};
use layer::deadline::{Deadline, DeadlineLayer};
#[cfg(all(test, feature = "http3"))]
pub(crate) use quic::test_server_config;
pub(crate) use svc::{Io, Transport};
#[cfg(all(test, feature = "http3"))]
pub(crate) use tests::test_connect_request;
#[cfg(test)]
pub(crate) use tests::test_connect_request_with_config;
use tower::{
    BoxError, Layer, ServiceBuilder, ServiceExt,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, Either, MapErr, MapRequest},
};

use crate::{
    config::connect::{ConnectConfig, ConnectConfigRef},
    dns::DynResolver,
    error::map_timeout_to_connector_error,
    proxy::Matcher as ProxyMatcher,
    rt::DynRuntime,
    tls,
};

/// Type-erased connection service passed through user-supplied layers.
pub type BoxedConnectService = BoxCloneSyncService<Unnameable, Conn, BoxError>;

/// Type-erased layer that wraps a [`BoxedConnectService`].
pub type BoxedConnectLayer =
    BoxCloneSyncServiceLayer<BoxedConnectService, Unnameable, Conn, BoxError>;

type LayeredConnect = MapRequest<
    MapErr<BoxedConnectService, fn(BoxError) -> BoxError>,
    fn(ConnectAttempt) -> Unnameable,
>;

/// Establishes stream and QUIC transports under one connection deadline.
/// Without user layers [`svc::Connect`] is called directly; user layers see it
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

/// One connection attempt under an optional deadline.
/// [`svc::Connect`] replaces `()` with the selected transport route.
#[derive(Clone)]
pub(crate) struct ConnectAttempt<R = ()> {
    request: Request<ConnectionKey>,
    deadline: Option<Instant>,
    route: R,
}

/// Connection-specific operations on the HTTP request passed to the connector.
pub(crate) trait ConnectRequestExt {
    /// Builds an internal CONNECT request using the origin and configuration of a frozen key.
    fn from_key(
        key: ConnectionKey,
        request_config: ConnectConfig,
        client_config: ConnectConfig,
    ) -> Self
    where
        Self: Sized;

    /// Borrows the connection options with request values taking precedence.
    fn connect_config(&self) -> ConnectConfigRef<'_>;
}

/// Opaque request passed through user-supplied connector layers.
/// Keeps transport selection, connection configuration and the connect deadline internal.
pub struct Unnameable(pub(super) ConnectAttempt);

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
    /// Stacks the user's layers and the connection deadline over the router.
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

impl ConnectRequestExt for Request<ConnectionKey> {
    fn from_key(
        key: ConnectionKey,
        request_config: ConnectConfig,
        client_config: ConnectConfig,
    ) -> Self {
        let origin = key.origin().clone();
        let mut request = Self::new(key);
        *request.method_mut() = Method::CONNECT;
        *request.uri_mut() = origin;
        if !request_config.is_empty() || !client_config.is_empty() {
            request
                .extensions_mut()
                .insert((request_config, client_config));
        }
        request
    }

    fn connect_config(&self) -> ConnectConfigRef<'_> {
        self.extensions()
            .get::<(ConnectConfig, ConnectConfig)>()
            .map(|(local, base)| ConnectConfigRef::new(local, base))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use http::Uri;
    #[cfg(feature = "http3")]
    use {crate::config::connect::Cached, std::sync::Arc};

    use super::*;
    use crate::protocol::Protocol;

    pub(crate) fn test_connect_request_with_config(
        uri: &Uri,
        protocol: Protocol,
        request_config: ConnectConfig,
        client_config: &ConnectConfig,
    ) -> Request<ConnectionKey> {
        let config = ConnectConfigRef::new(&request_config, client_config);
        let key = ConnectionKey::for_request(uri, protocol, config).unwrap();
        Request::from_key(key, request_config, client_config.clone())
    }

    #[cfg(feature = "http3")]
    pub(crate) fn test_connect_request(
        uri: Uri,
        protocol: Option<Protocol>,
        config: ConnectConfig,
    ) -> Request<ConnectionKey> {
        test_connect_request_with_config(
            &uri,
            protocol.unwrap_or(Protocol::Auto),
            config,
            &ConnectConfig::default(),
        )
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
                ::http::Uri::from_static("https://localhost/"),
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
        overridden.insert(Cached::new(proxy()));
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
                ::http::Uri::from_static("https://localhost/"),
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
