//! Connector contract and composition: [`Connector::new`] stacks the [`layer`] middleware every
//! connection passes over [`TransportConnector`], the [`svc`] that routes each request to the
//! [`stream`] or QUIC path. Both paths reach hosts through the shared [`dialer`] and return a
//! [`Conn`]: the [`Transport`] they establish with the [`Connected`] metadata they build.

mod connected;
mod layer;
#[cfg(feature = "http3")]
mod quic;
mod route;
mod stream;
mod svc;

pub(super) mod dialer;
pub(crate) mod request;

use std::time::Duration;

pub(crate) use connected::{Connected, HttpInfo};
use dialer::{BindOptions, Dialer, tcp};
use layer::deadline::{Deadline, DeadlineLayer};
pub(crate) use svc::{Io, Transport};
use svc::{TransportConnector, TransportRequest};
use tower::{
    BoxError, Layer, ServiceBuilder, ServiceExt,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer, Either},
};
#[cfg(all(test, feature = "http3"))]
pub(crate) use {quic::test_server_config, svc::TransportMismatch};

use crate::{
    config::connect::ConfigSet, dns::DynResolver, error::map_timeout_to_connector_error,
    proxy::Matcher as ProxyMatcher, rt::DynRuntime, tls,
};

/// Type-erased transport service retained after custom connector layers are composed.
pub type BoxedTransportConnector = BoxCloneSyncService<Unnameable, Conn, BoxError>;

/// Type-erased layer applied while assembling a [`BoxedTransportConnector`].
pub type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedTransportConnector, Unnameable, Conn, BoxError>;

/// Establishes stream and QUIC transports under one connection deadline.
/// Without user layers the transport connector is called directly; user layers see it
/// behind [`Unnameable`]. Clones share the transports' state.
pub(crate) type Connector =
    Deadline<Either<TransportConnector, BoxCloneSyncService<TransportRequest, Conn, BoxError>>>;

/// Client-wide connector settings, fixed at build.
pub(crate) struct Config {
    pub(crate) tcp: tcp::Config,
    pub(crate) tls: tls::Config,
    pub(crate) proxies: Vec<ProxyMatcher>,
    pub(crate) bind_options: BindOptions,
    pub(crate) happy_eyeballs_timeout: Option<Duration>,
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) verbose: bool,
    pub(crate) layers: Vec<BoxedConnectorLayer>,
}

/// Opaque request passed through user-supplied connector layers.
/// Keeps transport selection, connection configuration and the connect deadline internal.
pub struct Unnameable(pub(super) TransportRequest);

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
    /// Builds the dialer and the transport connector, then stacks the user's layers and the
    /// connection deadline over them.
    pub(crate) fn new(
        config: Config,
        runtime: DynRuntime,
        resolver: DynResolver,
        config_set: &ConfigSet,
    ) -> Result<Self, crate::Error> {
        let dialer = Dialer::new(
            runtime.clone(),
            resolver,
            config.tcp,
            config.bind_options,
            config.happy_eyeballs_timeout,
        );
        let connector = TransportConnector::new(
            dialer,
            config.tls,
            config.proxies,
            config.verbose,
            config_set,
        )?;

        let service = if config.layers.is_empty() {
            Either::Left(connector)
        } else {
            let service = config.layers.iter().fold(
                BoxCloneSyncService::new(connector.map_request(|Unnameable(request)| request)),
                |service, layer| layer.layer(service),
            );
            Either::Right(BoxCloneSyncService::new(
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "http3")]
    use {super::request::ConnectRequest, std::sync::Arc};

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
            let config = Config {
                tls: tls::Config {
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
            let config = Config {
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
