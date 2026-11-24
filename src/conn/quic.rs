//! QUIC connection service supporting direct UDP, MASQUE CONNECT-UDP, and SOCKS5 UDP routes.
//!
//! QUIC handshakes use the outer connector's timeout. The SOCKS UDP control connection also
//! uses the TCP dialer's address-race timeout.

mod endpoint;
mod masque;
#[cfg(feature = "socks")]
mod socks;

#[cfg(feature = "socks")]
use std::net::IpAddr;
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use endpoint::Endpoints;
use futures_util::future::{self, BoxFuture, Either, Ready};
#[cfg(feature = "socks")]
use netty::proxy::socks::{DnsResolve, udp::Address};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::Notify;
#[cfg(feature = "socks")]
use tower::ServiceExt;
use tower::{BoxError, Service};

use crate::{
    config::ConnectConfig,
    conn::{
        Conn, Request, Routed,
        dialer::{ConnectError, Race, bind_interface, resolve},
    },
    dns::{DynResolver, SocketAddrs},
    error::{ProxyConnect, ProxyMismatch},
    proxy::{Intercepted, matcher::Intercept, quic_port},
    rt::{DynRuntime, Timer as _},
    tls,
};
#[cfg(feature = "socks")]
use crate::{
    conn::dialer::{Dial, Dialer},
    rt::AsyncUdpSocket,
};

type ConnectFuture = BoxFuture<'static, Result<Conn, BoxError>>;

/// Minimum UDP payload size a proxy tunnel must carry for QUIC Initial datagrams
/// ([RFC 9000 Section 14.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1)).
pub(super) const TUNNEL_MTU: u16 = 1200;

const QUIC_PROXY_REQUIRED: &str =
    "HTTP/3 requires a quic:// proxy or SOCKS5 with the socks feature";
const URI_MISSING_HOST: &str = "HTTP/3 URI has no host";

/// Established proxy UDP tunnel handed to [`Endpoints::finish_tunnel`].
///
/// `remote` is the virtual socket peer address used by the inner endpoint, not the TLS target;
/// `ended` notifies the endpoint watcher when the underlying tunnel closes.
struct Tunnel<S> {
    socket: S,
    remote: SocketAddr,
    ended: Arc<Notify>,
}

/// Tower [`Service`] establishing QUIC connections for HTTP/3.
///
/// Supports direct UDP dials, MASQUE (`quic://`) CONNECT-UDP tunnels, and SOCKS5 UDP relays.
/// Clones share the underlying [`Endpoints`] and network dependencies.
#[derive(Clone)]
pub(crate) struct Connect {
    state: Arc<State>,
    #[cfg(feature = "socks")]
    dialer: Dialer,
}

/// Shared QUIC endpoints and network dependencies owned by [`Connect`].
///
/// Kept behind an [`Arc`] so connection futures can run independently of the service handle.
struct State {
    endpoints: Endpoints,
    network: Network,
}

/// Runtime, DNS resolver, and Happy Eyeballs settings shared by QUIC dial paths.
///
/// Passed to [`Endpoints`] and proxy helpers for hostname lookup, address racing, and timers.
struct Network {
    runtime: DynRuntime,
    resolver: DynResolver,
    happy_eyeballs_timeout: Option<Duration>,
}

// ===== impl Connect =====

impl Connect {
    /// Creates a QUIC connector; UDP endpoints are opened lazily on first use.
    pub(super) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        tls_config: tls::Config,
        connect_config: &ConnectConfig,
        #[cfg(feature = "socks")] dialer: Dialer,
        happy_eyeballs_timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(Self {
            state: Arc::new(State {
                endpoints: Endpoints::new(tls_config, connect_config)?,
                network: Network {
                    runtime,
                    resolver,
                    happy_eyeballs_timeout,
                },
            }),
            #[cfg(feature = "socks")]
            dialer,
        })
    }
}

impl Service<Routed> for Connect {
    type Response = Conn;
    type Error = BoxError;
    type Future = Either<ConnectFuture, Ready<Result<Conn, BoxError>>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, Routed { request, proxy }: Routed) -> Self::Future {
        let Some(proxy) = proxy else {
            return Either::Left(Box::pin(self.state.clone().connect(request)));
        };

        match proxy {
            Intercepted::Proxy(proxy) => match proxy.uri().scheme_str() {
                // Keep the proxy error for invalid authorities from environment rules.
                Some("quic") if let Err(error) = quic_port(proxy.uri()) => {
                    Either::Right(future::err(ProxyConnect::Message(error).into()))
                }
                Some("quic") => {
                    Either::Left(Box::pin(connect_masque(self.state.clone(), request, proxy)))
                }
                #[cfg(feature = "socks")]
                Some(scheme @ ("socks5" | "socks5h")) => {
                    let dns = if scheme == "socks5h" {
                        DnsResolve::Remote
                    } else {
                        DnsResolve::Local
                    };
                    Either::Left(Box::pin(connect_socks(
                        self.state.clone(),
                        self.dialer.clone(),
                        request,
                        proxy,
                        dns,
                    )))
                }
                _ => Either::Right(future::err(ProxyMismatch(QUIC_PROXY_REQUIRED).into())),
            },
            #[cfg(unix)]
            Intercepted::Unix(_) => {
                Either::Right(future::err(ProxyMismatch(QUIC_PROXY_REQUIRED).into()))
            }
        }
    }
}

// ===== impl State =====

impl State {
    async fn connect(self: Arc<Self>, request: Request<ConnectConfig>) -> Result<Conn, BoxError> {
        self.endpoints.connect(&self.network, request).await
    }
}

// ===== impl Network =====

impl Network {
    /// Resolves the host to a list of socket addresses.
    fn resolve(
        &self,
        host: &str,
        port: u16,
        explicit_port: bool,
    ) -> impl Future<Output = Result<SocketAddrs, ConnectError>> {
        resolve(host, port, explicit_port, move |name| {
            self.resolver.resolve(name)
        })
    }

    /// Races multiple socket addresses to establish a connection using the Happy Eyeballs
    /// algorithm.
    fn race<C, F>(
        &self,
        addrs: SocketAddrs,
        addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),
        start: impl FnMut(SocketAddr) -> Result<F, ConnectError>,
    ) -> impl Future<Output = Result<C, ConnectError>>
    where
        F: Future<Output = Result<C, ConnectError>> + Unpin,
    {
        Race::new(self.happy_eyeballs_timeout, move |delay| {
            self.runtime.sleep(delay)
        })
        .run(addrs, addresses, start)
    }
}

/// Connects to a remote server through a MASQUE proxy.
async fn connect_masque(
    state: Arc<State>,
    request: Request<ConnectConfig>,
    proxy: Intercept,
) -> Result<Conn, BoxError> {
    let State { endpoints, network } = state.as_ref();
    // Reject invalid local settings before opening the proxy connection.
    let config = endpoints.tunnel_config(&request)?;
    let uri = request.uri();
    let tunnel = async {
        let template = masque::template(&proxy)?;
        let outer = endpoints
            .connect_proxy(network, &request, template.proxy())
            .await?;
        masque::open(outer, network.runtime.clone(), template, &proxy, uri).await
    }
    .await
    .map_err(ProxyConnect::Source)?;

    endpoints
        .finish_tunnel(&network.runtime, uri, &config, tunnel)
        .await
}

/// Connects to a remote server through a SOCKS proxy.
#[cfg(feature = "socks")]
async fn connect_socks(
    state: Arc<State>,
    dialer: Dialer,
    request: Request<ConnectConfig>,
    proxy: Intercept,
    dns: DnsResolve,
) -> Result<Conn, BoxError> {
    let State { endpoints, network } = state.as_ref();
    let config = endpoints.tunnel_config(&request)?;
    let uri = request.uri();
    let host = crate::util::strip_ipv6_brackets(uri.host().ok_or(URI_MISSING_HOST)?);
    let port = uri.port_u16().unwrap_or(443);
    let config = &config;
    let open_relay = |remote| relay_socket(&network.runtime, request.body(), remote);
    let connect_target = |target| {
        let dial = dialer
            .clone()
            .oneshot(Dial::tcp(proxy.uri().clone(), request.body(), false));
        let tunnel = socks::open(dial, &proxy, target, &network.resolver, &open_relay);
        async move {
            endpoints
                .finish_tunnel(&network.runtime, uri, config, tunnel.await?)
                .await
                .map_err(endpoint::handshake_error("SOCKS5 target handshake error"))
        }
    };

    if dns == DnsResolve::Remote {
        let target = match host.parse::<IpAddr>() {
            Ok(ip) => Address::Ip((ip, port).into()),
            Err(_) => Address::Domain(host.into(), port),
        };
        return Ok(connect_target(target).await?);
    }

    let addresses = network.resolve(host, port, uri.port().is_some()).await?;
    // Race complete handshakes; the local socket bindings apply to the proxy, not these targets.
    Ok(network
        .race(addresses, (None, None), |address| {
            let attempt: BoxFuture<'_, _> = Box::pin(connect_target(Address::Ip(address)));
            Ok(attempt)
        })
        .await?)
}

/// Binds and registers a UDP relay socket using the request's local socket bindings.
#[cfg(feature = "socks")]
fn relay_socket(
    runtime: &DynRuntime,
    config: &ConnectConfig,
    remote: SocketAddr,
) -> Result<Box<dyn AsyncUdpSocket>, BoxError> {
    if matches!(
        (
            config.get_ref::<Ipv4Addr>(),
            config.get_ref::<Ipv6Addr>(),
            remote
        ),
        (Some(_), None, SocketAddr::V6(_)) | (None, Some(_), SocketAddr::V4(_))
    ) {
        return Err("relay address does not match local bindings".into());
    }
    Ok(runtime.udp_socket(bind_udp(config, remote)?)?)
}

/// Binds a non-blocking UDP socket matching the address family of `remote`.
fn bind_udp(config: &ConnectConfig, remote_addr: SocketAddr) -> Result<UdpSocket, ConnectError> {
    let address = match remote_addr {
        SocketAddr::V4(_) => SocketAddr::from((
            config
                .get_ref::<Ipv4Addr>()
                .copied()
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
            0,
        )),
        SocketAddr::V6(_) => SocketAddr::from((
            config
                .get_ref::<Ipv6Addr>()
                .copied()
                .unwrap_or(Ipv6Addr::UNSPECIFIED),
            0,
        )),
    };

    // Create a new UDP socket for the appropriate address family.
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .map_err(ConnectError::m("quic open error"))?;

    // Set the socket to non-blocking mode before binding it to an interface.
    socket
        .set_nonblocking(true)
        .map_err(ConnectError::m("quic set_nonblocking error"))?;

    // If the address is IPv6, set the socket to only accept IPv6 connections.
    if address.is_ipv6() {
        socket
            .set_only_v6(true)
            .map_err(ConnectError::m("quic set_only_v6 error"))?;
    }

    // Bind the socket to the specified interface, if provided.
    let interface = config.get_ref::<Arc<str>>().map(Arc::as_ref);
    bind_interface(&socket, address, interface)
        .map_err(ConnectError::m("quic bind interface error"))?;

    // Bind the socket to the local address.
    socket
        .bind(&address.into())
        .map_err(ConnectError::m("quic bind local error"))?;
    Ok(socket.into())
}
