//! The QUIC path: direct dials, MASQUE CONNECT-UDP and SOCKS5 UDP routes over the client's
//! QUIC [`Endpoints`]. Proxy setup and the target handshake share the connector's deadline.

mod endpoint;
mod masque;
#[cfg(feature = "socks")]
mod socks;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use endpoint::Endpoints;
use futures_util::future::{self, BoxFuture, Either, Ready};
use http::Request;
#[cfg(feature = "socks")]
use netty::proxy::socks::DnsResolve;
use socket2::{Domain, Protocol, Socket, Type};
use tower::{BoxError, Service};

#[cfg(feature = "socks")]
use crate::conn::dialer::Dialer;
use crate::{
    config::connect::ConnectConfig,
    conn::{
        Conn,
        dialer::{ConnectError, bind_interface},
    },
    dns::DynResolver,
    error::{ProxyConnect, ProxyMismatch},
    proxy::{Intercepted, Matcher, quic_port},
    rt::DynRuntime,
    tls::quic::QuicTls,
};

type ConnectFuture = BoxFuture<'static, Result<Conn, BoxError>>;

/// UDP payload a tunnel must carry for QUIC, which pads client Initial datagrams to 1200 bytes
/// ([RFC 9000 Section 14.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1)).
pub(super) const TUNNEL_MTU: u16 = 1200;

const QUIC_PROXY_REQUIRED: &str =
    "HTTP/3 requires a quic:// proxy or SOCKS5 with the socks feature";

/// Connects HTTP/3 origins over a selected route: directly, through a `quic://` MASQUE proxy, or
/// through SOCKS5 UDP. Clones share the endpoints.
#[derive(Clone)]
pub(crate) struct Connect {
    endpoints: Arc<Endpoints>,
    proxies: Arc<Vec<Matcher>>,
    #[cfg(feature = "socks")]
    dialer: Dialer,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Bindings<'a> {
    addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),
    interface: Option<&'a str>,
}

// ===== impl Connect =====

impl Connect {
    /// Builds the QUIC path. Endpoints open on the first connection that needs them.
    pub(super) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        proxies: Arc<Vec<Matcher>>,
        happy_eyeballs_timeout: Option<Duration>,
        tls: QuicTls,
        client_config: &ConnectConfig,
        #[cfg(feature = "socks")] dialer: Dialer,
    ) -> crate::Result<Self> {
        Ok(Self {
            endpoints: Arc::new(Endpoints::new(
                runtime,
                resolver,
                happy_eyeballs_timeout,
                tls,
                client_config,
            )?),
            proxies,
            #[cfg(feature = "socks")]
            dialer,
        })
    }
}

impl Service<Request<ConnectConfig>> for Connect {
    type Response = Conn;
    type Error = BoxError;
    type Future = Either<ConnectFuture, Ready<Result<Conn, BoxError>>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<ConnectConfig>) -> Self::Future {
        let endpoints = self.endpoints.clone();
        match Matcher::select(
            request.body().get_ref::<Matcher>(),
            &self.proxies,
            request.uri(),
        ) {
            None => Either::Left(Box::pin(async move { endpoints.connect(&request).await })),
            #[cfg(unix)]
            Some(Intercepted::Unix(_)) => {
                Either::Right(future::err(ProxyMismatch(QUIC_PROXY_REQUIRED).into()))
            }
            Some(Intercepted::Proxy(proxy)) => match proxy.uri().scheme_str() {
                // Keep the proxy error for invalid authorities from environment rules.
                Some("quic") if let Err(error) = quic_port(proxy.uri()) => {
                    Either::Right(future::err(ProxyConnect::Message(error).into()))
                }
                Some("quic") => Either::Left(Box::pin(async move {
                    masque::connect(&endpoints, request, proxy).await
                })),
                #[cfg(feature = "socks")]
                Some(scheme @ ("socks5" | "socks5h")) => {
                    let dns = if scheme == "socks5h" {
                        DnsResolve::Remote
                    } else {
                        DnsResolve::Local
                    };
                    let dialer = self.dialer.clone();
                    Either::Left(Box::pin(async move {
                        socks::connect(&endpoints, dialer, request, proxy, dns).await
                    }))
                }
                _ => Either::Right(future::err(ProxyMismatch(QUIC_PROXY_REQUIRED).into())),
            },
        }
    }
}

/// Binds a UDP socket for the address family of `remote` before the runtime registers it.
fn bind_udp(bindings: Bindings<'_>, remote: SocketAddr) -> Result<UdpSocket, ConnectError> {
    let address = match remote {
        SocketAddr::V4(_) => {
            SocketAddr::from((bindings.addresses.0.unwrap_or(Ipv4Addr::UNSPECIFIED), 0))
        }
        SocketAddr::V6(_) => {
            SocketAddr::from((bindings.addresses.1.unwrap_or(Ipv6Addr::UNSPECIFIED), 0))
        }
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
    bind_interface(&socket, address, bindings.interface)
        .map_err(ConnectError::m("quic bind interface error"))?;

    // Bind the socket to the local address.
    socket
        .bind(&address.into())
        .map_err(ConnectError::m("quic bind local error"))?;
    Ok(socket.into())
}
