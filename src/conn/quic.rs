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
#[cfg(test)]
pub(crate) use endpoint::test_server_config;
use futures_util::future::BoxFuture;
#[cfg(feature = "socks")]
use netty::proxy::socks::DnsResolve;
use socket2::{Domain, Protocol, Socket, Type};
use tower::{BoxError, Service};

#[cfg(feature = "socks")]
use crate::conn::dialer::Dialer;
use crate::{
    conn::{
        Conn, ConnectAttempt,
        dialer::{ConnectError, SocketBindings},
    },
    dns::DynResolver,
    error::{ProxyConnect, ProxyMismatch},
    proxy::{Intercepted, matcher::Intercept, quic_port},
    rt::DynRuntime,
    tls::quic::QuicTls,
};

type ConnectFuture = BoxFuture<'static, Result<Conn, BoxError>>;

const QUIC_PROXY_REQUIRED: &str =
    "HTTP/3 requires a quic:// proxy or SOCKS5 with the socks feature";

pub(crate) enum Route {
    Direct,
    Masque(Intercept),
    #[cfg(feature = "socks")]
    Socks {
        proxy: Intercept,
        dns: DnsResolve,
    },
}

/// Connects HTTP/3 origins over a selected route: directly, through a `quic://` MASQUE proxy, or
/// through SOCKS5 UDP. Clones share the endpoints.
#[derive(Clone)]
pub(crate) struct Connect {
    endpoints: Arc<Endpoints>,
    #[cfg(feature = "socks")]
    dialer: Dialer,
}

// ===== impl Route =====

impl Route {
    pub(super) fn new(proxy: Option<Intercepted>) -> Result<Self, BoxError> {
        match proxy {
            None => Ok(Self::Direct),
            Some(Intercepted::Proxy(proxy)) => match proxy.uri().scheme_str() {
                Some("quic") => {
                    // Keep the proxy error for invalid authorities from environment rules.
                    quic_port(proxy.uri()).map_err(ProxyConnect::Message)?;
                    Ok(Self::Masque(proxy))
                }
                #[cfg(feature = "socks")]
                Some(scheme @ ("socks5" | "socks5h")) => {
                    let dns = if scheme == "socks5h" {
                        DnsResolve::Remote
                    } else {
                        DnsResolve::Local
                    };
                    Ok(Self::Socks { proxy, dns })
                }
                _ => Err(ProxyMismatch(QUIC_PROXY_REQUIRED).into()),
            },
            #[cfg(unix)]
            Some(Intercepted::Unix(_)) => Err(ProxyMismatch(QUIC_PROXY_REQUIRED).into()),
        }
    }
}

// ===== impl Connect =====

impl Connect {
    /// Builds the QUIC path. Endpoints open on the first connection that needs them.
    pub(super) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        bindings: SocketBindings,
        happy_eyeballs_timeout: Option<Duration>,
        tls: QuicTls,
        #[cfg(feature = "socks")] dialer: Dialer,
    ) -> crate::Result<Self> {
        Ok(Self {
            endpoints: Arc::new(Endpoints::new(
                runtime,
                resolver,
                bindings,
                happy_eyeballs_timeout,
                tls,
            )?),
            #[cfg(feature = "socks")]
            dialer,
        })
    }
}

impl Service<ConnectAttempt<Route>> for Connect {
    type Response = Conn;
    type Error = BoxError;
    type Future = ConnectFuture;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        ConnectAttempt {
            request,
            deadline,
            route,
        }: ConnectAttempt<Route>,
    ) -> Self::Future {
        let endpoints = self.endpoints.clone();
        match route {
            Route::Direct => Box::pin(async move { endpoints.connect(&request).await }),
            #[cfg(feature = "socks")]
            Route::Socks { proxy, dns } => {
                let dialer = self.dialer.clone();
                Box::pin(async move {
                    socks::connect(&endpoints, dialer, request, deadline, proxy, dns).await
                })
            }
            Route::Masque(proxy) => {
                Box::pin(async move { masque::connect(&endpoints, request, deadline, proxy).await })
            }
        }
    }
}

/// Binds a UDP socket for the address family of `remote` before the runtime registers it.
fn bind_udp(bindings: &SocketBindings, remote: SocketAddr) -> Result<UdpSocket, ConnectError> {
    let (ipv4, ipv6) = bindings.addresses();
    let address = match remote {
        SocketAddr::V4(_) => SocketAddr::from((ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED), 0)),
        SocketAddr::V6(_) => SocketAddr::from((ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED), 0)),
    };
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .map_err(ConnectError::m("quic open error"))?;
    socket
        .set_nonblocking(true)
        .map_err(ConnectError::m("quic set_nonblocking error"))?;
    if address.is_ipv6() {
        socket
            .set_only_v6(true)
            .map_err(ConnectError::m("quic set_only_v6 error"))?;
    }
    bindings
        .bind_interface(&socket, address)
        .map_err(ConnectError::m("quic bind interface error"))?;
    socket
        .bind(&address.into())
        .map_err(ConnectError::m("quic bind local error"))?;
    Ok(socket.into())
}
