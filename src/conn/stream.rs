//! Stream routing for direct, proxy and Unix connections.
//!
//! The outer service enforces the connection deadline across dialing and handshakes.
//! TCP dials share that deadline so their timeout errors reach connector middleware.

#[cfg(unix)]
use std::path::Path;
use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::BoxFuture;
use http::Request;
#[cfg(feature = "socks")]
use netty::proxy::socks::{DnsResolve, Version};
use tower::{BoxError, Service, ServiceExt};

#[cfg(feature = "socks")]
use crate::dns::DynResolver;
use crate::{
    conn::{
        Conn, ConnectAttempt, ConnectRequestExt, Connected, ConnectionKey, HttpInfo, Io, Transport,
        connected::tls_info,
        dialer::{Dial, Dialer, SocketBindings},
    },
    error::{ProxyConnect, ProxyMismatch},
    ext::UriExt,
    proxy::{Intercepted, matcher::Intercept},
    rt::Connection,
    tls::{
        AlpnProtocol,
        connector::{HandshakeOptions, MaybeHttpsStream, StreamTls, TlsConnector},
    },
};

#[cfg(feature = "socks")]
mod socks;
mod tunnel;

type ConnectFuture = BoxFuture<'static, Result<Conn, BoxError>>;

pub(crate) enum Route {
    Direct,
    /// Sends the HTTP request directly to the proxy. TLS, if used, authenticates the proxy.
    Forward(Intercept),
    /// CONNECT uses HTTP/1.1 to the proxy. The origin handshake keeps its own ALPN.
    Tunnel(Intercepted),
    #[cfg(feature = "socks")]
    Socks {
        proxy: Intercept,
        version: Version,
        dns: DnsResolve,
    },
    #[cfg(unix)]
    Unix(Arc<Path>),
}

/// Establishes the byte stream HTTP/1 or HTTP/2 uses, including proxy and TLS handshakes.
#[derive(Clone)]
pub(crate) struct Connect {
    state: Arc<State>,
}

struct State {
    dialer: Dialer,
    tls: StreamTls,
    tcp_nodelay: bool,
    #[cfg(feature = "socks")]
    resolver: DynResolver,
}

// ===== impl Route =====

impl Route {
    pub(super) fn new(proxy: Option<Intercepted>, is_https: bool) -> Result<Self, ProxyMismatch> {
        Ok(match proxy {
            None => Self::Direct,
            #[cfg(unix)]
            Some(proxy @ Intercepted::Unix(_)) if is_https => Self::Tunnel(proxy),
            #[cfg(unix)]
            Some(Intercepted::Unix(path)) => Self::Unix(path),
            Some(Intercepted::Proxy(proxy)) => match proxy.uri().scheme_str() {
                Some("quic") => return Err(ProxyMismatch("QUIC proxies require HTTP/3")),
                #[cfg(feature = "socks")]
                Some(scheme @ ("socks4" | "socks4a" | "socks5" | "socks5h")) => {
                    let version = match scheme {
                        "socks4" | "socks4a" => Version::V4,
                        _ => Version::V5,
                    };
                    let dns = match scheme {
                        "socks4a" | "socks5h" => DnsResolve::Remote,
                        _ => DnsResolve::Local,
                    };
                    Self::Socks {
                        proxy,
                        version,
                        dns,
                    }
                }
                _ if is_https => Self::Tunnel(Intercepted::Proxy(proxy)),
                _ => Self::Forward(proxy),
            },
        })
    }

    fn uses_tcp(&self) -> bool {
        cfg_select! {
            unix => !matches!(self, Self::Unix(_) | Self::Tunnel(Intercepted::Unix(_))),
            _ => true,
        }
    }
}

// ===== impl Connect =====

impl Connect {
    /// Combines the dial service with the client's stream TLS configuration.
    pub(super) fn new(
        dialer: Dialer,
        tls: StreamTls,
        tcp_nodelay: bool,
        #[cfg(feature = "socks")] resolver: DynResolver,
    ) -> Self {
        Self {
            state: Arc::new(State {
                dialer,
                tls,
                tcp_nodelay,
                #[cfg(feature = "socks")]
                resolver,
            }),
        }
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

    #[inline]
    fn call(&mut self, attempt: ConnectAttempt<Route>) -> Self::Future {
        Box::pin(self.state.clone().connect(attempt))
    }
}

// ===== impl State =====

impl State {
    async fn connect(
        self: Arc<Self>,
        ConnectAttempt {
            request,
            deadline,
            route,
        }: ConnectAttempt<Route>,
    ) -> Result<Conn, BoxError> {
        debug!("starting new connection: {:?}", request.uri());
        let nodelay = (!self.tcp_nodelay && route.uses_tcp()).then_some(false);
        let bindings = SocketBindings::from_config(request.connect_config());
        let mut tls = match self.tls.clone().for_request(&request) {
            Ok(tls) => tls,
            Err(error) if matches!(route, Route::Forward(_)) => {
                return Err(ProxyConnect::Source(error.into()).into());
            }
            Err(error) => return Err(error.into()),
        };

        let dialer = self.dialer.clone();
        let io = match route {
            Route::Direct => {
                // Disable Nagle through TLS when the target is secure.
                // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
                let io = dialer
                    .oneshot(Dial::Tcp {
                        uri: request.uri().clone(),
                        bindings,
                        deadline,
                        nodelay: request.uri().is_https(),
                    })
                    .await?;
                MaybeHttpsStream::Http(io)
            }
            Route::Tunnel(proxy) => {
                tunnel::connect(dialer, &tls, &request, &proxy, bindings, deadline).await?
            }
            Route::Forward(proxy) => {
                tls.no_alpn();
                let io = dialer
                    .oneshot(Dial::Tcp {
                        uri: proxy.uri().clone(),
                        bindings,
                        deadline,
                        nodelay: proxy.uri().is_https(),
                    })
                    .await
                    .map_err(ProxyConnect::Source)?;
                return finish(io, request, tls, nodelay, Some(proxy))
                    .await
                    .map_err(|error| ProxyConnect::Source(error).into());
            }
            #[cfg(feature = "socks")]
            Route::Socks {
                proxy,
                version,
                dns,
            } => {
                let io = socks::connect(
                    dialer,
                    self.resolver.clone(),
                    request.uri(),
                    bindings,
                    deadline,
                    &proxy,
                    (version, dns),
                )
                .await?;
                MaybeHttpsStream::Http(io)
            }
            #[cfg(unix)]
            Route::Unix(path) => MaybeHttpsStream::Http(dialer.oneshot(Dial::Unix(path)).await?),
        };

        // Unwrap the CONNECT result once, before the origin's TLS and subsequent I/O.
        match io {
            MaybeHttpsStream::Http(io) => finish(io, request, tls, nodelay, None).await,
            MaybeHttpsStream::Https(io) => finish(io, request, tls, nodelay, None).await,
        }
    }
}

/// TLS authenticates the origin or the forward proxy. Socket addresses always describe the
/// dialed hop, including when it carries a CONNECT tunnel.
async fn finish(
    io: impl Connection,
    request: Request<ConnectionKey>,
    tls: TlsConnector,
    nodelay: Option<bool>,
    proxy: Option<Intercept>,
) -> Result<Conn, BoxError> {
    let (local_addr, remote_addr) = (io.local_addr(), io.peer_addr());
    let tls_peer = proxy.as_ref().map_or(request.uri(), Intercept::uri);
    let stream = if tls_peer.is_http() {
        MaybeHttpsStream::Http(io)
    } else {
        let options = HandshakeOptions::new(request.connect_config());
        MaybeHttpsStream::Https(
            tls.handshake(
                io,
                request.body(),
                options,
                tls_peer,
                remote_addr.map(|addr| addr.ip()),
            )
            .await?,
        )
    };

    let mut connected = Connected::new();
    if let (Some(local_addr), Some(remote_addr)) = (local_addr, remote_addr) {
        connected = connected.extra(HttpInfo {
            remote_addr,
            local_addr,
        });
    }
    if let Some(proxy) = proxy {
        connected = connected.proxy(proxy);
    }
    let stream: Box<dyn Io> = match stream {
        MaybeHttpsStream::Http(stream) => Box::new(stream),
        MaybeHttpsStream::Https(stream) => {
            if let Some(nodelay) = nodelay {
                // Keep TCP_NODELAY on until the last TLS handshake on the socket completes.
                stream.get_ref().set_nodelay(nodelay)?;
            }
            let ssl = stream.ssl();
            if ssl
                .selected_alpn_protocol()
                .is_some_and(|alpn| AlpnProtocol::HTTP2.eq(alpn))
            {
                connected = connected.negotiated_h2();
            }
            if tls.tls_info() {
                connected = connected.extra(tls_info(
                    ssl.peer_certificate().as_deref(),
                    ssl.peer_cert_chain(),
                ));
            }
            Box::new(stream)
        }
    };
    Ok(Conn {
        transport: Transport::Stream(stream),
        connected,
    })
}
