//! Stream routing for direct, proxy and Unix connections.
//!
//! The outer service enforces the connection deadline across dialing and handshakes.
//! TCP dials share that deadline so their timeout errors reach connector middleware.

#[cfg(feature = "socks")]
mod socks;
mod tunnel;

use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::{self, BoxFuture, Either, Ready};
use http::Request;
#[cfg(feature = "socks")]
use netty::proxy::socks::{DnsResolve, Version};
use tower::{BoxError, Service, ServiceExt};

#[cfg(feature = "socks")]
use crate::dns::DynResolver;
use crate::{
    config::connect::ConnectConfig,
    conn::{
        Conn, ConnectRequestExt, Connected, HttpInfo, Io, Transport,
        connected::tls_info,
        dialer::{Dial, Dialer},
    },
    error::{ProxyConnect, ProxyMismatch},
    ext::UriExt,
    proxy::{Intercepted, Matcher, matcher::Intercept},
    rt::Connection,
    tls::{
        AlpnProtocol,
        connector::{MaybeHttpsStream, StreamTls, TlsConnector},
    },
};

/// Establishes the byte stream HTTP/1 or HTTP/2 uses, including proxy and TLS handshakes.
#[derive(Clone)]
pub(crate) struct Connect {
    state: Arc<State>,
}

struct State {
    dialer: Dialer,
    proxies: Arc<Vec<Matcher>>,
    tls: StreamTls,
    tcp_nodelay: bool,
    #[cfg(feature = "socks")]
    resolver: DynResolver,
}

// ===== impl Connect =====

impl Connect {
    /// Combines the dial service with the client's proxy rules and stream TLS.
    #[must_use]
    pub(super) fn new(
        dialer: Dialer,
        proxies: Arc<Vec<Matcher>>,
        tls: StreamTls,
        tcp_nodelay: bool,
        #[cfg(feature = "socks")] resolver: DynResolver,
    ) -> Self {
        Self {
            state: Arc::new(State {
                dialer,
                proxies,
                tls,
                tcp_nodelay,
                #[cfg(feature = "socks")]
                resolver,
            }),
        }
    }
}

impl Service<Request<ConnectConfig>> for Connect {
    type Response = Conn;
    type Error = BoxError;
    type Future = Either<BoxFuture<'static, Result<Conn, BoxError>>, Ready<Result<Conn, BoxError>>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn call(&mut self, request: Request<ConnectConfig>) -> Self::Future {
        let proxy = request.intercept(&self.state.proxies);
        if let Some(Intercepted::Proxy(proxy)) = &proxy
            && proxy.uri().scheme_str() == Some("quic")
        {
            return Either::Right(future::err(
                ProxyMismatch("QUIC proxies require HTTP/3").into(),
            ));
        }
        Either::Left(Box::pin(self.state.clone().connect(request, proxy)))
    }
}

// ===== impl State =====

impl State {
    async fn connect(
        self: Arc<Self>,
        request: Request<ConnectConfig>,
        proxy: Option<Intercepted>,
    ) -> Result<Conn, BoxError> {
        debug!("starting new connection: {:?}", request.uri());
        let deadline = request.deadline();
        let is_https = request.uri().is_https();
        let uses_tcp = cfg_select! {
            unix => !matches!(proxy, Some(Intercepted::Unix(_))),
            _ => true,
        };
        let nodelay = (!self.tcp_nodelay && uses_tcp).then_some(false);
        let dialer = self.dialer.clone();

        let (io, tls) = match proxy {
            None => {
                let tls = self.tls.clone().for_request(&request)?;
                // Disable Nagle through TLS when the target is secure.
                // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
                let io = dialer
                    .oneshot(Dial::Tcp {
                        uri: request.uri().clone(),
                        config: request.body().clone(),
                        deadline,
                        nodelay: is_https,
                    })
                    .await?;
                (MaybeHttpsStream::Http(io), tls)
            }
            #[cfg(unix)]
            Some(proxy @ Intercepted::Unix(_)) if is_https => {
                let tls = self.tls.clone().for_request(&request)?;
                (tunnel::connect(dialer, &tls, &request, &proxy).await?, tls)
            }
            #[cfg(unix)]
            Some(Intercepted::Unix(path)) => {
                let tls = self.tls.clone().for_request(&request)?;
                (
                    MaybeHttpsStream::Http(dialer.oneshot(Dial::Unix(path)).await?),
                    tls,
                )
            }
            Some(Intercepted::Proxy(proxy)) => match proxy.uri().scheme_str() {
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
                    let tls = self.tls.clone().for_request(&request)?;
                    let io = socks::connect(
                        dialer,
                        self.resolver.clone(),
                        &request,
                        &proxy,
                        (version, dns),
                    )
                    .await?;
                    (MaybeHttpsStream::Http(io), tls)
                }
                _ if is_https => {
                    let tls = self.tls.clone().for_request(&request)?;
                    let io =
                        tunnel::connect(dialer, &tls, &request, &Intercepted::Proxy(proxy)).await?;
                    (io, tls)
                }
                _ => {
                    let mut tls = self
                        .tls
                        .clone()
                        .for_request(&request)
                        .map_err(|error| ProxyConnect::Source(error.into()))?;
                    tls.no_alpn();
                    let io = dialer
                        .oneshot(Dial::Tcp {
                            uri: proxy.uri().clone(),
                            config: request.body().clone(),
                            deadline,
                            nodelay: proxy.uri().is_https(),
                        })
                        .await
                        .map_err(ProxyConnect::Source)?;
                    return finish(io, request, tls, nodelay, Some(proxy))
                        .await
                        .map_err(|error| ProxyConnect::Source(error).into());
                }
            },
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
    request: Request<ConnectConfig>,
    tls: TlsConnector,
    nodelay: Option<bool>,
    proxy: Option<Intercept>,
) -> Result<Conn, BoxError> {
    let (local_addr, remote_addr) = (io.local_addr(), io.peer_addr());
    let tls_peer = proxy.as_ref().map_or(request.uri(), Intercept::uri);
    let stream = if tls_peer.is_http() {
        MaybeHttpsStream::Http(io)
    } else {
        MaybeHttpsStream::Https(
            tls.handshake(
                io,
                request.uri(),
                request.protocol(),
                request.body(),
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
