//! Stream connection service for direct, proxied, and Unix domain socket routes.
//!
//! The outer service enforces the total timeout; TCP also times the address race after DNS.

use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::{self, BoxFuture, Either, Ready};
use http::Uri;
#[cfg(feature = "socks")]
use netty::proxy::socks::{DnsResolve, SocksConnector, Version};
use netty::proxy::tunnel::{TunnelConnector, TunnelError};
use tower::{BoxError, Service, ServiceExt, service_fn};

#[cfg(unix)]
use crate::conn::dialer::Dial;
#[cfg(feature = "socks")]
use crate::dns::{DynResolver, Name};
use crate::{
    config::ConnectConfig,
    conn::{
        Conn, Connected, HttpInfo, Io, Request, Routed, Transport, connected::tls_info,
        dialer::Dialer, tcp_dial,
    },
    error::{ProxyConnect, ProxyMismatch},
    ext::UriExt,
    protocol::Protocol,
    proxy::{Intercepted, matcher::Intercept},
    rt::Connection,
    tls::{
        self, AlpnProtocol,
        connector::{self, MaybeHttpsStream, TlsConnector},
    },
};

// Unix sockets are addressed by path; this placeholder URI marks the hop as plain HTTP.
#[cfg(unix)]
const UNIX_PROXY_URI: &str = "http://localhost";

/// Establishes byte streams for HTTP/1 and HTTP/2 over TCP or Unix domain sockets.
///
/// Handles direct dials, HTTP/HTTPS forward proxies, HTTP CONNECT tunnels, SOCKS4/SOCKS5
/// proxies, and origin or proxy-hop TLS handshakes. Clones share the underlying [`State`].
#[derive(Clone)]
pub(crate) struct Connect {
    state: Arc<State>,
}

/// Shared dialer, stream TLS context cache, and optional DNS resolver for SOCKS proxies.
///
/// Owned by [`Connect`] behind an [`Arc`] so connection futures can run independently.
struct State {
    dialer: Dialer,
    tls: Arc<connector::Context>,
    #[cfg(feature = "socks")]
    resolver: DynResolver,
}

// ===== impl Connect =====

impl Connect {
    /// Creates a stream connector from a dialer and TLS context.
    pub(super) fn new(
        dialer: Dialer,
        tls_config: tls::Config,
        connect_config: &ConnectConfig,
        #[cfg(feature = "socks")] resolver: DynResolver,
    ) -> crate::Result<Self> {
        Ok(Self {
            state: Arc::new(State {
                dialer,
                tls: Arc::new(connector::Context::new(tls_config, connect_config)?),
                #[cfg(feature = "socks")]
                resolver,
            }),
        })
    }
}

impl Service<Routed> for Connect {
    type Response = Conn;
    type Error = BoxError;
    type Future = Either<BoxFuture<'static, Result<Conn, BoxError>>, Ready<Result<Conn, BoxError>>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn call(&mut self, Routed { request, proxy }: Routed) -> Self::Future {
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
        let is_https = request.uri().is_https();
        let uses_tcp = cfg_select! {
            unix => !matches!(proxy, Some(Intercepted::Unix(_))),
            _ => true,
        };
        let restore_nodelay = uses_tcp && !self.dialer.nodelay();
        let (io, tls) = match proxy {
            None => {
                let tls = self.tls.clone().for_config(request.body())?;
                // Disable Nagle through TLS when the target is secure.
                // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
                let io = self
                    .dialer
                    .clone()
                    .oneshot(tcp_dial(&request, request.uri().clone(), is_https))
                    .await?;
                (MaybeHttpsStream::Http(io), tls)
            }
            #[cfg(feature = "socks")]
            Some(Intercepted::Proxy(ref proxy))
                if let Some(scheme @ ("socks4" | "socks4a" | "socks5" | "socks5h")) =
                    proxy.uri().scheme_str() =>
            {
                let version = match scheme {
                    "socks4" | "socks4a" => Version::V4,
                    _ => Version::V5,
                };
                let dns = match scheme {
                    "socks4a" | "socks5h" => DnsResolve::Remote,
                    _ => DnsResolve::Local,
                };
                let tls = self.tls.clone().for_config(request.body())?;
                let hop = self.dialer.clone().map_request(|uri: Uri| {
                    let nodelay = is_https || uri.is_https();
                    tcp_dial(&request, uri, nodelay)
                });
                let resolver = self.resolver.clone().map_request(Name::new);
                let io = socks_connector(proxy, hop, resolver, (version, dns))
                    .oneshot(request.uri().clone())
                    .await?;
                (MaybeHttpsStream::Http(io), tls)
            }
            Some(proxy) if is_https => {
                let tls = self.tls.clone().for_config(request.body())?;
                let io = self.connect_tunnel(&request, &proxy, &tls).await?;
                (io, tls)
            }
            #[cfg(unix)]
            Some(Intercepted::Unix(path)) => {
                let tls = self.tls.clone().for_config(request.body())?;
                (
                    MaybeHttpsStream::Http(self.dialer.clone().oneshot(Dial::Unix(path)).await?),
                    tls,
                )
            }
            Some(Intercepted::Proxy(proxy)) => {
                let mut tls = self
                    .tls
                    .clone()
                    .for_config(request.body())
                    .map_err(|error| ProxyConnect::Source(error.into()))?;
                tls.no_alpn();
                let io = self
                    .dialer
                    .clone()
                    .oneshot(tcp_dial(
                        &request,
                        proxy.uri().clone(),
                        proxy.uri().is_https(),
                    ))
                    .await
                    .map_err(ProxyConnect::Source)?;
                return finish(io, request, tls, restore_nodelay, Some(proxy))
                    .await
                    .map_err(|error| ProxyConnect::Source(error).into());
            }
        };

        // Unwrap the CONNECT result once, before the origin's TLS and subsequent I/O.
        match io {
            MaybeHttpsStream::Http(io) => finish(io, request, tls, restore_nodelay, None).await,
            MaybeHttpsStream::Https(io) => finish(io, request, tls, restore_nodelay, None).await,
        }
    }

    fn connect_tunnel(
        &self,
        request: &Request<ConnectConfig>,
        route: &Intercepted,
        tls: &TlsConnector,
    ) -> impl Future<Output = Result<MaybeHttpsStream<Box<dyn Connection>>, TunnelError>> + Send
    {
        let hop = service_fn(move |uri: Uri| {
            let dial = match route {
                Intercepted::Proxy(_) => tcp_dial(request, uri.clone(), true),
                #[cfg(unix)]
                Intercepted::Unix(path) => Dial::Unix(path.clone()),
            };
            let dial = self.dialer.clone().oneshot(dial);
            // The proxy hop must speak HTTP/1.1 CONNECT. Its TLS future owns the options
            // and origin used to scope session tickets.
            let tls = (!uri.is_http()).then(|| {
                let mut tls = tls.clone();
                tls.no_alpn();
                (
                    tls,
                    request.uri().clone(),
                    alpn(request.protocol()),
                    request.body().clone(),
                )
            });
            async move {
                let io = dial.await?;
                let Some((tls, origin, alpn, config)) = tls else {
                    return Ok(MaybeHttpsStream::Http(io));
                };
                let remote_addr = io.peer_addr().map(|addr| addr.ip());
                tls.handshake(io, &origin, &uri, alpn, remote_addr, &config)
                    .await
                    .map(MaybeHttpsStream::Https)
            }
        });

        tunnel_connector(route, hop).oneshot(request.uri().clone())
    }
}

/// Completes the final TLS handshake, if needed, and records metadata for the dialed hop.
async fn finish(
    io: impl Connection,
    request: Request<ConnectConfig>,
    tls: TlsConnector,
    restore_nodelay: bool,
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
                tls_peer,
                alpn(request.protocol()),
                remote_addr.map(|addr| addr.ip()),
                request.body(),
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
            if restore_nodelay {
                stream.get_ref().set_nodelay(false)?;
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

/// Returns the ALPN override for an explicit stream protocol.
fn alpn(protocol: Protocol) -> Option<AlpnProtocol> {
    match protocol {
        Protocol::Http1 => Some(AlpnProtocol::HTTP1),
        #[cfg(feature = "http2")]
        Protocol::Http2 => Some(AlpnProtocol::HTTP2),
        Protocol::Auto => None,
        #[cfg(feature = "http3")]
        Protocol::Http3 => None,
    }
}

/// Builds a [`SocksConnector`] for `proxy` over `hop` and `resolver`.
#[cfg(feature = "socks")]
fn socks_connector<C, R>(
    proxy: &Intercept,
    hop: C,
    resolver: R,
    (version, dns): (Version, DnsResolve),
) -> SocksConnector<C, R> {
    let mut connector = SocksConnector::new(proxy.uri().clone(), hop, resolver);
    connector.set_auth(proxy.raw_auth());
    connector.set_version(version);
    connector.set_dns_mode(dns);
    connector
}

/// Builds an HTTP [CONNECT] tunnel connector over `hop`.
///
/// [CONNECT]: https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6
fn tunnel_connector<C>(route: &Intercepted, hop: C) -> TunnelConnector<C> {
    let (proxy_uri, proxy) = match route {
        Intercepted::Proxy(proxy) => (proxy.uri().clone(), Some(proxy)),
        #[cfg(unix)]
        Intercepted::Unix(_) => (Uri::from_static(UNIX_PROXY_URI), None),
    };
    let mut tunnel = TunnelConnector::new(proxy_uri, hop);
    if let Some(proxy) = proxy {
        if let Some(auth) = proxy.basic_auth() {
            tunnel = tunnel.with_auth(auth.clone());
        }
        if let Some(headers) = proxy.custom_headers() {
            tunnel = tunnel.with_headers(headers.clone());
        }
    }
    tunnel
}
