//! The stream path: direct, CONNECT tunnel, forward-proxy, SOCKS4/5 and Unix routes, then
//! target TLS. Every route ends in one place that finishes TLS and builds the [`Conn`].

mod verbose;

use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::BoxFuture;
use http::Uri;
#[cfg(feature = "socks")]
use netty::proxy::socks;
use netty::proxy::tunnel;
use tower::{BoxError, Service, ServiceExt, util::MapRequest};
use verbose::Verbose;

use super::connected::tls_info;
use crate::{
    conn::{
        AsyncConn, Conn, Connected, HttpInfo, Transport,
        dialer::{Dialer, SocketRequest},
        request::ConnectRequest,
    },
    error::{ProxyConnect, ProxyMismatch},
    ext::UriExt,
    proxy::{Intercepted, Matcher, matcher::Intercept},
    rt::{self, BoxConnection},
    tls::{
        AlpnProtocol,
        connector::{HttpsConnector, MaybeHttpsStream, StreamTls},
    },
};

/// Establishes a direct socket, a forward-proxy connection, or a proxy tunnel,
/// then finishes target TLS and returns the stream for the HTTP/1 or HTTP/2 pool.
/// Clones share the dialer, compiled TLS and proxy rules.
#[derive(Clone)]
pub(crate) struct StreamConnector {
    dialer: Dialer,
    tls: StreamTls,
    proxies: Arc<Vec<Matcher>>,
    verbose: Verbose,
}

/// A dialed stream whose socket stays reachable beneath any proxy TLS.
trait Dialed {
    /// Returns the socket dialed by the runtime.
    fn socket(&self) -> &dyn rt::Connection;
}

/// Builds the TLS connector for a CONNECT proxy hop.
/// The hop uses the same per-connection TLS setup as the target, without ALPN.
fn proxy_hop<S>(
    tls: &HttpsConnector<()>,
    inner: S,
    req: &ConnectRequest,
) -> MapRequest<HttpsConnector<S>, impl Fn(Uri) -> ConnectRequest + Clone + Send + Sync + 'static> {
    let mut connector = tls.clone().with_inner(inner);
    connector.no_alpn();
    let route = req.clone();
    MapRequest::new(connector, move |uri| route.clone().with_route_uri(uri))
}

/// Finishes TLS over an established route and restores Nagle once when `restore_nagle` is set.
/// Builds the metadata from the dialed socket's addresses, the target TLS session and the
/// identity of `proxy`, the forward proxy `io` reaches. An `http` route skips TLS.
async fn finish<IO>(
    verbose: Verbose,
    io: IO,
    req: ConnectRequest,
    tls: HttpsConnector<()>,
    restore_nagle: bool,
    proxy: Option<Intercept>,
) -> Result<Conn, BoxError>
where
    IO: AsyncConn + Dialed,
{
    let socket = io.socket();
    let (local_addr, remote_addr) = (socket.local_addr(), socket.peer_addr());
    let stream = tls
        .handshake(io, req, remote_addr.map(|addr| addr.ip()))
        .await?;

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
    let stream = match stream {
        MaybeHttpsStream::Http(stream) => verbose.wrap(stream),
        MaybeHttpsStream::Https(stream) => {
            if restore_nagle {
                stream.get_ref().socket().set_nodelay(false)?;
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
            verbose.wrap(stream)
        }
    };
    Ok(Conn {
        transport: Transport::Stream(stream),
        connected,
    })
}

// ===== impl StreamConnector =====

impl StreamConnector {
    /// Creates the stream path over `dialer` with the client's stream TLS and proxy rules.
    /// `verbose` traces each connection's I/O.
    pub(crate) fn new(
        dialer: Dialer,
        tls: StreamTls,
        proxies: Arc<Vec<Matcher>>,
        verbose: bool,
    ) -> Self {
        Self {
            dialer,
            tls,
            proxies,
            verbose: Verbose(verbose),
        }
    }
}

impl Service<ConnectRequest> for StreamConnector {
    type Response = Conn;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Conn, BoxError>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: ConnectRequest) -> Self::Future {
        let dialer = self.dialer.clone();
        let proxies = self.proxies.clone();
        let verbose = self.verbose;
        // TCP routes turn Nagle back on after TLS unless the client disables it.
        let restore_nagle = !self.dialer.nodelay();
        let tls = self.tls.clone();
        #[cfg(feature = "socks")]
        let resolver = self.dialer.resolver().clone();

        Box::pin(async move {
            debug!("starting new connection: {:?}", req.uri());
            let intercepted = req
                .config_override::<Matcher>()
                .and_then(|proxy| proxy.intercept(req.uri()))
                .or_else(|| proxies.iter().find_map(|proxy| proxy.intercept(req.uri())));
            let uri = req.uri().clone();
            let secure = uri.is_https();
            let bind_options = req.bind_options().clone();

            #[cfg(unix)]
            let unix = match &intercepted {
                Some(Intercepted::Unix(path)) => Some(path.clone()),
                _ => None,
            };

            let dialer = dialer.map_request(move |uri: Uri| SocketRequest {
                secure: secure || uri.is_https(),
                uri,
                bind_options: bind_options.clone(),
                #[cfg(unix)]
                unix: unix.clone(),
            });

            match intercepted {
                None => {
                    let tls = tls.for_request(&req)?;
                    let io = dialer.oneshot(req.route_uri().clone()).await?;
                    finish(verbose, io, req, tls, restore_nagle, None).await
                }
                Some(Intercepted::Proxy(proxy)) => {
                    let proxy_uri = proxy.uri().clone();
                    if proxy_uri.scheme_str() == Some("quic") {
                        return Err(ProxyMismatch("QUIC proxies require HTTP/3").into());
                    }
                    #[cfg(feature = "socks")]
                    if let Some((version, dns)) = match proxy_uri.scheme_str() {
                        Some("socks4") => Some((socks::Version::V4, socks::DnsResolve::Local)),
                        Some("socks4a") => Some((socks::Version::V4, socks::DnsResolve::Remote)),
                        Some("socks5") => Some((socks::Version::V5, socks::DnsResolve::Local)),
                        Some("socks5h") => Some((socks::Version::V5, socks::DnsResolve::Remote)),
                        _ => None,
                    } {
                        let mut connector = socks::SocksConnector::new(
                            proxy_uri,
                            dialer,
                            resolver.map_request(crate::dns::Name::new),
                        );
                        connector.set_auth(proxy.raw_auth());
                        connector.set_version(version);
                        connector.set_dns_mode(dns);

                        let io = {
                            let _stage = req.enter_proxy_stage();
                            connector.oneshot(uri).await?
                        };
                        let tls = tls.for_request(&req)?;
                        return finish(verbose, io, req, tls, restore_nagle, None).await;
                    }

                    if secure {
                        let tls = tls.for_request(&req)?;
                        let mut tunnel =
                            tunnel::TunnelConnector::new(proxy_uri, proxy_hop(&tls, dialer, &req));

                        if let Some(auth) = proxy.basic_auth() {
                            tunnel = tunnel.with_auth(auth.clone());
                        }

                        if let Some(headers) = proxy.custom_headers() {
                            tunnel = tunnel.with_headers(headers.clone());
                        }

                        let io = {
                            let _stage = req.enter_proxy_stage();
                            tunnel.oneshot(uri).await?
                        };
                        finish(verbose, io, req, tls, restore_nagle, None).await
                    } else {
                        // The proxy is the peer, so its TLS handshake is part of the proxy stage.
                        let _stage = req.enter_proxy_stage();
                        // HTTP/1 forwarding to an HTTPS proxy must not negotiate target ALPN.
                        let mut tls = tls
                            .for_request(&req)
                            .map_err(|err| ProxyConnect::Source(err.into()))?;
                        tls.no_alpn();
                        let req = req.with_route_uri(proxy_uri);
                        let io = dialer
                            .oneshot(req.route_uri().clone())
                            .await
                            .map_err(ProxyConnect::Source)?;
                        finish(verbose, io, req, tls, restore_nagle, Some(proxy))
                            .await
                            .map_err(|err| ProxyConnect::Source(err).into())
                    }
                }
                #[cfg(unix)]
                Some(Intercepted::Unix(_)) => {
                    let tls = tls.for_request(&req)?;
                    if secure {
                        let tunnel = tunnel::TunnelConnector::new(
                            Uri::from_static("http://localhost"),
                            proxy_hop(&tls, dialer, &req),
                        );
                        let io = tunnel.oneshot(uri).await?;
                        finish(verbose, io, req, tls, false, None).await
                    } else {
                        let io = dialer.oneshot(req.route_uri().clone()).await?;
                        finish(verbose, io, req, tls, false, None).await
                    }
                }
            }
        })
    }
}

// ===== impl Dialed =====

impl Dialed for BoxConnection {
    #[inline]
    fn socket(&self) -> &dyn rt::Connection {
        self.as_ref()
    }
}

impl<T: Dialed> Dialed for MaybeHttpsStream<T> {
    #[inline]
    fn socket(&self) -> &dyn rt::Connection {
        self.as_ref().socket()
    }
}
