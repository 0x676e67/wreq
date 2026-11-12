//! The stream path's routes: direct, CONNECT tunnel, forward-proxy, SOCKS4/5 and Unix. Each
//! yields a [`Routed`] stream, which [`Tls`](super::layer::tls::Tls) finishes into a
//! [`Conn`](super::Conn).

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

use crate::{
    conn::{
        dialer::{Dialer, SocketRequest},
        request::ConnectRequest,
    },
    error::{ProxyConnect, ProxyMismatch},
    ext::UriExt,
    proxy::{Intercepted, Matcher, matcher::Intercept},
    rt::{self, BoxConnection},
    tls::connector::{HttpsConnector, MaybeHttpsStream},
};

/// Selects the request's route from its proxy rules and establishes a stream over it: a direct
/// socket, a forward-proxy connection or a proxy tunnel. Target TLS is left to the caller.
/// Clones share the dialer and proxy rules.
#[derive(Clone)]
pub(crate) struct StreamRouter {
    dialer: Dialer,
    proxies: Arc<Vec<Matcher>>,
}

/// A connection request with the TLS selected for it, which an HTTPS proxy hop reuses.
pub(crate) struct RouteRequest {
    pub(super) request: ConnectRequest,
    pub(super) tls: HttpsConnector<()>,
}

/// A stream a route established, before target TLS, with what finishing it needs.
pub(crate) struct Routed {
    pub(super) io: RoutedIo,
    /// The request, re-routed to the proxy when `proxy` is set.
    pub(super) request: ConnectRequest,
    /// The request's TLS, without ALPN when `proxy` is set.
    pub(super) tls: HttpsConnector<()>,
    /// The forward proxy `io` reaches; it is then the TLS peer and names the connection.
    pub(super) proxy: Option<Intercept>,
    /// TCP routes turn Nagle back on after TLS unless the client disables it.
    pub(super) restore_nagle: bool,
}

/// The stream types routes produce. Finishing matches once, so neither costs the other a
/// branch per read or write.
pub(crate) enum RoutedIo {
    /// A dialed socket, or a SOCKS tunnel over one.
    Socket(BoxConnection),
    /// A CONNECT tunnel, whose proxy hop may carry TLS.
    Hop(MaybeHttpsStream<BoxConnection>),
}

/// A dialed stream whose socket stays reachable beneath any proxy TLS.
pub(crate) trait Dialed {
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

// ===== impl StreamRouter =====

impl StreamRouter {
    /// Creates the stream routes over `dialer` with the client's proxy rules.
    pub(crate) fn new(dialer: Dialer, proxies: Arc<Vec<Matcher>>) -> Self {
        Self { dialer, proxies }
    }
}

impl Service<RouteRequest> for StreamRouter {
    type Response = Routed;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Routed, BoxError>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, RouteRequest { request: req, tls }: RouteRequest) -> Self::Future {
        let dialer = self.dialer.clone();
        let proxies = self.proxies.clone();
        let restore_nagle = !self.dialer.nodelay();
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
            let deadline = req.deadline();

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
                deadline,
            });

            match intercepted {
                None => {
                    let io = dialer.oneshot(req.route_uri().clone()).await?;
                    Ok(Routed {
                        io: RoutedIo::Socket(io),
                        request: req,
                        tls,
                        proxy: None,
                        restore_nagle,
                    })
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

                        let io = connector.oneshot(uri).await?;
                        return Ok(Routed {
                            io: RoutedIo::Socket(io),
                            request: req,
                            tls,
                            proxy: None,
                            restore_nagle,
                        });
                    }

                    if secure {
                        let mut tunnel =
                            tunnel::TunnelConnector::new(proxy_uri, proxy_hop(&tls, dialer, &req));

                        if let Some(auth) = proxy.basic_auth() {
                            tunnel = tunnel.with_auth(auth.clone());
                        }

                        if let Some(headers) = proxy.custom_headers() {
                            tunnel = tunnel.with_headers(headers.clone());
                        }

                        let io = tunnel.oneshot(uri).await?;
                        Ok(Routed {
                            io: RoutedIo::Hop(io),
                            request: req,
                            tls,
                            proxy: None,
                            restore_nagle,
                        })
                    } else {
                        // HTTP/1 forwarding to an HTTPS proxy must not negotiate target ALPN.
                        let mut tls = tls;
                        tls.no_alpn();
                        let req = req.with_route_uri(proxy_uri);
                        let io = dialer
                            .oneshot(req.route_uri().clone())
                            .await
                            .map_err(ProxyConnect::Source)?;
                        Ok(Routed {
                            io: RoutedIo::Socket(io),
                            request: req,
                            tls,
                            proxy: Some(proxy),
                            restore_nagle,
                        })
                    }
                }
                #[cfg(unix)]
                Some(Intercepted::Unix(_)) => {
                    let io = if secure {
                        let tunnel = tunnel::TunnelConnector::new(
                            Uri::from_static("http://localhost"),
                            proxy_hop(&tls, dialer, &req),
                        );
                        RoutedIo::Hop(tunnel.oneshot(uri).await?)
                    } else {
                        RoutedIo::Socket(dialer.oneshot(req.route_uri().clone()).await?)
                    };
                    Ok(Routed {
                        io,
                        request: req,
                        tls,
                        proxy: None,
                        restore_nagle: false,
                    })
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
