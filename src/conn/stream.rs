//! The stream path's routes: direct, CONNECT tunnel, forward-proxy, SOCKS4/5 and Unix. Each
//! yields a [`Routed`] stream, which [`Tls`](super::layer::tls::Tls) finishes into a
//! [`Conn`](super::Conn).

#[cfg(unix)]
use std::path::Path;
use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use futures_util::future::BoxFuture;
use http::Uri;
#[cfg(feature = "socks")]
use netty::proxy::socks;
use netty::proxy::tunnel;
use tower::{BoxError, Service, ServiceExt};

use crate::{
    conn::{
        dialer::{BindOptions, Dialer, SocketRequest},
        request::ConnectRequest,
        route::Route,
    },
    error::{ProxyConnect, ProxyMismatch},
    ext::UriExt,
    proxy::{Matcher, matcher::Intercept},
    rt::{self, BoxConnection},
    tls::connector::{MaybeHttpsStream, TlsConnector},
};

/// Selects the request's route from its proxy rules and establishes a stream over it: a direct
/// socket, a forward-proxy connection or a proxy tunnel. Target TLS is left to the caller.
/// Clones share the dialer and proxy rules.
#[derive(Clone)]
pub(crate) struct StreamRouter {
    dialer: Dialer,
    proxies: Arc<Vec<Matcher>>,
}

/// A connection request with the TLS selected for it, which an HTTPS proxy hop reuses, and
/// the connect deadline a proxy dial stops at.
pub(crate) struct RouteRequest {
    pub(super) request: ConnectRequest,
    pub(super) tls: TlsConnector,
    pub(super) deadline: Option<Instant>,
}

/// A stream a route established, before target TLS, with what finishing it needs.
pub(crate) struct Routed {
    pub(super) io: RoutedIo,
    pub(super) request: ConnectRequest,
    /// The request's TLS, without ALPN when `proxy` is set.
    pub(super) tls: TlsConnector,
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

/// Dials the hosts a route names with one request's socket bindings and deadline.
#[derive(Clone)]
struct RouteDialer {
    dialer: Dialer,
    /// Whether the origin is `https`, which keeps Nagle off until its TLS handshake ends.
    secure: bool,
    bind_options: Option<Arc<BindOptions>>,
    #[cfg(unix)]
    unix: Option<Arc<Path>>,
    deadline: Option<Instant>,
}

/// Reaches a CONNECT proxy: dials it and, for an `https` proxy, runs TLS with it. The hop uses
/// the same per-connection TLS setup as the target, without ALPN.
#[derive(Clone)]
struct ProxyHop {
    dialer: RouteDialer,
    tls: TlsConnector,
    request: ConnectRequest,
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

    fn call(&mut self, req: RouteRequest) -> Self::Future {
        let RouteRequest {
            request,
            mut tls,
            deadline,
        } = req;
        let route = Route::select(&request, &self.proxies);
        let dialer = RouteDialer::new(&self.dialer, &request, &route, deadline);
        // A Unix socket has no Nagle to restore.
        let restore_nagle = cfg_select! {
            unix => !self.dialer.nodelay() && !matches!(route, Route::Unix(_)),
            _ => !self.dialer.nodelay(),
        };
        #[cfg(feature = "socks")]
        let resolver = self.dialer.resolver().clone();

        Box::pin(async move {
            debug!("starting new connection: {:?}", request.uri());
            let target = request.uri().clone();
            let mut forward = None;

            let io = match route {
                Route::Direct => RoutedIo::Socket(dialer.dial(target).await?),
                Route::Http(proxy) if target.is_https() => {
                    let hop = ProxyHop::new(dialer, &tls, &request);
                    let mut tunnel = tunnel::TunnelConnector::new(proxy.uri().clone(), hop);
                    if let Some(auth) = proxy.basic_auth() {
                        tunnel = tunnel.with_auth(auth.clone());
                    }
                    if let Some(headers) = proxy.custom_headers() {
                        tunnel = tunnel.with_headers(headers.clone());
                    }
                    RoutedIo::Hop(tunnel.oneshot(target).await?)
                }
                Route::Http(proxy) => {
                    // HTTP/1 forwarding to an HTTPS proxy must not negotiate target ALPN.
                    tls.no_alpn();
                    let io = dialer
                        .dial(proxy.uri().clone())
                        .await
                        .map_err(ProxyConnect::Source)?;
                    forward = Some(proxy);
                    RoutedIo::Socket(io)
                }
                #[cfg(feature = "socks")]
                Route::Socks {
                    proxy,
                    version,
                    dns,
                } => {
                    let mut connector = socks::SocksConnector::new(
                        proxy.uri().clone(),
                        dialer,
                        resolver.map_request(crate::dns::Name::new),
                    );
                    connector.set_auth(proxy.raw_auth());
                    connector.set_version(version);
                    connector.set_dns_mode(dns);
                    RoutedIo::Socket(connector.oneshot(target).await?)
                }
                Route::Quic(_) => {
                    return Err(ProxyMismatch("QUIC proxies require HTTP/3").into());
                }
                #[cfg(unix)]
                Route::Unix(_) => {
                    if target.is_https() {
                        let tunnel = tunnel::TunnelConnector::new(
                            Uri::from_static("http://localhost"),
                            ProxyHop::new(dialer, &tls, &request),
                        );
                        RoutedIo::Hop(tunnel.oneshot(target).await?)
                    } else {
                        RoutedIo::Socket(dialer.dial(target).await?)
                    }
                }
            };

            Ok(Routed {
                io,
                request,
                tls,
                proxy: forward,
                restore_nagle,
            })
        })
    }
}

// ===== impl RouteDialer =====

impl RouteDialer {
    fn new(
        dialer: &Dialer,
        request: &ConnectRequest,
        route: &Route,
        deadline: Option<Instant>,
    ) -> Self {
        Self {
            dialer: dialer.clone(),
            secure: request.uri().is_https(),
            bind_options: request.bind_options().clone(),
            #[cfg(unix)]
            unix: match route {
                Route::Unix(path) => Some(path.clone()),
                _ => None,
            },
            // Only a proxy dial reports its own timeout; the deadline layer bounds the rest.
            deadline: match route {
                Route::Direct => None,
                _ => deadline,
            },
        }
    }

    fn request(&self, uri: Uri) -> SocketRequest {
        SocketRequest {
            secure: self.secure || uri.is_https(),
            uri,
            bind_options: self.bind_options.clone(),
            #[cfg(unix)]
            unix: self.unix.clone(),
            deadline: self.deadline,
        }
    }

    /// Dials `uri` without boxing the future.
    async fn dial(&self, uri: Uri) -> Result<BoxConnection, BoxError> {
        self.dialer.dial(self.request(uri)).await
    }
}

impl Service<Uri> for RouteDialer {
    type Response = BoxConnection;
    type Error = BoxError;
    type Future = <Dialer as Service<SocketRequest>>::Future;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.dialer.poll_ready(cx)
    }

    #[inline]
    fn call(&mut self, uri: Uri) -> Self::Future {
        let request = self.request(uri);
        self.dialer.call(request)
    }
}

// ===== impl ProxyHop =====

impl ProxyHop {
    fn new(dialer: RouteDialer, tls: &TlsConnector, request: &ConnectRequest) -> Self {
        let mut tls = tls.clone();
        tls.no_alpn();
        Self {
            dialer,
            tls,
            request: request.clone(),
        }
    }
}

impl Service<Uri> for ProxyHop {
    type Response = MaybeHttpsStream<BoxConnection>;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, BoxError>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.dialer.poll_ready(cx)
    }

    fn call(&mut self, proxy: Uri) -> Self::Future {
        let dialer = self.dialer.clone();
        let tls = self.tls.clone();
        let request = self.request.clone();

        Box::pin(async move {
            let io = dialer.dial(proxy.clone()).await?;
            let remote_ip = io.peer_addr().map(|addr| addr.ip());
            tls.handshake(io, &request, &proxy, remote_ip).await
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
