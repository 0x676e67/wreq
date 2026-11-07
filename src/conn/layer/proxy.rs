//! TCP and Unix proxy handshakes, shared proxy selection and target TLS.
//! Every stream route ends in one place that finishes TLS and builds the [`Conn`].
//! With `http3`, the `quic` submodule establishes QUIC proxy routes.

#[cfg(feature = "http3")]
mod quic;

use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::BoxFuture;
use http::Uri;
#[cfg(feature = "socks")]
use netty::proxy::socks;
use netty::proxy::tunnel;
#[cfg(feature = "http3")]
pub(crate) use quic::{QuicProxyConnector, QuicProxyLayer};
use tower::{BoxError, Layer, Service, ServiceExt, util::MapRequest};

use crate::{
    conn::{
        AsyncConnWithInfo, Config, Conn, TlsConn, Transport, request::ConnectRequest,
        transport::SocketRequest, verbose::Verbose,
    },
    dns::DynResolver,
    error::{ProxyConnect, ProxyMismatch},
    ext::UriExt,
    proxy::{Intercepted, Matcher},
    rt::{self, BoxConnection},
    tls::connector::{HttpsConnector, HttpsLayer, MaybeHttpsStream},
};

/// Adds proxy selection, proxy handshakes and target TLS around a socket service.
/// Clones share the client's proxy rules and connection policy.
#[derive(Clone)]
pub(crate) struct ProxyLayer {
    config: Arc<Config>,
    tls: HttpsLayer,
    resolver: DynResolver,
}

/// Establishes a direct socket, a forward-proxy connection, or a proxy tunnel,
/// then finishes target TLS and returns the stream for the HTTP/1 or HTTP/2 pool.
/// Each attempt waits for readiness on the socket service instance it calls.
#[derive(Clone)]
pub(crate) struct ProxyConnector<S> {
    inner: S,
    config: Arc<Config>,
    tls: HttpsLayer,
    #[cfg_attr(
        not(feature = "socks"),
        expect(
            dead_code,
            reason = "Only SOCKS currently resolves targets outside socket dialing"
        )
    )]
    resolver: DynResolver,
}

/// A dialed stream whose socket stays reachable beneath any proxy TLS.
trait Dialed {
    /// Returns the socket dialed by the runtime.
    fn socket(&self) -> &dyn rt::Connection;
}

/// Tries the request's proxy rule, then the client's rules in order.
fn intercept(request: &ConnectRequest, proxies: &[Matcher]) -> Option<Intercepted> {
    request
        .config_override::<Matcher>()
        .and_then(|proxy| proxy.intercept(request.uri()))
        .or_else(|| {
            proxies
                .iter()
                .find_map(|proxy| proxy.intercept(request.uri()))
        })
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

/// Finishes TLS over an established route, restores Nagle once for TCP routes,
/// and attaches connection metadata. An `http` route skips TLS.
async fn finish<IO>(
    config: &Config,
    io: IO,
    req: ConnectRequest,
    tls: HttpsConnector<()>,
    restore_nodelay: bool,
) -> Result<Conn, BoxError>
where
    IO: AsyncConnWithInfo + Dialed,
{
    let verbose = Verbose(config.verbose);
    let stream = match tls.handshake(io, req).await? {
        MaybeHttpsStream::Http(stream) => verbose.wrap(stream),
        MaybeHttpsStream::Https(stream) => {
            if restore_nodelay && !config.nodelay {
                stream.get_ref().socket().set_nodelay(false)?;
            }
            verbose.wrap(TlsConn { stream })
        }
    };
    let mut connected = stream.connected();
    if config.tls_info
        && let Some(tls_info) = stream.tls_info()
    {
        connected = connected.extra(tls_info);
    }
    Ok(Conn {
        transport: Transport::Stream(stream),
        connected,
    })
}

// ===== impl ProxyLayer =====

impl ProxyLayer {
    pub(crate) fn new(config: Config, tls: HttpsLayer, resolver: DynResolver) -> Self {
        Self {
            config: Arc::new(config),
            tls,
            resolver,
        }
    }
}

impl<S> Layer<S> for ProxyLayer {
    type Service = ProxyConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyConnector {
            inner,
            config: self.config.clone(),
            tls: self.tls.clone(),
            resolver: self.resolver.clone(),
        }
    }
}

// ===== impl ProxyConnector =====

impl<S> Service<ConnectRequest> for ProxyConnector<S>
where
    S: Service<SocketRequest, Response = BoxConnection> + Clone + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + Unpin + 'static,
{
    type Response = Conn;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: ConnectRequest) -> Self::Future {
        let inner = self.inner.clone();
        let config = self.config.clone();
        let tls = self.tls.clone();
        #[cfg(feature = "socks")]
        let resolver = self.resolver.clone();

        Box::pin(async move {
            debug!("starting new connection: {:?}", req.uri());
            let intercepted = intercept(&req, &config.proxies);
            let uri = req.uri().clone();
            let secure = uri.is_https();
            let bind_options = req.bind_options().clone();

            #[cfg(unix)]
            let unix = match &intercepted {
                Some(Intercepted::Unix(path)) => Some(path.clone()),
                _ => None,
            };

            let inner = inner.map_request(move |uri: Uri| SocketRequest {
                secure: secure || uri.is_https(),
                uri,
                bind_options: bind_options.clone(),
                #[cfg(unix)]
                unix: unix.clone(),
            });

            match intercepted {
                None => {
                    let tls = tls.for_request(&req)?;
                    let io = inner
                        .oneshot(req.route_uri().clone())
                        .await
                        .map_err(Into::into)?;
                    finish(&config, io, req, tls, true).await
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
                            inner,
                            resolver.map_request(crate::dns::Name::new),
                        );
                        connector.set_auth(proxy.raw_auth());
                        connector.set_version(version);
                        connector.set_dns_mode(dns);

                        let io = connector.oneshot(uri).await?;
                        let tls = tls.for_request(&req)?;
                        return finish(&config, io, req, tls, true).await;
                    }

                    if secure {
                        let tls = tls.for_request(&req)?;
                        let mut tunnel =
                            tunnel::TunnelConnector::new(proxy_uri, proxy_hop(&tls, inner, &req));

                        if let Some(auth) = proxy.basic_auth() {
                            tunnel = tunnel.with_auth(auth.clone());
                        }

                        if let Some(headers) = proxy.custom_headers() {
                            tunnel = tunnel.with_headers(headers.clone());
                        }

                        let io = tunnel.oneshot(uri).await?;
                        finish(&config, io, req, tls, true).await
                    } else {
                        // HTTP/1 forwarding to an HTTPS proxy must not negotiate target ALPN.
                        let mut tls = tls
                            .for_request(&req)
                            .map_err(|err| ProxyConnect::Source(err.into()))?;
                        tls.no_alpn();
                        let req = req.with_route_uri(proxy_uri);
                        let io = inner
                            .oneshot(req.route_uri().clone())
                            .await
                            .map_err(|err| ProxyConnect::Source(err.into()))?;
                        let mut conn = finish(&config, io, req, tls, true)
                            .await
                            .map_err(ProxyConnect::Source)?;
                        conn.connected = conn.connected.proxy(proxy);
                        Ok(conn)
                    }
                }
                #[cfg(unix)]
                Some(Intercepted::Unix(_)) => {
                    let tls = tls.for_request(&req)?;
                    if secure {
                        let tunnel = tunnel::TunnelConnector::new(
                            Uri::from_static("http://localhost"),
                            proxy_hop(&tls, inner, &req),
                        );
                        let io = tunnel.oneshot(uri).await?;
                        finish(&config, io, req, tls, false).await
                    } else {
                        let io = inner
                            .oneshot(req.route_uri().clone())
                            .await
                            .map_err(Into::into)?;
                        finish(&config, io, req, tls, false).await
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
