//! TCP and Unix proxy handshakes and shared proxy selection.
//! [`ProxyConnection`] passes the stream to [`super::tls`] for target TLS.
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
use tower::{BoxError, Layer, Service, ServiceExt};

use crate::{
    conn::{request::ConnectRequest, transport::SocketRequest},
    dns::DynResolver,
    error::ProxyConnect,
    ext::UriExt,
    proxy::{Intercepted, Matcher, matcher::Intercept},
    rt::BoxConnection,
    tls::connector::{HttpsConnector, MaybeHttpsStream, TlsConnector},
};

/// Adds proxy selection and handshakes around a socket service.
/// The selected target TLS context travels with tunnels to the outer TLS service.
#[derive(Clone)]
pub(crate) struct ProxyLayer {
    proxies: Arc<Vec<Matcher>>,
    tls: TlsConnector,
    resolver: DynResolver,
}

/// Establishes a direct socket, a forward-proxy connection, or a proxy tunnel.
/// Each attempt waits for readiness on the socket service instance it calls.
#[derive(Clone)]
pub(crate) struct ProxyConnector<S> {
    inner: S,
    proxies: Arc<Vec<Matcher>>,
    tls: TlsConnector,
    #[cfg_attr(
        not(feature = "socks"),
        expect(
            dead_code,
            reason = "Only SOCKS currently resolves targets outside socket dialing"
        )
    )]
    resolver: DynResolver,
}

/// Socket or tunnel plus the state needed to finish TLS and attach proxy metadata.
pub(crate) enum ProxyConnection {
    /// A direct or SOCKS connection ready for optional target TLS.
    Raw {
        io: BoxConnection,
        req: ConnectRequest,
        tls: HttpsConnector<()>,
    },
    /// A CONNECT tunnel whose transport may already use proxy TLS.
    Tunnel {
        io: MaybeHttpsStream<BoxConnection>,
        req: ConnectRequest,
        tls: HttpsConnector<()>,
        tcp: bool,
    },
    /// A forward proxy handles HTTP requests without an additional target handshake.
    Forward {
        io: MaybeHttpsStream<BoxConnection>,
        proxy: Option<Intercept>,
    },
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

// ===== impl ProxyLayer =====

impl ProxyLayer {
    pub(crate) fn new(
        proxies: Arc<Vec<Matcher>>,
        tls: TlsConnector,
        resolver: DynResolver,
    ) -> Self {
        Self {
            proxies,
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
            proxies: self.proxies.clone(),
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
    type Response = ProxyConnection;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: ConnectRequest) -> Self::Future {
        let inner = self.inner.clone();
        let proxies = self.proxies.clone();
        let tls = self.tls.clone();
        #[cfg(feature = "socks")]
        let resolver = self.resolver.clone();

        Box::pin(async move {
            debug!("starting new connection: {:?}", req.uri());
            let intercepted = intercept(&req, &proxies);
            let uri = req.uri().clone();
            let secure = uri.is_https();
            let bindings = req.bind_options().clone();

            #[cfg(unix)]
            let unix = match &intercepted {
                Some(Intercepted::Unix(path)) => Some(path.clone()),
                _ => None,
            };

            let inner = inner.map_request(move |uri: Uri| SocketRequest {
                secure: secure || uri.is_https(),
                uri,
                options: bindings.clone(),
                #[cfg(unix)]
                unix: unix.clone(),
            });
            let tls = tls.layer(());

            match intercepted {
                None => {
                    let tls = tls.with_request(&req)?;
                    let io = inner
                        .oneshot(req.route_uri().clone())
                        .await
                        .map_err(Into::into)?;
                    Ok(ProxyConnection::Raw { io, req, tls })
                }
                Some(Intercepted::Proxy(proxy)) => {
                    let proxy_uri = proxy.uri().clone();
                    if proxy_uri.scheme_str() == Some("quic") {
                        return Err(
                            ProxyConnect::Message("QUIC proxies require HTTP/3".into()).into()
                        );
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
                        let tls = tls.with_request(&req)?;
                        return Ok(ProxyConnection::Raw { io, req, tls });
                    }

                    if secure {
                        let tls = tls.with_request(&req)?;
                        let connector = tls.clone().with_inner(inner);
                        let mut tunnel = tunnel::TunnelConnector::new(proxy_uri, connector);

                        if let Some(auth) = proxy.basic_auth() {
                            tunnel = tunnel.with_auth(auth.clone());
                        }

                        if let Some(headers) = proxy.custom_headers() {
                            tunnel = tunnel.with_headers(headers.clone());
                        }

                        let io = tunnel.oneshot(uri).await?;
                        Ok(ProxyConnection::Tunnel {
                            io,
                            req,
                            tls,
                            tcp: true,
                        })
                    } else {
                        // HTTP/1 forwarding to an HTTPS proxy must not negotiate target ALPN.
                        let mut connector = tls
                            .with_request(&req)
                            .map_err(|err| ProxyConnect::Source(err.into()))?
                            .with_inner(inner);
                        connector.no_alpn();
                        let io = connector
                            .oneshot(req.with_route_uri(proxy_uri))
                            .await
                            .map_err(ProxyConnect::Source)?;
                        Ok(ProxyConnection::Forward {
                            io,
                            proxy: Some(proxy),
                        })
                    }
                }
                #[cfg(unix)]
                Some(Intercepted::Unix(_)) => {
                    let tls = tls.with_request(&req)?;
                    if secure {
                        let connector = tls.clone().with_inner(inner);
                        let tunnel = tunnel::TunnelConnector::new(
                            Uri::from_static("http://localhost"),
                            connector,
                        );
                        let io = tunnel.oneshot(uri).await?;
                        Ok(ProxyConnection::Tunnel {
                            io,
                            req,
                            tls,
                            tcp: false,
                        })
                    } else {
                        let io = tls.with_inner(inner).oneshot(req).await?;
                        Ok(ProxyConnection::Forward { io, proxy: None })
                    }
                }
            }
        })
    }
}

#[cfg(all(test, feature = "tokio-rt"))]
mod tests {
    use std::{
        future::pending,
        sync::atomic::{AtomicBool, Ordering},
    };

    use super::*;
    use crate::{
        Proxy,
        conn::{config::ConfigSet, layer::tls::TlsLayer},
        rt::{Runtime, tokio::TokioRuntime},
        tls::config::TlsConnectorBuilder,
    };

    struct Socket {
        active: Arc<AtomicBool>,
        forwarded: bool,
        waited: bool,
        reserved: bool,
    }

    struct Active(Arc<AtomicBool>);

    // ===== impl Socket =====

    impl Clone for Socket {
        fn clone(&self) -> Self {
            Self {
                active: self.active.clone(),
                forwarded: self.forwarded,
                waited: false,
                reserved: false,
            }
        }
    }

    impl Service<SocketRequest> for Socket {
        type Response = BoxConnection;
        type Error = BoxError;
        type Future = BoxFuture<'static, Result<BoxConnection, BoxError>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
            if !self.waited {
                self.waited = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.reserved = true;
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: SocketRequest) -> Self::Future {
            assert!(
                std::mem::take(&mut self.reserved),
                "called without this instance's readiness"
            );
            assert_eq!(
                req.uri.authority().unwrap().as_str(),
                if self.forwarded {
                    "proxy.invalid:8080"
                } else {
                    "target.invalid"
                }
            );
            self.active.store(true, Ordering::Relaxed);
            let active = Active(self.active.clone());
            Box::pin(async move {
                let _active = active;
                pending().await
            })
        }
    }

    // ===== impl Active =====

    impl Drop for Active {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Relaxed);
        }
    }

    #[test]
    fn composed_stream_preserves_socket_readiness_and_cancellation() {
        let tls = TlsConnectorBuilder::new()
            .build(ConfigSet::default())
            .unwrap();
        let resolver = DynResolver::new(TokioRuntime.resolver());

        for forwarded in [false, true] {
            let proxies = Arc::new(if forwarded {
                vec![
                    Proxy::all("http://proxy.invalid:8080")
                        .unwrap()
                        .into_matcher(),
                ]
            } else {
                Vec::new()
            });
            let active = Arc::new(AtomicBool::new(false));
            let connector = TlsLayer::new(false, true, false).layer(
                ProxyLayer::new(proxies, tls.clone(), resolver.clone()).layer(Socket {
                    active: active.clone(),
                    forwarded,
                    waited: false,
                    reserved: false,
                }),
            );
            let req = ConnectRequest::test(
                Uri::from_static("http://target.invalid/"),
                None,
                ConfigSet::default(),
            );
            let mut connecting = tokio_test::task::spawn(connector.oneshot(req));
            assert!(connecting.poll().is_pending());
            assert!(!active.load(Ordering::Relaxed));
            assert!(connecting.poll().is_pending());
            assert!(active.load(Ordering::Relaxed));
            drop(connecting);
            assert!(!active.load(Ordering::Relaxed));
        }
    }
}
