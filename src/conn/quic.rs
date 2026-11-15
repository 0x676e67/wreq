//! The QUIC path: direct dials, MASQUE CONNECT-UDP and SOCKS5 UDP routes over the client's
//! QUIC [`Endpoints`]. Proxy setup and the target handshake share the connector's deadline.

mod endpoint;
mod masque;
#[cfg(feature = "socks")]
mod socks;

use std::{
    sync::Arc,
    task::{Context, Poll},
};

use endpoint::Endpoints;
#[cfg(test)]
pub(crate) use endpoint::test_server_config;
use futures_util::future::{self, BoxFuture, Either, Ready};
#[cfg(feature = "socks")]
use netty::proxy::socks::Version;
use tower::{BoxError, Service};

use crate::{
    conn::{Conn, dialer::Dialer, route::Route, svc::TransportRequest},
    error::{ProxyConnect, ProxyMismatch},
    proxy::{Matcher, quic_port},
    tls::quic::QuicTls,
};

/// Selects the request's route from its proxy rules and connects HTTP/3 origins over it:
/// directly, through a `quic://` MASQUE proxy, or through SOCKS5 UDP. Other proxy routes fail
/// before DNS. Clones share the proxy rules and endpoints.
#[derive(Clone)]
pub(crate) struct QuicRouter {
    inner: Arc<Inner>,
}

/// The client's proxy rules and the endpoints every route connects through.
struct Inner {
    proxies: Arc<Vec<Matcher>>,
    endpoints: Endpoints,
}

// ===== impl QuicRouter =====

impl QuicRouter {
    /// Creates the QUIC path over `dialer` with the client's QUIC TLS and proxy rules.
    /// Endpoints open on the first connection that needs them.
    pub(crate) fn new(
        dialer: Dialer,
        tls: QuicTls,
        proxies: Arc<Vec<Matcher>>,
    ) -> crate::Result<Self> {
        Ok(Self {
            inner: Arc::new(Inner {
                proxies,
                endpoints: Endpoints::new(dialer, tls)?,
            }),
        })
    }
}

impl Service<TransportRequest> for QuicRouter {
    type Response = Conn;
    type Error = BoxError;
    type Future = Either<BoxFuture<'static, Result<Conn, BoxError>>, Ready<Result<Conn, BoxError>>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, TransportRequest { request, deadline }: TransportRequest) -> Self::Future {
        let inner = self.inner.clone();
        match Route::select(&request, &inner.proxies) {
            Route::Direct => {
                Either::Left(Box::pin(
                    async move { inner.endpoints.connect(&request).await },
                ))
            }
            #[cfg(feature = "socks")]
            Route::Socks {
                proxy,
                version: Version::V5,
                dns,
            } => Either::Left(Box::pin(async move {
                socks::connect(&inner.endpoints, request, proxy, dns, deadline).await
            })),
            Route::Quic(proxy) => {
                // Environment proxy entries reach this point without builder validation.
                if let Err(message) = quic_port(proxy.uri()) {
                    return Either::Right(future::err(ProxyConnect::Message(message).into()));
                }
                Either::Left(Box::pin(async move {
                    masque::connect(&inner.endpoints, request, proxy, deadline).await
                }))
            }
            _ => Either::Right(future::err(
                ProxyMismatch("HTTP/3 requires a quic:// proxy or SOCKS5 with the socks feature")
                    .into(),
            )),
        }
    }
}
