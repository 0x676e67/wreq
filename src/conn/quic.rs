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
use tower::{BoxError, Service};

use crate::{
    conn::{Conn, dialer::Dialer, request::ConnectRequest},
    error::{ProxyConnect, ProxyMismatch},
    proxy::{Intercepted, Matcher, quic_port},
    tls::quic::QuicTls,
};

/// Connects HTTP/3 origins over QUIC directly, through a `quic://` MASQUE proxy, or through
/// SOCKS5 UDP. Other proxy routes fail before DNS. Clones share the proxy rules and endpoints.
#[derive(Clone)]
pub(crate) struct QuicConnector {
    inner: Arc<Inner>,
}

/// The client's proxy rules and the endpoints every route connects through.
struct Inner {
    proxies: Arc<Vec<Matcher>>,
    endpoints: Endpoints,
}

// ===== impl QuicConnector =====

impl QuicConnector {
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

impl Service<ConnectRequest> for QuicConnector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Either<BoxFuture<'static, Result<Conn, BoxError>>, Ready<Result<Conn, BoxError>>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: ConnectRequest) -> Self::Future {
        let proxy = match request
            .config_override::<Matcher>()
            .and_then(|proxy| proxy.intercept(request.uri()))
            .or_else(|| {
                self.inner
                    .proxies
                    .iter()
                    .find_map(|proxy| proxy.intercept(request.uri()))
            }) {
            None => {
                let inner = self.inner.clone();
                return Either::Left(Box::pin(
                    async move { inner.endpoints.connect(&request).await },
                ));
            }
            #[cfg(feature = "socks")]
            Some(Intercepted::Proxy(proxy))
                if matches!(proxy.uri().scheme_str(), Some("socks5" | "socks5h")) =>
            {
                let inner = self.inner.clone();
                return Either::Left(Box::pin(async move {
                    socks::connect(&inner.endpoints, request, proxy).await
                }));
            }
            Some(Intercepted::Proxy(proxy)) if proxy.uri().scheme_str() == Some("quic") => proxy,
            Some(_) => {
                return Either::Right(future::err(
                    ProxyMismatch(
                        "HTTP/3 requires a quic:// proxy or SOCKS5 with the socks feature",
                    )
                    .into(),
                ));
            }
        };

        // Environment proxy entries reach this point without builder validation.
        if let Err(message) = quic_port(proxy.uri()) {
            return Either::Right(future::err(ProxyConnect::Message(message).into()));
        }

        let inner = self.inner.clone();
        Either::Left(Box::pin(async move {
            masque::connect(&inner.endpoints, request, proxy).await
        }))
    }
}
