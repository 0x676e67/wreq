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
    conn::{Conn, dialer::Dialer, request::ConnectAttempt, route::Route},
    error::{ProxyConnect, ProxyMismatch},
    proxy::quic_port,
    tls::quic::QuicTls,
};

/// Connects HTTP/3 origins over a selected route: directly, through a `quic://` MASQUE proxy, or
/// through SOCKS5 UDP. Unsupported proxy routes fail before DNS. Clones share the endpoints.
#[derive(Clone)]
pub(crate) struct QuicConnector {
    endpoints: Arc<Endpoints>,
}

// ===== impl QuicConnector =====

impl QuicConnector {
    /// Creates the QUIC path over `dialer` with the client's QUIC TLS.
    /// Endpoints open on the first connection that needs them.
    pub(crate) fn new(dialer: Dialer, tls: QuicTls) -> crate::Result<Self> {
        Ok(Self {
            endpoints: Arc::new(Endpoints::new(dialer, tls)?),
        })
    }
}

impl Service<(ConnectAttempt, Route)> for QuicConnector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Either<BoxFuture<'static, Result<Conn, BoxError>>, Ready<Result<Conn, BoxError>>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, (attempt, route): (ConnectAttempt, Route)) -> Self::Future {
        let endpoints = self.endpoints.clone();
        match route {
            Route::Direct => Either::Left(Box::pin(async move {
                endpoints.connect(attempt.request()).await
            })),
            #[cfg(feature = "socks")]
            Route::Socks {
                proxy,
                version: Version::V5,
                dns,
            } => {
                let (request, deadline) = attempt.into_parts();
                Either::Left(Box::pin(async move {
                    socks::connect(&endpoints, request, deadline, proxy, dns).await
                }))
            }
            Route::Quic(proxy) => {
                // Environment proxy entries reach this point without builder validation.
                if let Err(message) = quic_port(proxy.uri()) {
                    return Either::Right(future::err(ProxyConnect::Message(message).into()));
                }
                let (request, deadline) = attempt.into_parts();
                Either::Left(Box::pin(async move {
                    masque::connect(&endpoints, request, deadline, proxy).await
                }))
            }
            _ => Either::Right(future::err(
                ProxyMismatch("HTTP/3 requires a quic:// proxy or SOCKS5 with the socks feature")
                    .into(),
            )),
        }
    }
}
