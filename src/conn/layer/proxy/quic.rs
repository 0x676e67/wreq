//! QUIC proxy routes: direct dials, MASQUE CONNECT-UDP and SOCKS5 UDP associations.
//! Proxy setup and the target handshake share the connector's deadline.

pub(crate) mod masque;
#[cfg(feature = "socks")]
pub(crate) mod socks;

use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::{self, BoxFuture, Either, Ready};
use tower::{BoxError, Layer, Service};

use super::intercept;
#[cfg(feature = "socks")]
use crate::conn::transport::SocketConnector;
use crate::{
    conn::{Conn, request::ConnectRequest, transport::QuicConnector},
    error::{ProxyConnect, ProxyMismatch},
    proxy::{Intercepted, Matcher, quic_port},
};

/// Middleware layer to use [`QuicProxyConnector`].
/// Clones share the client's proxy rules.
#[derive(Clone)]
pub(crate) struct QuicProxyLayer {
    proxies: Arc<Vec<Matcher>>,
    #[cfg(feature = "socks")]
    socket: SocketConnector,
}

/// Connects over QUIC directly, through a `quic://` MASQUE proxy, or through SOCKS5 UDP.
/// Other proxy routes fail before DNS. Only [`QuicConnector`] is wrapped, since tunnels
/// need its endpoints and TLS.
#[derive(Clone)]
pub(crate) struct QuicProxyConnector<S> {
    pub(in crate::conn) inner: S,
    proxies: Arc<Vec<Matcher>>,
    /// Dials the TCP control connections of SOCKS5 UDP associations.
    #[cfg(feature = "socks")]
    socket: SocketConnector,
}

// ===== impl QuicProxyLayer =====

impl QuicProxyLayer {
    pub(crate) fn new(
        proxies: Arc<Vec<Matcher>>,
        #[cfg(feature = "socks")] socket: SocketConnector,
    ) -> Self {
        Self {
            proxies,
            #[cfg(feature = "socks")]
            socket,
        }
    }
}

impl<S> Layer<S> for QuicProxyLayer {
    type Service = QuicProxyConnector<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        QuicProxyConnector {
            inner,
            proxies: self.proxies.clone(),
            #[cfg(feature = "socks")]
            socket: self.socket.clone(),
        }
    }
}

// ===== impl QuicProxyConnector =====

impl Service<ConnectRequest> for QuicProxyConnector<QuicConnector> {
    type Response = Conn;
    type Error = BoxError;
    type Future = Either<BoxFuture<'static, Result<Conn, BoxError>>, Ready<Result<Conn, BoxError>>>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: ConnectRequest) -> Self::Future {
        let proxy = match intercept(&request, &self.proxies) {
            None => return Either::Left(self.inner.call(request)),
            #[cfg(feature = "socks")]
            Some(Intercepted::Proxy(proxy))
                if matches!(proxy.uri().scheme_str(), Some("socks5" | "socks5h")) =>
            {
                let quic = self.inner.clone();
                let socket = self.socket.clone();
                return Either::Left(Box::pin(async move {
                    socks::connect(&quic, socket, request, proxy).await
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

        let quic = self.inner.clone();
        Either::Left(Box::pin(async move {
            masque::connect(&quic, request, proxy).await
        }))
    }
}
