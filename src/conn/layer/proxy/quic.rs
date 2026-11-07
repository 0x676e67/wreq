//! Selects direct QUIC, MASQUE or SOCKS5 UDP routes.
//! Proxy setup and the target handshake share the enclosing connection deadline.

mod masque;
#[cfg(feature = "socks")]
mod socks;

use std::{
    future::ready,
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::BoxFuture;
use tower::{BoxError, Layer, Service};

#[cfg(feature = "socks")]
use crate::{conn::transport::TcpConnector, dns::DynResolver};
use crate::{
    conn::{Conn, request::ConnectRequest, transport::QuicConnector},
    error::{ProxyConnect, ProxyMismatch},
    proxy::{Intercepted, Matcher, quic_port},
    rt::DynRuntime,
};

/// Stores the client proxy rules and runtime used to build the QUIC proxy service.
#[derive(Clone)]
pub(crate) struct QuicProxyLayer {
    runtime: DynRuntime,
    proxies: Arc<Vec<Matcher>>,
    #[cfg(feature = "socks")]
    tcp: TcpConnector<DynResolver>,
    #[cfg(feature = "socks")]
    resolver: DynResolver,
}

/// Establishes the selected route and returns the target QUIC connection.
/// Direct requests use the inner service; proxied requests retain their tunnel
/// with the returned connection's endpoint.
#[derive(Clone)]
pub(crate) struct QuicProxyConnector {
    inner: QuicConnector,
    runtime: DynRuntime,
    proxies: Arc<Vec<Matcher>>,
    #[cfg(feature = "socks")]
    tcp: TcpConnector<DynResolver>,
    #[cfg(feature = "socks")]
    resolver: DynResolver,
}

// ===== impl QuicProxyLayer =====

impl QuicProxyLayer {
    /// Uses `runtime` to drive proxy HTTP/3 connections and `proxies` as client rules.
    pub(crate) fn new(
        runtime: DynRuntime,
        proxies: Arc<Vec<Matcher>>,
        #[cfg(feature = "socks")] tcp: TcpConnector<DynResolver>,
        #[cfg(feature = "socks")] resolver: DynResolver,
    ) -> Self {
        Self {
            runtime,
            proxies,
            #[cfg(feature = "socks")]
            tcp,
            #[cfg(feature = "socks")]
            resolver,
        }
    }
}

impl Layer<QuicConnector> for QuicProxyLayer {
    type Service = QuicProxyConnector;

    fn layer(&self, inner: QuicConnector) -> Self::Service {
        QuicProxyConnector {
            inner,
            runtime: self.runtime.clone(),
            proxies: self.proxies.clone(),
            #[cfg(feature = "socks")]
            tcp: self.tcp.clone(),
            #[cfg(feature = "socks")]
            resolver: self.resolver.clone(),
        }
    }
}

// ===== impl QuicProxyConnector =====

impl Service<ConnectRequest> for QuicProxyConnector {
    type Response = Conn;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Conn, BoxError>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: ConnectRequest) -> Self::Future {
        let proxy = match super::intercept(&request, &self.proxies) {
            None => return self.inner.call(request),
            #[cfg(feature = "socks")]
            Some(Intercepted::Proxy(proxy))
                if matches!(proxy.uri().scheme_str(), Some("socks5" | "socks5h")) =>
            {
                let inner = self.inner.clone();
                let mut tcp = self.tcp.clone();
                if let Some(bind_options) = request.bind_options() {
                    tcp = tcp.set_bind_options(bind_options);
                }
                let resolver = self.resolver.clone();
                let timer = self.runtime.timer();
                return Box::pin(socks::connect(inner, tcp, resolver, timer, request, proxy));
            }
            Some(Intercepted::Proxy(proxy)) if proxy.uri().scheme_str() == Some("quic") => proxy,
            Some(_) => {
                return Box::pin(ready(Err(ProxyMismatch(
                    "HTTP/3 requires a quic:// proxy or SOCKS5 with the socks feature",
                )
                .into())));
            }
        };

        // Environment proxy entries reach this layer without builder validation.
        if let Err(message) = quic_port(proxy.uri()) {
            return Box::pin(ready(Err(ProxyConnect::Message(message).into())));
        }

        // The concrete transport has no readiness reservation to transfer to its clone.
        let inner = self.inner.clone();
        let runtime = self.runtime.clone();
        Box::pin(masque::connect(runtime, inner, request, proxy))
    }
}
