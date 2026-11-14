//! Stream routing for direct, proxy and Unix connections.
//!
//! The outer service enforces the connection deadline across dialing and handshakes.
//! TCP dials share that deadline so their timeout errors reach connector middleware.

use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use futures_util::future::BoxFuture;
use http::Uri;
use tower::{BoxError, Service};

use crate::{
    conn::{
        Conn,
        dialer::{Dialer, SocketRequest},
        request::ConnectRequest,
        route::Route,
        svc::TransportRequest,
    },
    error::{ProxyConnect, ProxyMismatch},
    ext::UriExt,
    proxy::Matcher,
    tls::connector::{MaybeHttpsStream, StreamTls},
};

#[cfg(feature = "socks")]
mod socks;
mod tls;
mod tunnel;

/// Selects a stream route and establishes the connection, including any proxy and TLS handshakes.
#[derive(Clone)]
pub(crate) struct StreamConnector {
    dialer: Dialer,
    proxies: Arc<Vec<Matcher>>,
    tls: StreamTls,
}

impl StreamConnector {
    /// Creates the stream routes over `dialer` with the client's proxy rules.
    pub(crate) fn new(dialer: Dialer, proxies: Arc<Vec<Matcher>>, tls: StreamTls) -> Self {
        Self {
            dialer,
            proxies,
            tls,
        }
    }
}

impl Service<TransportRequest> for StreamConnector {
    type Response = Conn;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Conn, BoxError>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, TransportRequest { request, deadline }: TransportRequest) -> Self::Future {
        let route = Route::select(&request, &self.proxies);
        Box::pin(connect(
            self.dialer.clone(),
            self.tls.clone(),
            request,
            route,
            deadline,
        ))
    }
}

async fn connect(
    dialer: Dialer,
    tls: StreamTls,
    request: ConnectRequest,
    route: Route,
    deadline: Option<Instant>,
) -> Result<Conn, BoxError> {
    debug!("starting new connection: {:?}", request.uri());
    let target_https = request.uri().is_https();
    let reset_nodelay = cfg_select! {
        unix => !dialer.nodelay() && !matches!(route, Route::Unix(_)),
        _ => !dialer.nodelay(),
    };

    let (io, tls) = match route {
        Route::Direct => {
            let tls = tls.for_request(&request)?;
            let io = dialer
                .dial(tcp_request(&request, request.uri().clone(), deadline))
                .await?;
            (MaybeHttpsStream::Http(io), tls)
        }
        Route::Http(proxy) if target_https => {
            let tls = tls.for_request(&request)?;
            let io = tunnel::connect(&dialer, &tls, &request, Some(&proxy), |uri| {
                tcp_request(&request, uri, deadline)
            })
            .await?;
            (io, tls)
        }
        Route::Http(proxy) => {
            let mut tls = tls
                .for_request(&request)
                .map_err(|error| ProxyConnect::Source(error.into()))?;
            tls.no_alpn();
            let io = dialer
                .dial(tcp_request(&request, proxy.uri().clone(), deadline))
                .await
                .map_err(ProxyConnect::Source)?;
            return tls::finish(io, request, tls, reset_nodelay, Some(proxy))
                .await
                .map_err(|error| ProxyConnect::Source(error).into());
        }
        #[cfg(feature = "socks")]
        Route::Socks {
            proxy,
            version,
            dns,
        } => {
            let tls = tls.for_request(&request)?;
            let io = socks::connect(&dialer, &request, &proxy, version, dns, deadline).await?;
            (MaybeHttpsStream::Http(io), tls)
        }
        #[cfg(unix)]
        Route::Unix(path) => {
            let tls = tls.for_request(&request)?;
            let io = if target_https {
                tunnel::connect(&dialer, &tls, &request, None, move |_| {
                    SocketRequest::Unix(path.clone())
                })
                .await?
            } else {
                MaybeHttpsStream::Http(dialer.dial(SocketRequest::Unix(path)).await?)
            };
            (io, tls)
        }
        Route::Quic(_) => return Err(ProxyMismatch("QUIC proxies require HTTP/3").into()),
    };

    // Unwrap the CONNECT result once, before the origin's TLS and subsequent I/O.
    match io {
        MaybeHttpsStream::Http(io) => tls::finish(io, request, tls, reset_nodelay, None).await,
        MaybeHttpsStream::Https(io) => tls::finish(io, request, tls, reset_nodelay, None).await,
    }
}

fn tcp_request(request: &ConnectRequest, uri: Uri, deadline: Option<Instant>) -> SocketRequest {
    SocketRequest::Tcp {
        secure: request.uri().is_https() || uri.is_https(),
        uri,
        config_set: request.config_set().clone(),
        deadline,
    }
}
