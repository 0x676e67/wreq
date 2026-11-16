//! Stream routing for direct, proxy and Unix connections.
//!
//! The outer service enforces the connection deadline across dialing and handshakes.
//! TCP dials share that deadline so their timeout errors reach connector middleware.

use std::task::{Context, Poll};

use futures_util::future::{self, BoxFuture, Either, Ready};
use tower::{BoxError, Service};

use crate::{
    conn::{
        Conn,
        dialer::{Dialer, SocketRequest},
        request::ConnectAttempt,
        route::Route,
    },
    error::{ProxyConnect, ProxyMismatch},
    ext::UriExt,
    tls::connector::{MaybeHttpsStream, StreamTls},
};

#[cfg(feature = "socks")]
mod socks;
mod tls;
mod tunnel;

/// Establishes stream connections over a selected route, including any proxy and TLS handshakes.
#[derive(Clone)]
pub(crate) struct StreamConnector {
    dialer: Dialer,
    tls: StreamTls,
}

impl StreamConnector {
    /// Creates the stream connector over `dialer` with the client's stream TLS.
    pub(crate) fn new(dialer: Dialer, tls: StreamTls) -> Self {
        Self { dialer, tls }
    }
}

impl Service<(ConnectAttempt, Route)> for StreamConnector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Either<BoxFuture<'static, Result<Conn, BoxError>>, Ready<Result<Conn, BoxError>>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, (attempt, route): (ConnectAttempt, Route)) -> Self::Future {
        if let Route::Quic(_) = route {
            return Either::Right(future::err(
                ProxyMismatch("QUIC proxies require HTTP/3").into(),
            ));
        }
        Either::Left(Box::pin(connect(
            self.dialer.clone(),
            self.tls.clone(),
            attempt,
            route,
        )))
    }
}

async fn connect(
    dialer: Dialer,
    tls: StreamTls,
    attempt: ConnectAttempt,
    route: Route,
) -> Result<Conn, BoxError> {
    let (request, deadline) = attempt.into_parts();
    debug!("starting new connection: {:?}", request.uri());
    let is_https = request.uri().is_https();
    let nodelay = cfg_select! {
        unix => !dialer.nodelay() && !matches!(route, Route::Unix(_)),
        _ => !dialer.nodelay(),
    };
    let bindings = dialer.bindings(request.bindings());
    let mut tls = match tls.for_request(&request) {
        Ok(tls) => tls,
        Err(error) if matches!(route, Route::Http(_)) && !is_https => {
            return Err(ProxyConnect::Source(error.into()).into());
        }
        Err(error) => return Err(error.into()),
    };

    let io = match route {
        Route::Direct => {
            let io = dialer
                .dial(SocketRequest::tcp(
                    &request,
                    request.uri().clone(),
                    bindings,
                    deadline,
                ))
                .await?;
            MaybeHttpsStream::Http(io)
        }
        Route::Http(proxy) if is_https => {
            tunnel::connect(&dialer, &tls, &request, Some(&proxy), move |uri| {
                SocketRequest::Tcp {
                    secure: true,
                    uri,
                    bindings: bindings.clone(),
                    deadline,
                }
            })
            .await?
        }
        Route::Http(proxy) => {
            tls.no_alpn();
            let io = dialer
                .dial(SocketRequest::tcp(
                    &request,
                    proxy.uri().clone(),
                    bindings,
                    deadline,
                ))
                .await
                .map_err(ProxyConnect::Source)?;
            return tls::finish(io, request, tls, nodelay, Some(proxy))
                .await
                .map_err(|error| ProxyConnect::Source(error).into());
        }
        #[cfg(feature = "socks")]
        Route::Socks {
            proxy,
            version,
            dns,
        } => {
            let io = socks::connect(&dialer, &request, deadline, &proxy, version, dns).await?;
            MaybeHttpsStream::Http(io)
        }
        #[cfg(unix)]
        Route::Unix(path) => {
            if is_https {
                tunnel::connect(&dialer, &tls, &request, None, move |_| {
                    SocketRequest::Unix(path.clone())
                })
                .await?
            } else {
                MaybeHttpsStream::Http(dialer.dial(SocketRequest::Unix(path)).await?)
            }
        }
        Route::Quic(_) => unreachable!("rejected before boxing the connect future"),
    };

    // Unwrap the CONNECT result once, before the origin's TLS and subsequent I/O.
    match io {
        MaybeHttpsStream::Http(io) => tls::finish(io, request, tls, nodelay, None).await,
        MaybeHttpsStream::Https(io) => tls::finish(io, request, tls, nodelay, None).await,
    }
}
