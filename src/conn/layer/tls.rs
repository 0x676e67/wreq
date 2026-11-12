//! Target TLS for the stream path.

use std::task::{Context, Poll};

use futures_util::future::{self, BoxFuture};
use tower::{BoxError, Layer, Service};

use crate::{
    conn::{
        Conn, Connected, HttpInfo, Io, Transport,
        connected::tls_info,
        request::ConnectRequest,
        stream::{Dialed, RouteRequest, Routed, RoutedIo},
        svc::TransportRequest,
    },
    error::ProxyConnect,
    proxy::matcher::Intercept,
    tls::{
        AlpnProtocol,
        connector::{MaybeHttpsStream, StreamTls, TlsConnector},
    },
};

/// Middleware layer to use [`Tls`].
#[derive(Clone)]
pub(crate) struct TlsLayer {
    tls: StreamTls,
}

/// Finishes the stream a route establishes. It selects the request's TLS before routing, so a
/// local TLS error costs no dial and a proxy hop reuses the selection; then it runs the target
/// handshake over the routed stream and builds the [`Conn`] with its metadata.
#[derive(Clone)]
pub(crate) struct Tls<S> {
    inner: S,
    tls: StreamTls,
}

/// Finishes TLS over an established route and restores Nagle once when `restore_nagle` is set.
/// The TLS peer is `proxy`, the forward proxy `io` reaches, or else the origin; an `http` peer
/// skips TLS. Builds the metadata from the dialed socket's addresses, the TLS session and the
/// proxy's identity.
async fn finish<S>(
    io: S,
    request: ConnectRequest,
    tls: TlsConnector,
    restore_nagle: bool,
    proxy: Option<Intercept>,
) -> Result<Conn, BoxError>
where
    S: Io + Dialed,
{
    let socket = io.socket();
    let (local_addr, remote_addr) = (socket.local_addr(), socket.peer_addr());
    let route = proxy.as_ref().map_or(request.uri(), Intercept::uri);
    let stream = tls
        .handshake(io, &request, route, remote_addr.map(|addr| addr.ip()))
        .await?;

    let mut connected = Connected::new();
    if let (Some(local_addr), Some(remote_addr)) = (local_addr, remote_addr) {
        connected = connected.extra(HttpInfo {
            remote_addr,
            local_addr,
        });
    }
    if let Some(proxy) = proxy {
        connected = connected.proxy(proxy);
    }
    let stream: Box<dyn Io> = match stream {
        MaybeHttpsStream::Http(stream) => Box::new(stream),
        MaybeHttpsStream::Https(stream) => {
            if restore_nagle {
                stream.get_ref().socket().set_nodelay(false)?;
            }
            let ssl = stream.ssl();
            if ssl
                .selected_alpn_protocol()
                .is_some_and(|alpn| AlpnProtocol::HTTP2.eq(alpn))
            {
                connected = connected.negotiated_h2();
            }
            if tls.tls_info() {
                connected = connected.extra(tls_info(
                    ssl.peer_certificate().as_deref(),
                    ssl.peer_cert_chain(),
                ));
            }
            Box::new(stream)
        }
    };
    Ok(Conn {
        transport: Transport::Stream(stream),
        connected,
    })
}

// ===== impl TlsLayer =====

impl TlsLayer {
    /// Creates a layer that finishes routed streams with the client's compiled stream TLS.
    pub(crate) fn new(tls: StreamTls) -> Self {
        Self { tls }
    }
}

impl<S> Layer<S> for TlsLayer {
    type Service = Tls<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        Tls {
            inner,
            tls: self.tls.clone(),
        }
    }
}

// ===== impl Tls =====

impl<S> Service<TransportRequest> for Tls<S>
where
    S: Service<RouteRequest, Response = Routed>,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = Conn;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Conn, BoxError>>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, TransportRequest { request, deadline }: TransportRequest) -> Self::Future {
        let tls = match self.tls.clone().for_request(&request) {
            Ok(tls) => tls,
            Err(error) => return Box::pin(future::ready(Err(error.into()))),
        };
        let routing = self.inner.call(RouteRequest {
            request,
            tls,
            deadline,
        });

        Box::pin(async move {
            let Routed {
                io,
                request,
                tls,
                proxy,
                restore_nagle,
            } = routing.await.map_err(Into::into)?;
            // A forward proxy is the TLS peer, so a failed handshake is a proxy failure.
            let forward = proxy.is_some();
            let conn = match io {
                RoutedIo::Socket(io) => finish(io, request, tls, restore_nagle, proxy).await,
                RoutedIo::Hop(io) => finish(io, request, tls, restore_nagle, proxy).await,
            };
            if forward {
                conn.map_err(|error| ProxyConnect::Source(error).into())
            } else {
                conn
            }
        })
    }
}
