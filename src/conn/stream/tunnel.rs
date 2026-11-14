//! HTTP CONNECT over a TCP or Unix proxy socket.

use http::Uri;
use netty::proxy::tunnel::{TunnelConnector, TunnelError};
use tower::{BoxError, ServiceExt, service_fn};

use crate::{
    conn::{
        dialer::{Dialer, SocketRequest},
        request::ConnectRequest,
    },
    proxy::matcher::Intercept,
    rt::{BoxConnection, Connection},
    tls::connector::{MaybeHttpsStream, TlsConnector},
};

// The Unix path selects the socket. This URI marks the hop as plain HTTP.
const UNIX_PROXY_URI: &str = "http://localhost";

/// Opens a [CONNECT tunnel] to the request's origin.
///
/// The dial request addresses the proxy. An HTTPS proxy uses the request's TLS
/// context with ALPN disabled so this hop can send HTTP/1.1 CONNECT.
///
/// [CONNECT tunnel]: https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6
pub(super) async fn connect(
    dialer: &Dialer,
    tls: &TlsConnector,
    request: &ConnectRequest,
    proxy: Option<&Intercept>,
    socket_request: impl Fn(Uri) -> SocketRequest + Send,
) -> Result<MaybeHttpsStream<BoxConnection>, TunnelError> {
    let target = request.uri().clone();
    let proxy_uri = proxy.map_or_else(|| Uri::from_static(UNIX_PROXY_URI), |p| p.uri().clone());
    // netty validates the CONNECT target before asking this service to dial the proxy.
    let hop = service_fn(move |proxy: Uri| {
        let socket_request = socket_request(proxy.clone());
        let mut tls = tls.clone();
        tls.no_alpn();
        dial_proxy(dialer.clone(), socket_request, tls, request.clone(), proxy)
    });
    let mut tunnel = TunnelConnector::new(proxy_uri, hop);
    if let Some(proxy) = proxy {
        if let Some(auth) = proxy.basic_auth() {
            tunnel = tunnel.with_auth(auth.clone());
        }
        if let Some(headers) = proxy.custom_headers() {
            tunnel = tunnel.with_headers(headers.clone());
        }
    }
    tunnel.oneshot(target).await
}

// The returned future owns the hop state because netty can drop the dial service after calling it.
async fn dial_proxy(
    dialer: Dialer,
    socket_request: SocketRequest,
    tls: TlsConnector,
    request: ConnectRequest,
    proxy: Uri,
) -> Result<MaybeHttpsStream<BoxConnection>, BoxError> {
    let io = dialer.dial(socket_request).await?;
    let remote_ip = io.peer_addr().map(|addr| addr.ip());
    tls.handshake(io, &request, &proxy, remote_ip).await
}
