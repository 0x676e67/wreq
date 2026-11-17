//! HTTP CONNECT over a TCP or Unix proxy socket.

use std::future::Future;

use http::{Request, Uri};
use netty::proxy::tunnel::{TunnelConnector, TunnelError};
use tower::{ServiceExt, service_fn};

use crate::{
    config::connect::ConnectConfig,
    conn::{
        ConnectRequestExt,
        dialer::{Dial, Dialer},
    },
    ext::UriExt,
    proxy::Intercepted,
    rt::{BoxConnection, Connection},
    tls::connector::{MaybeHttpsStream, TlsConnector},
};

// The Unix path selects the socket. This URI marks the hop as plain HTTP.
#[cfg(unix)]
const UNIX_PROXY_URI: &str = "http://localhost";

/// Opens a [CONNECT tunnel] to the request's origin.
///
/// The dial request addresses the proxy. An HTTPS proxy uses the request's TLS
/// context with ALPN disabled so this hop can send HTTP/1.1 CONNECT.
///
/// [CONNECT tunnel]: https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6
pub(super) fn connect(
    dialer: Dialer,
    tls: &TlsConnector,
    request: &Request<ConnectConfig>,
    route: &Intercepted,
) -> impl Future<Output = Result<MaybeHttpsStream<BoxConnection>, TunnelError>> + Send {
    let target = request.uri().clone();
    let deadline = request.deadline();
    let config = request.body().clone();
    let (proxy_uri, proxy) = match route {
        Intercepted::Proxy(proxy) => (proxy.uri().clone(), Some(proxy)),
        #[cfg(unix)]
        Intercepted::Unix(_) => (Uri::from_static(UNIX_PROXY_URI), None),
    };
    // netty validates the CONNECT target before asking this service to dial the proxy.
    let hop = service_fn(move |uri: Uri| {
        let dialer = dialer.clone();
        let dial = match route {
            Intercepted::Proxy(_) => Dial::Tcp {
                uri: uri.clone(),
                config: config.clone(),
                deadline,
                nodelay: true,
            },
            #[cfg(unix)]
            Intercepted::Unix(path) => Dial::Unix(path.clone()),
        };
        // netty requires a future that owns its inputs. Keep only the TLS options
        // and the origin used to scope tickets for this handshake.
        let tls = (!uri.is_http()).then(|| {
            let mut tls = tls.clone();
            tls.no_alpn();
            (
                tls,
                request.uri().clone(),
                request.protocol(),
                request.body().clone(),
            )
        });
        async move {
            let io = dialer.oneshot(dial).await?;
            let Some((tls, origin, protocol, config)) = tls else {
                return Ok(MaybeHttpsStream::Http(io));
            };
            let remote_ip = io.peer_addr().map(|addr| addr.ip());
            tls.handshake(io, &origin, protocol, &config, &uri, remote_ip)
                .await
                .map(MaybeHttpsStream::Https)
        }
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
    tunnel.oneshot(target)
}
