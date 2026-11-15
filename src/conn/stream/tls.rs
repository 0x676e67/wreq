//! Final TLS handshake and connection metadata.

use tower::BoxError;

use crate::{
    conn::{
        Conn, Connected, HttpInfo, Io, Transport, connected::tls_info, request::ConnectRequest,
    },
    proxy::matcher::Intercept,
    rt::Connection,
    tls::{
        AlpnProtocol,
        connector::{MaybeHttpsStream, TlsConnector},
    },
};

/// Finishes TLS and records the negotiated HTTP version and peer certificates.
///
/// TLS addresses the origin except when forwarding, where it addresses the proxy.
/// Socket metadata always describes the underlying hop, even through a tunnel.
pub(super) async fn finish(
    io: impl Connection,
    request: ConnectRequest,
    tls: TlsConnector,
    reset_nodelay: bool,
    proxy: Option<Intercept>,
) -> Result<Conn, BoxError> {
    let (local_addr, remote_addr) = (io.local_addr(), io.peer_addr());
    let tls_peer = proxy.as_ref().map_or(request.uri(), Intercept::uri);
    let stream = tls
        .handshake(io, &request, tls_peer, remote_addr.map(|addr| addr.ip()))
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
            if reset_nodelay {
                // Keep TCP_NODELAY on until the last TLS handshake on the socket completes.
                stream.get_ref().set_nodelay(false)?;
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
