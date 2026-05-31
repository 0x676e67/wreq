use std::{io, net::SocketAddr};

use bytes::Bytes;
use tokio_btls::SslStream;

use crate::{
    conn::{Connected, Connection, http::HttpInfo},
    tls::{TlsInfo, conn::MaybeHttpsStream},
};

/// A trait for extracting connection information such as peer and local addresses.
pub trait ConnectionInfo {
    /// Returns the remote address that this stream is connected to.
    fn peer_addr(&self) -> Option<SocketAddr>;

    /// Returns the local address that this stream is bound to.
    fn local_addr(&self) -> Option<SocketAddr>;

    /// Set the value of the `TCP_NODELAY` option on the underlying TCP stream.
    /// For non-TCP streams (e.g. Unix sockets) the default implementation is a no-op.
    fn set_nodelay(&self, _nodelay: bool) -> io::Result<()>;
}

/// A trait for extracting TLS information from a connection.
pub trait TlsInfoFactory {
    #[inline]
    fn tls_info(&self) -> Option<TlsInfo> {
        None
    }
}

// ===== impl ConnectionInfo =====

impl<T> Connection for T
where
    T: ConnectionInfo,
{
    #[inline]
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        match (self.peer_addr(), self.local_addr()) {
            (Some(remote_addr), Some(local_addr)) => connected.extra(HttpInfo {
                remote_addr,
                local_addr,
            }),
            _ => connected,
        }
    }
}

impl<T: ConnectionInfo + ?Sized> ConnectionInfo for Box<T> {
    #[inline(always)]
    fn peer_addr(&self) -> Option<SocketAddr> {
        (**self).peer_addr()
    }

    #[inline(always)]
    fn local_addr(&self) -> Option<SocketAddr> {
        (**self).local_addr()
    }

    #[inline(always)]
    fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        (**self).set_nodelay(nodelay)
    }
}

impl<T> TlsInfoFactory for T where T: ConnectionInfo {}

// ===== impl TlsInfoFactory =====

fn extract_tls_info<S>(ssl_stream: &SslStream<S>) -> TlsInfo {
    let ssl = ssl_stream.ssl();
    TlsInfo {
        peer_certificate: ssl
            .peer_certificate()
            .and_then(|cert| cert.to_der().ok())
            .map(Bytes::from),
        peer_certificate_chain: ssl.peer_cert_chain().map(|chain| {
            chain
                .iter()
                .filter_map(|cert| cert.to_der().ok())
                .map(Bytes::from)
                .collect()
        }),
    }
}

// Generic impl: any SslStream can provide TLS info.
impl<T> TlsInfoFactory for SslStream<T> {
    #[inline(always)]
    fn tls_info(&self) -> Option<TlsInfo> {
        Some(extract_tls_info(self))
    }
}

// Generic impl: MaybeHttpsStream delegates to the inner stream.
impl<T: TlsInfoFactory> TlsInfoFactory for MaybeHttpsStream<T> {
    fn tls_info(&self) -> Option<TlsInfo> {
        match self {
            MaybeHttpsStream::Https(tls) => tls.tls_info(),
            MaybeHttpsStream::Http(_) => None,
        }
    }
}
