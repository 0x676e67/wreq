use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio_boring2::SslStream;

use crate::tls::{TlsInfo, conn::MaybeHttpsStream};

/// A trait for extracting TLS information from a connection.
///
/// Implementors can provide access to peer certificate data or other TLS-related metadata.
/// For non-TLS connections, this typically returns `None`.
pub trait TlsInfoFactory {
    fn tls_info(&self) -> Option<TlsInfo>;
}

// ===== impl TcpStream =====

impl TlsInfoFactory for TcpStream {
    fn tls_info(&self) -> Option<TlsInfo> {
        None
    }
}

impl TlsInfoFactory for SslStream<TcpStream> {
    fn tls_info(&self) -> Option<TlsInfo> {
        self.ssl().peer_certificate().map(|c| TlsInfo {
            peer_certificate: c.to_der().ok(),
        })
    }
}

impl TlsInfoFactory for MaybeHttpsStream<TcpStream> {
    fn tls_info(&self) -> Option<TlsInfo> {
        match self {
            MaybeHttpsStream::Https(tls) => tls.tls_info(),
            MaybeHttpsStream::Http(_) => None,
        }
    }
}

impl TlsInfoFactory for SslStream<MaybeHttpsStream<TcpStream>> {
    fn tls_info(&self) -> Option<TlsInfo> {
        self.ssl().peer_certificate().map(|c| TlsInfo {
            peer_certificate: c.to_der().ok(),
        })
    }
}

// ===== impl UnixStream =====

#[cfg(unix)]
impl TlsInfoFactory for UnixStream {
    fn tls_info(&self) -> Option<TlsInfo> {
        None
    }
}

#[cfg(unix)]
impl TlsInfoFactory for SslStream<UnixStream> {
    fn tls_info(&self) -> Option<TlsInfo> {
        self.ssl().peer_certificate().map(|c| TlsInfo {
            peer_certificate: c.to_der().ok(),
        })
    }
}

#[cfg(unix)]
impl TlsInfoFactory for MaybeHttpsStream<UnixStream> {
    fn tls_info(&self) -> Option<TlsInfo> {
        match self {
            MaybeHttpsStream::Https(tls) => tls.tls_info(),
            MaybeHttpsStream::Http(_) => None,
        }
    }
}

#[cfg(unix)]
impl TlsInfoFactory for SslStream<MaybeHttpsStream<UnixStream>> {
    fn tls_info(&self) -> Option<TlsInfo> {
        self.ssl().peer_certificate().map(|c| TlsInfo {
            peer_certificate: c.to_der().ok(),
        })
    }
}
