use tokio::net::TcpStream;
use tokio_boring2::SslStream;

use crate::{
    core::rt::TokioIo,
    tls::{MaybeHttpsStream, TlsInfo},
};

/// A trait for extracting TLS information from a connection.
///
/// Implementors can provide access to peer certificate data or other TLS-related metadata.
/// For non-TLS connections, this typically returns `None`.
pub trait TlsInfoFactory {
    fn tls_info(&self) -> Option<TlsInfo>;
}

impl TlsInfoFactory for TcpStream {
    fn tls_info(&self) -> Option<TlsInfo> {
        None
    }
}

impl<T: TlsInfoFactory> TlsInfoFactory for TokioIo<T> {
    fn tls_info(&self) -> Option<TlsInfo> {
        self.inner().tls_info()
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

impl TlsInfoFactory for SslStream<TokioIo<MaybeHttpsStream<TcpStream>>> {
    fn tls_info(&self) -> Option<TlsInfo> {
        self.ssl().peer_certificate().map(|c| TlsInfo {
            peer_certificate: c.to_der().ok(),
        })
    }
}
