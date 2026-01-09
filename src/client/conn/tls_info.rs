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

/// Extract TLS metadata from an SSL connection.
fn extract_tls_info<S>(ssl_stream: &SslStream<S>) -> Option<TlsInfo> {
    let ssl = ssl_stream.ssl();

    // Return None if no leaf certificate (maintains backward compatibility)
    let leaf_cert = ssl.peer_certificate()?;
    let peer_certificate = leaf_cert.to_der().ok();

    // Build full chain: leaf first, then intermediates
    let peer_certificate_chain = {
        let mut chain = Vec::new();

        // Add leaf certificate first
        if let Some(leaf_der) = &peer_certificate {
            chain.push(leaf_der.clone());
        }

        // Add intermediate certificates
        if let Some(intermediates) = ssl.peer_cert_chain() {
            chain.extend(intermediates.iter().filter_map(|c| c.to_der().ok()));
        }

        if chain.is_empty() { None } else { Some(chain) }
    };

    Some(TlsInfo {
        peer_certificate,
        peer_certificate_chain,
    })
}

// ===== impl TcpStream =====

impl TlsInfoFactory for TcpStream {
    fn tls_info(&self) -> Option<TlsInfo> {
        None
    }
}

impl TlsInfoFactory for SslStream<TcpStream> {
    fn tls_info(&self) -> Option<TlsInfo> {
        extract_tls_info(self)
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
        extract_tls_info(self)
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
        extract_tls_info(self)
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
        extract_tls_info(self)
    }
}
