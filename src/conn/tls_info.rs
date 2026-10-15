use btls::ssl::SslRef;
use bytes::Bytes;

use crate::tls::{TlsInfo, conn::MaybeHttpsStream};

/// A trait for extracting TLS information from a connection.
pub trait TlsInfoFactory {
    /// Returns the TLS session securing this connection, if any.
    #[inline]
    fn ssl(&self) -> Option<&SslRef> {
        None
    }

    fn tls_info(&self) -> Option<TlsInfo> {
        let ssl = self.ssl()?;
        Some(TlsInfo {
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
        })
    }
}

// Generic impl: MaybeHttpsStream reports only its own TLS layer.
impl<T> TlsInfoFactory for MaybeHttpsStream<T> {
    #[inline]
    fn ssl(&self) -> Option<&SslRef> {
        match self {
            MaybeHttpsStream::Https(tls) => Some(tls.ssl()),
            MaybeHttpsStream::Http(_) => None,
        }
    }
}
