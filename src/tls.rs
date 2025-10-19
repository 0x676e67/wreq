//!  TLS options configuration
//!
//! By default, a `Client` will make use of BoringSSL for TLS.
//!
//! - Various parts of TLS can also be configured or even disabled on the `ClientBuilder`.

pub(crate) mod conn;
mod keylog;
mod options;
mod x509;

pub use boring2::ssl::{CertificateCompressionAlgorithm, ExtensionType};

pub use self::{
    keylog::KeyLog,
    options::{TlsOptions, TlsOptionsBuilder},
    x509::{CertStore, CertStoreBuilder, Certificate, Identity},
};

/// Http extension carrying extra TLS layer information.
/// Made available to clients on responses when `tls_info` is set.
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub(crate) peer_certificate: Option<Vec<u8>>,
}

impl TlsInfo {
    /// Get the DER encoded leaf certificate of the peer.
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_deref()
    }
}

use boring2::ssl;
use bytes::{BufMut, Bytes, BytesMut};

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct TlsVersion(ssl::SslVersion);

impl TlsVersion {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: TlsVersion = TlsVersion(ssl::SslVersion::TLS1);

    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: TlsVersion = TlsVersion(ssl::SslVersion::TLS1_1);

    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: TlsVersion = TlsVersion(ssl::SslVersion::TLS1_2);

    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: TlsVersion = TlsVersion(ssl::SslVersion::TLS1_3);
}

/// A TLS ALPN protocol.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct AlpnProtocol(&'static [u8]);

impl AlpnProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpnProtocol = AlpnProtocol(b"http/1.1");

    /// Prefer HTTP/2
    pub const HTTP2: AlpnProtocol = AlpnProtocol(b"h2");

    /// Prefer HTTP/3
    pub const HTTP3: AlpnProtocol = AlpnProtocol(b"h3");

    /// Create a new [`AlpnProtocol`] from a static byte slice.
    #[inline]
    pub const fn new(value: &'static [u8]) -> Self {
        AlpnProtocol(value)
    }

    #[inline]
    fn encode(self) -> Bytes {
        Self::encode_sequence(std::iter::once(&self))
    }

    fn encode_sequence<'a, I>(items: I) -> Bytes
    where
        I: IntoIterator<Item = &'a AlpnProtocol>,
    {
        let mut buf = BytesMut::new();
        for item in items {
            buf.put_u8(item.0.len() as u8);
            buf.extend_from_slice(item.0);
        }
        buf.freeze()
    }
}

/// A TLS ALPS protocol.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct AlpsProtocol(&'static [u8]);

impl AlpsProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpsProtocol = AlpsProtocol(b"http/1.1");

    /// Prefer HTTP/2
    pub const HTTP2: AlpsProtocol = AlpsProtocol(b"h2");

    /// Prefer HTTP/3
    pub const HTTP3: AlpsProtocol = AlpsProtocol(b"h3");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_protocol_encode() {
        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP1, AlpnProtocol::HTTP2]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h2"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP1, AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP3]);
        assert_eq!(alpn, Bytes::from_static(b"\x02h2\x02h3"));

        let alpn = AlpnProtocol::encode_sequence(&[
            AlpnProtocol::HTTP1,
            AlpnProtocol::HTTP2,
            AlpnProtocol::HTTP3,
        ]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h2\x02h3"));
    }

    #[test]
    fn alpn_protocol_encode_single() {
        let alpn = AlpnProtocol::HTTP1.encode();
        assert_eq!(alpn, b"\x08http/1.1".as_ref());

        let alpn = AlpnProtocol::HTTP2.encode();
        assert_eq!(alpn, b"\x02h2".as_ref());

        let alpn = AlpnProtocol::HTTP3.encode();
        assert_eq!(alpn, b"\x02h3".as_ref());
    }
}
