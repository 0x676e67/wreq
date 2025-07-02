//! TLS configuration
//!
//! By default, a `Client` will make use of BoringSSL for TLS.
//!
//! - Various parts of TLS can also be configured or even disabled on the `ClientBuilder`.

#[macro_use]
mod macros;
mod config;
mod conn;
mod keylog;
mod x509;

pub use boring2::ssl::ExtensionType;
use bytes::{Bytes, BytesMut};

pub(crate) use self::conn::{HttpsConnector, MaybeHttpsStream, TlsConnector, TlsConnectorBuilder};
pub use self::{
    config::TlsConfig,
    keylog::KeyLogPolicy,
    x509::{CertStore, CertStoreBuilder, Certificate, CertificateInput, Identity},
};

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsVersion(boring2::ssl::SslVersion);

impl TlsVersion {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: TlsVersion = TlsVersion(boring2::ssl::SslVersion::TLS1);

    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: TlsVersion = TlsVersion(boring2::ssl::SslVersion::TLS1_1);

    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: TlsVersion = TlsVersion(boring2::ssl::SslVersion::TLS1_2);

    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: TlsVersion = TlsVersion(boring2::ssl::SslVersion::TLS1_3);
}

/// A TLS ALPN protocol.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct AlpnProtocol(&'static [u8]);

impl AlpnProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpnProtocol = AlpnProtocol(b"\x08http/1.1");

    /// Prefer HTTP/2
    pub const HTTP2: AlpnProtocol = AlpnProtocol(b"\x02h2");

    /// Prefer HTTP/3
    pub const HTTP3: AlpnProtocol = AlpnProtocol(b"\x02h3");

    #[inline]
    pub(crate) fn encode(self) -> Bytes {
        Bytes::from_static(self.0)
    }

    #[inline]
    pub(crate) fn encode_sequence<'a, I>(items: I) -> Bytes
    where
        I: IntoIterator<Item = &'a AlpnProtocol>,
    {
        encode_sequence(items)
    }
}

impl AsRef<[u8]> for AlpnProtocol {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

/// Application-layer protocol settings for HTTP/1.1 and HTTP/2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlpsProtocol(&'static [u8]);

impl AlpsProtocol {
    /// Application Settings protocol for HTTP/1.1
    pub const HTTP1: AlpsProtocol = AlpsProtocol(b"http/1.1");

    /// Application Settings protocol for HTTP/2
    pub const HTTP2: AlpsProtocol = AlpsProtocol(b"h2");

    /// Application Settings protocol for HTTP/3
    pub const HTTP3: AlpsProtocol = AlpsProtocol(b"h3");

    #[inline]
    pub(crate) fn encode_sequence<'a, I>(items: I) -> Bytes
    where
        I: IntoIterator<Item = &'a AlpsProtocol>,
    {
        encode_sequence(items)
    }
}

impl AsRef<[u8]> for AlpsProtocol {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

/// IANA assigned identifier of compression algorithm.
/// See <https://www.rfc-editor.org/rfc/rfc8879.html#name-compression-algorithms>
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CertificateCompressionAlgorithm(boring2::ssl::CertificateCompressionAlgorithm);

impl CertificateCompressionAlgorithm {
    /// Zlib compression algorithm.
    pub const ZLIB: CertificateCompressionAlgorithm =
        CertificateCompressionAlgorithm(boring2::ssl::CertificateCompressionAlgorithm::ZLIB);

    /// Brotli compression algorithm.
    pub const BROTLI: CertificateCompressionAlgorithm =
        CertificateCompressionAlgorithm(boring2::ssl::CertificateCompressionAlgorithm::BROTLI);

    /// Zstd compression algorithm.
    pub const ZSTD: CertificateCompressionAlgorithm =
        CertificateCompressionAlgorithm(boring2::ssl::CertificateCompressionAlgorithm::ZSTD);
}

/// Hyper extension carrying extra TLS layer information.
/// Made available to clients on responses when `tls_info` is set.
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub(crate) peer_certificate: Option<Vec<u8>>,
}

impl TlsInfo {
    /// Get the DER encoded leaf certificate of the peer.
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_ref().map(|der| &der[..])
    }
}

fn encode_sequence<'a, T, I>(items: I) -> Bytes
where
    T: AsRef<[u8]> + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut buf = BytesMut::new();
    for item in items {
        buf.extend_from_slice(item.as_ref());
    }
    buf.freeze()
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
