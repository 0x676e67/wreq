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
use bytes::{BufMut, Bytes, BytesMut};

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
    const _HTTP1: [u8; 8] = *b"http/1.1";
    const _HTTP2: [u8; 2] = *b"h2";
    const _HTTP3: [u8; 2] = *b"h3";

    /// Prefer HTTP/1.1
    pub const HTTP1: AlpnProtocol = AlpnProtocol(&AlpnProtocol::_HTTP1);

    /// Prefer HTTP/2
    pub const HTTP2: AlpnProtocol = AlpnProtocol(&AlpnProtocol::_HTTP2);

    /// Prefer HTTP/3
    pub const HTTP3: AlpnProtocol = AlpnProtocol(&AlpnProtocol::_HTTP3);
}

impl AlpnProtocol {
    pub(crate) fn encode(alpns: &[Self]) -> Bytes {
        let total_len: usize = alpns.iter().map(|alpn| alpn.0.len() + 1).sum();
        let mut buf = BytesMut::with_capacity(total_len);

        for alpn in alpns {
            let b = alpn.0;
            buf.put_u8(b.len() as u8);
            buf.extend_from_slice(b);
        }

        buf.freeze()
    }
}

impl Default for AlpnProtocol {
    fn default() -> Self {
        const DEFAULT: [u8; 12] = concat_array!(
            [AlpnProtocol::_HTTP2.len() as u8],
            AlpnProtocol::_HTTP2,
            [AlpnProtocol::_HTTP1.len() as u8],
            AlpnProtocol::_HTTP1
        );
        AlpnProtocol(&DEFAULT)
    }
}

impl From<AlpnProtocol> for Bytes {
    #[inline(always)]
    fn from(alpn: AlpnProtocol) -> Self {
        Bytes::from_static(alpn.0)
    }
}

/// Application-layer protocol settings for HTTP/1.1 and HTTP/2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationProtocol(&'static [u8]);

impl ApplicationProtocol {
    /// Application Settings protocol for HTTP/1.1
    pub const HTTP1: ApplicationProtocol = ApplicationProtocol(b"http/1.1");

    /// Application Settings protocol for HTTP/2
    pub const HTTP2: ApplicationProtocol = ApplicationProtocol(b"h2");

    /// Application Settings protocol for HTTP/3
    pub const HTTP3: ApplicationProtocol = ApplicationProtocol(b"h3");
}

/// IANA assigned identifier of compression algorithm.
/// See https://www.rfc-editor.org/rfc/rfc8879.html#name-compression-algorithms
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
