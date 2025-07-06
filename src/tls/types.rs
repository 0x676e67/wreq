use bytes::{Bytes, BytesMut};

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct TlsVersion(pub(super) boring2::ssl::SslVersion);

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
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
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
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
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

/// A TLS extension type.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct ExtensionType(pub(super) boring2::ssl::ExtensionType);

impl ExtensionType {
    /// Server Name Indication extension.
    pub const SERVER_NAME: ExtensionType = ExtensionType(boring2::ssl::ExtensionType::SERVER_NAME);

    /// Certificate Status Request extension.
    pub const STATUS_REQUEST: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::STATUS_REQUEST);

    /// EC Point Formats extension.
    pub const EC_POINT_FORMATS: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::EC_POINT_FORMATS);

    /// Signature Algorithms extension.
    pub const SIGNATURE_ALGORITHMS: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::SIGNATURE_ALGORITHMS);

    /// SRTP extension.
    pub const SRTP: ExtensionType = ExtensionType(boring2::ssl::ExtensionType::SRTP);

    /// Application Layer Protocol Negotiation extension.
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION);

    /// Padding extension.
    pub const PADDING: ExtensionType = ExtensionType(boring2::ssl::ExtensionType::PADDING);

    /// Extended Master Secret extension.
    pub const EXTENDED_MASTER_SECRET: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::EXTENDED_MASTER_SECRET);

    /// QUIC Transport Parameters (legacy) extension.
    pub const QUIC_TRANSPORT_PARAMETERS_LEGACY: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::QUIC_TRANSPORT_PARAMETERS_LEGACY);

    /// QUIC Transport Parameters (standard) extension.
    pub const QUIC_TRANSPORT_PARAMETERS_STANDARD: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::QUIC_TRANSPORT_PARAMETERS_STANDARD);

    /// Certificate Compression extension.
    pub const CERT_COMPRESSION: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::CERT_COMPRESSION);

    /// Session Ticket extension.
    pub const SESSION_TICKET: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::SESSION_TICKET);

    /// Supported Groups extension.
    pub const SUPPORTED_GROUPS: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::SUPPORTED_GROUPS);

    /// Pre-Shared Key extension.
    pub const PRE_SHARED_KEY: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::PRE_SHARED_KEY);

    /// Early Data extension.
    pub const EARLY_DATA: ExtensionType = ExtensionType(boring2::ssl::ExtensionType::EARLY_DATA);

    /// Supported Versions extension.
    pub const SUPPORTED_VERSIONS: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::SUPPORTED_VERSIONS);

    /// Cookie extension.
    pub const COOKIE: ExtensionType = ExtensionType(boring2::ssl::ExtensionType::COOKIE);

    /// PSK Key Exchange Modes extension.
    pub const PSK_KEY_EXCHANGE_MODES: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::PSK_KEY_EXCHANGE_MODES);

    /// Certificate Authorities extension.
    pub const CERTIFICATE_AUTHORITIES: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::CERTIFICATE_AUTHORITIES);

    /// Signature Algorithms Certificate extension.
    pub const SIGNATURE_ALGORITHMS_CERT: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::SIGNATURE_ALGORITHMS_CERT);

    /// Key Share extension.
    pub const KEY_SHARE: ExtensionType = ExtensionType(boring2::ssl::ExtensionType::KEY_SHARE);

    /// Renegotiation extension.
    pub const RENEGOTIATE: ExtensionType = ExtensionType(boring2::ssl::ExtensionType::RENEGOTIATE);

    /// Delegated Credential extension.
    pub const DELEGATED_CREDENTIAL: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::DELEGATED_CREDENTIAL);

    /// Application Settings extension.
    pub const APPLICATION_SETTINGS: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::APPLICATION_SETTINGS);

    /// Application Settings New extension.
    pub const APPLICATION_SETTINGS_NEW: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::APPLICATION_SETTINGS_NEW);

    /// Encrypted Client Hello extension.
    pub const ENCRYPTED_CLIENT_HELLO: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::ENCRYPTED_CLIENT_HELLO);

    /// Certificate Timestamp extension.
    pub const CERTIFICATE_TIMESTAMP: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::CERTIFICATE_TIMESTAMP);

    /// Next Protocol Negotiation extension.
    pub const NEXT_PROTO_NEG: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::NEXT_PROTO_NEG);

    /// Channel ID extension.
    pub const CHANNEL_ID: ExtensionType = ExtensionType(boring2::ssl::ExtensionType::CHANNEL_ID);

    /// Record Size Limit extension.
    pub const RECORD_SIZE_LIMIT: ExtensionType =
        ExtensionType(boring2::ssl::ExtensionType::RECORD_SIZE_LIMIT);
}

impl From<u16> for ExtensionType {
    fn from(value: u16) -> Self {
        ExtensionType(boring2::ssl::ExtensionType::from(value))
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
