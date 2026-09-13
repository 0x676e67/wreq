//!  TLS options configuration
//!
//! - Various parts of TLS can also be configured or even disabled on the `ClientBuilder`.

pub(super) mod conn;

pub mod compress;
pub mod keylog;
pub mod session;
pub mod trust;

use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
};

/// Re-exports of TLS-related types from `btls` for public use.
pub use btls::ssl::{ExtensionType, KeyShare};
use bytes::{BufMut, Bytes, BytesMut};
use compress::CertificateCompressor;
use educe::Educe;

/// Http extension carrying extra TLS layer information.
/// Made available to clients on responses when `tls_info` is set.
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub(crate) peer_certificate: Option<Bytes>,
    pub(crate) peer_certificate_chain: Option<Vec<Bytes>>,
}

impl TlsInfo {
    /// Get the DER encoded leaf certificate of the peer.
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_deref()
    }

    /// Get the DER encoded certificate chain of the peer.
    ///
    /// This includes the leaf certificate on the client side.
    pub fn peer_certificate_chain(&self) -> Option<impl Iterator<Item = &[u8]>> {
        self.peer_certificate_chain
            .as_ref()
            .map(|v| v.iter().map(|b| b.as_ref()))
    }
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct TlsVersion(btls::ssl::SslVersion);

impl TlsVersion {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1);

    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1_1);

    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1_2);

    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: TlsVersion = TlsVersion(btls::ssl::SslVersion::TLS1_3);
}

/// An application protocol identifier for TLS ALPN negotiation.
/// Lists of these identifiers define the offer and its preference order.
/// Identifiers borrow static bytes and can be reused across TLS configurations.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct AlpnProtocol(&'static [u8]);

impl AlpnProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpnProtocol = AlpnProtocol(b"http/1.1");

    /// Prefer HTTP/2
    pub const HTTP2: AlpnProtocol = AlpnProtocol(b"h2");

    /// Prefer HTTP/3
    pub const HTTP3: AlpnProtocol = AlpnProtocol(b"h3");

    fn encode_sequence(items: &[AlpnProtocol]) -> Bytes {
        // RFC 7301 section 3.1 uses length-prefixed identifiers in preference order.
        // https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1
        let mut buf = BytesMut::new();
        for item in items {
            buf.put_u8(item.0.len() as u8);
            buf.extend_from_slice(item.0);
        }
        buf.freeze()
    }
}

impl PartialEq<[u8]> for AlpnProtocol {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
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

impl PartialEq<[u8]> for AlpsProtocol {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

/// Builder for `[`TlsOptions`]`.
#[must_use]
#[derive(Debug, Clone)]
pub struct TlsOptionsBuilder {
    config: TlsOptions,
}

/// TLS connection configuration options.
///
/// This struct provides fine-grained control over the behavior of TLS
/// connections, including:
/// - **Protocol negotiation** (ALPN, ALPS, TLS versions)
/// - **Session management** (tickets, PSK, key shares)
/// - **Security & privacy** (OCSP, GREASE, ECH, delegated credentials)
/// - **Performance tuning** (record size, cipher preferences, hardware overrides)
///
/// All fields are optional or have defaults. See each field for details.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Educe)]
#[educe(PartialEq, Eq, Hash)]
pub struct TlsOptions {
    /// Protocols offered through ALPN, in preference order ([RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301)).
    ///
    /// Fixed HTTP version requirements override this list. `None` and empty lists inherit
    /// the client's offer, which defaults to HTTP/2 then HTTP/1.1 in automatic mode.
    ///
    /// **Default:** `None` (inherits the client's offer).
    pub alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,

    /// Protocols that exchange application-layer settings through ALPS during the handshake.
    ///
    /// **Default:** `None`.
    pub alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,

    /// Selects the new ALPS codepoint when ALPS protocols are configured.
    ///
    /// **Default:** `false`.
    pub alps_use_new_codepoint: bool,

    /// Controls TLS session tickets ([RFC 5077](https://tools.ietf.org/html/rfc5077)).
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub session_ticket: Option<bool>,

    /// Minimum TLS version allowed for the connection.
    ///
    /// **Default:** `None` (inherits the client's minimum TLS version).
    pub min_tls_version: Option<TlsVersion>,

    /// Maximum TLS version allowed for the connection.
    ///
    /// **Default:** `None` (inherits the client's maximum TLS version).
    pub max_tls_version: Option<TlsVersion>,

    /// Controls PSK with (EC)DHE key establishment (`psk_dhe_ke`).
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub psk_dhe_ke: Option<bool>,

    /// Skips session tickets when a cached session is selected for resumption.
    ///
    /// **Default:** `false`.
    pub psk_skip_session_ticket: bool,

    /// Enables ticket-based resumption and the TLS 1.3 `pre_shared_key` extension.
    ///
    /// Uses a previously established session, not out-of-band PSKs.
    /// See [RFC 8446 section 4.2.11](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11).
    ///
    /// **Default:** `false`.
    pub pre_shared_key: bool,

    /// Controls GREASE ECH when no supported ECH configuration is available.
    /// `Some(true)` enables it; `Some(false)` disables it.
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub enable_ech_grease: Option<bool>,

    /// Controls permutation of ClientHello extensions.
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub permute_extensions: Option<bool>,

    /// Controls TLS GREASE ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701)).
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub grease_enabled: Option<bool>,

    /// Controls whether the ClientHello `signature_algorithms` extension includes a
    /// GREASE value ([RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html)).
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub grease_sigalgs_enabled: Option<bool>,

    /// Enables OCSP stapling for the connection.
    ///
    /// **Default:** `false`.
    pub enable_ocsp_stapling: bool,

    /// Enables Signed Certificate Timestamps (SCT).
    ///
    /// **Default:** `false`.
    pub enable_signed_cert_timestamps: bool,

    /// Maximum TLS record size.
    ///
    /// **Default:** `None`.
    pub record_size_limit: Option<u16>,

    /// Key shares offered in TLS 1.3 handshakes.
    ///
    /// **Default:** `None`.
    pub key_shares: Option<Cow<'static, [KeyShare]>>,

    /// Encoded Trust Anchor IDs sent in a TLS 1.3 [`ClientHello`].
    ///
    /// Each ID must be non-empty and have a one-byte length prefix; omit the list's outer two-byte
    /// length. IDs only guide server certificate selection and must identify roots accepted by the
    /// configured certificate store, or certificate verification may fail.
    ///
    /// `Some(&[])` sends an empty [`trust_anchors` extension]; `None` omits it. Invalid encoding
    /// fails TLS setup, and wreq does not implement the specification's retry mechanism.
    ///
    /// **Default:** `None`.
    ///
    /// [`ClientHello`]: https://www.rfc-editor.org/rfc/rfc9846.html#section-4.2.2
    /// [`trust_anchors` extension]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-trust-anchor-ids-04#section-4.1
    pub trust_anchors: Option<Cow<'static, [u8]>>,

    /// Controls TLS renegotiation.
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub renegotiation: Option<bool>,

    /// Signature algorithms for delegated credentials ([RFC 9345](https://datatracker.ietf.org/doc/html/rfc9345)).
    ///
    /// **Default:** `None`.
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// List of supported elliptic curves.
    ///
    /// **Default:** `None`.
    pub curves_list: Option<Cow<'static, str>>,

    /// List of supported signature algorithms.
    ///
    /// **Default:** `None`.
    pub sigalgs_list: Option<Cow<'static, str>>,

    /// Cipher suite selection and ordering in BoringSSL's cipher-list syntax.
    ///
    /// **Default:** `None`.
    pub cipher_list: Option<Cow<'static, str>>,

    /// Controls whether to preserve the TLS 1.3 cipher list configured by [`Self::cipher_list`].
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub preserve_tls13_cipher_list: Option<bool>,

    /// Supported certificate compression algorithms ([RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879)).
    ///
    /// **Default:** `None`.
    #[educe(
        PartialEq(method(certificate_compressors_eq)),
        Hash(method(hash_certificate_compressors))
    )]
    pub certificate_compressors: Option<Cow<'static, [&'static dyn CertificateCompressor]>>,

    /// TLS extension order used for permutation.
    ///
    /// **Default:** `None`.
    pub extension_permutation: Option<Cow<'static, [ExtensionType]>>,

    /// Overrides AES hardware acceleration.
    ///
    /// **Default:** `None` (backend policy unchanged).
    pub aes_hw_override: Option<bool>,

    /// Randomizes the AES hardware acceleration override for each connection.
    ///
    /// **Default:** `false`.
    pub random_aes_hw_override: bool,
}

fn certificate_compressors_eq(
    left: &Option<Cow<'static, [&'static dyn CertificateCompressor]>>,
    right: &Option<Cow<'static, [&'static dyn CertificateCompressor]>>,
) -> bool {
    left.as_deref()
        .into_iter()
        .flatten()
        .map(|compressor| compressor.algorithm())
        .eq(right
            .as_deref()
            .into_iter()
            .flatten()
            .map(|compressor| compressor.algorithm()))
}

fn hash_certificate_compressors<H: Hasher>(
    compressors: &Option<Cow<'static, [&'static dyn CertificateCompressor]>>,
    state: &mut H,
) {
    let compressors = compressors.as_deref();
    compressors.map_or(0, <[_]>::len).hash(state);
    for compressor in compressors.into_iter().flatten() {
        compressor.algorithm().hash(state);
    }
}

impl TlsOptionsBuilder {
    /// Sets the ALPN protocols to use.
    #[inline]
    pub fn alpn_protocols<I>(mut self, alpn: I) -> Self
    where
        I: IntoIterator<Item = AlpnProtocol>,
    {
        self.config.alpn_protocols = Some(Cow::Owned(alpn.into_iter().collect()));
        self
    }

    /// Sets the ALPS protocols to use.
    #[inline]
    pub fn alps_protocols<I>(mut self, alps: I) -> Self
    where
        I: IntoIterator<Item = AlpsProtocol>,
    {
        self.config.alps_protocols = Some(Cow::Owned(alps.into_iter().collect()));
        self
    }

    /// Sets whether to use a new codepoint for ALPS.
    #[inline]
    pub fn alps_use_new_codepoint(mut self, enabled: bool) -> Self {
        self.config.alps_use_new_codepoint = enabled;
        self
    }
    /// Sets the session ticket flag.
    #[inline]
    pub fn session_ticket(mut self, enabled: bool) -> Self {
        self.config.session_ticket = Some(enabled);
        self
    }

    /// Sets the minimum TLS version to use.
    #[inline]
    pub fn min_tls_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.min_tls_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    #[inline]
    pub fn max_tls_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.max_tls_version = version.into();
        self
    }

    /// Sets the GREASE ECH extension flag.
    /// `None` leaves the backend policy unchanged.
    #[inline]
    pub fn enable_ech_grease<T: Into<Option<bool>>>(mut self, enabled: T) -> Self {
        self.config.enable_ech_grease = enabled.into();
        self
    }

    /// Sets whether to permute ClientHello extensions.
    #[inline]
    pub fn permute_extensions<T>(mut self, permute: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.permute_extensions = permute.into();
        self
    }

    /// Sets the GREASE enabled flag.
    #[inline]
    pub fn grease_enabled<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.grease_enabled = enabled.into();
        self
    }

    /// Sets whether the ClientHello `signature_algorithms` extension includes a
    /// GREASE value.
    #[inline]
    pub fn grease_sigalgs_enabled<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.grease_sigalgs_enabled = enabled.into();
        self
    }

    /// Sets the OCSP stapling flag.
    #[inline]
    pub fn enable_ocsp_stapling(mut self, enabled: bool) -> Self {
        self.config.enable_ocsp_stapling = enabled;
        self
    }

    /// Sets the signed certificate timestamps flag.
    #[inline]
    pub fn enable_signed_cert_timestamps(mut self, enabled: bool) -> Self {
        self.config.enable_signed_cert_timestamps = enabled;
        self
    }

    /// Sets the record size limit.
    #[inline]
    pub fn record_size_limit<U: Into<Option<u16>>>(mut self, limit: U) -> Self {
        self.config.record_size_limit = limit.into();
        self
    }

    /// Sets the PSK DHE key establishment flag.
    #[inline]
    pub fn psk_dhe_ke(mut self, enabled: bool) -> Self {
        self.config.psk_dhe_ke = Some(enabled);
        self
    }

    /// Sets the pre-shared key flag.
    #[inline]
    pub fn pre_shared_key(mut self, enabled: bool) -> Self {
        self.config.pre_shared_key = enabled;
        self
    }

    /// Sets the PSK skip session ticket flag.
    #[inline]
    pub fn psk_skip_session_ticket(mut self, skip: bool) -> Self {
        self.config.psk_skip_session_ticket = skip;
        self
    }

    /// Sets the renegotiation flag.
    #[inline]
    pub fn renegotiation(mut self, enabled: bool) -> Self {
        self.config.renegotiation = Some(enabled);
        self
    }

    /// Sets the delegated credentials.
    #[inline]
    pub fn delegated_credentials<T>(mut self, creds: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.delegated_credentials = Some(creds.into());
        self
    }

    /// Sets the client key shares to be used in the TLS 1.3 handshake.
    #[inline]
    pub fn key_shares<T>(mut self, key_shares: T) -> Self
    where
        T: Into<Cow<'static, [KeyShare]>>,
    {
        self.config.key_shares = Some(key_shares.into());
        self
    }

    /// Sets the encoded Trust Anchor IDs sent in ClientHello.
    ///
    /// See [`TlsOptions::trust_anchors`] for encoding and verification requirements.
    #[inline]
    pub fn trust_anchors<T>(mut self, ids: T) -> Self
    where
        T: Into<Cow<'static, [u8]>>,
    {
        self.config.trust_anchors = Some(ids.into());
        self
    }

    /// Sets the supported curves list.
    #[inline]
    pub fn curves_list<T>(mut self, curves: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.curves_list = Some(curves.into());
        self
    }

    /// Sets the supported signature algorithms.
    #[inline]
    pub fn sigalgs_list<T>(mut self, sigalgs: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.sigalgs_list = Some(sigalgs.into());
        self
    }

    /// Sets the cipher list.
    #[inline]
    pub fn cipher_list<T>(mut self, ciphers: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.cipher_list = Some(ciphers.into());
        self
    }

    /// Sets whether to preserve the TLS 1.3 cipher list as configured by [`Self::cipher_list`].
    ///
    /// By default, BoringSSL does not preserve the TLS 1.3 cipher list. When this option is
    /// disabled (the default), BoringSSL uses its internal default TLS 1.3 cipher suites in its
    /// default order, regardless of what is set via [`Self::cipher_list`].
    ///
    /// When enabled, this option ensures that the TLS 1.3 cipher suites explicitly set via
    /// [`Self::cipher_list`] are retained in their original order, without being reordered or
    /// modified by BoringSSL's internal logic. This is useful for maintaining specific cipher suite
    /// priorities for TLS 1.3. Note that if [`Self::cipher_list`] does not include any TLS 1.3
    /// cipher suites, BoringSSL will still fall back to its default TLS 1.3 cipher suites and
    /// order.
    #[inline]
    pub fn preserve_tls13_cipher_list<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.preserve_tls13_cipher_list = enabled.into();
        self
    }

    /// Sets the certificate compression algorithms.
    #[inline]
    pub fn certificate_compressors<T>(mut self, algs: T) -> Self
    where
        T: Into<Cow<'static, [&'static dyn CertificateCompressor]>>,
    {
        self.config.certificate_compressors = Some(algs.into());
        self
    }

    /// Sets the extension permutation.
    #[inline]
    pub fn extension_permutation<T>(mut self, permutation: T) -> Self
    where
        T: Into<Cow<'static, [ExtensionType]>>,
    {
        self.config.extension_permutation = Some(permutation.into());
        self
    }

    /// Sets the AES hardware override flag.
    #[inline]
    pub fn aes_hw_override<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.aes_hw_override = enabled.into();
        self
    }

    /// Sets the random AES hardware override flag.
    #[inline]
    pub fn random_aes_hw_override(mut self, enabled: bool) -> Self {
        self.config.random_aes_hw_override = enabled;
        self
    }

    /// Builds the `TlsOptions` from the builder.
    #[inline]
    pub fn build(self) -> TlsOptions {
        self.config
    }
}

impl TlsOptions {
    /// Creates a new `TlsOptionsBuilder` instance.
    pub fn builder() -> TlsOptionsBuilder {
        TlsOptionsBuilder {
            config: TlsOptions::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_protocol_encode() {
        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP1, AlpnProtocol::HTTP2]);
        assert_eq!(alpn, Bytes::from_static(b"\x08http/1.1\x02h2"));

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP1]);
        assert_eq!(alpn, Bytes::from_static(b"\x02h2\x08http/1.1"));

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
        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP1]);
        assert_eq!(alpn, b"\x08http/1.1".as_ref());

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP2]);
        assert_eq!(alpn, b"\x02h2".as_ref());

        let alpn = AlpnProtocol::encode_sequence(&[AlpnProtocol::HTTP3]);
        assert_eq!(alpn, b"\x02h3".as_ref());
    }
}
