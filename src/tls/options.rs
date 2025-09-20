use std::borrow::Cow;

use super::{
    AlpnProtocol, AlpsProtocol, CertificateCompressionAlgorithm, ExtensionType, TlsVersion,
};

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
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub struct TlsOptions {
    /// Application-Layer Protocol Negotiation ([RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301)).
    ///
    /// Specifies which application protocols (e.g., HTTP/2, HTTP/1.1) may be negotiated
    /// over a single TLS connection.
    ///
    /// **Default:** `Some([HTTP/2, HTTP/1.1])`
    pub alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,

    /// Application-Layer Protocol Settings (ALPS).
    ///
    /// Enables exchanging application-layer settings during the handshake
    /// for protocols negotiated via ALPN.
    ///
    /// **Default:** `None`
    pub alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,

    /// Whether to use an alternative ALPS codepoint for compatibility.
    ///
    /// Useful when larger ALPS payloads are required.
    ///
    /// **Default:** `false`
    pub alps_use_new_codepoint: bool,

    /// Enables TLS Session Tickets ([RFC 5077](https://tools.ietf.org/html/rfc5077)).
    ///
    /// Allows session resumption without requiring server-side state.
    ///
    /// **Default:** `true`
    pub session_ticket: bool,

    /// Minimum TLS version allowed for the connection.
    ///
    /// **Default:** `None` (library default applied)
    pub min_tls_version: Option<TlsVersion>,

    /// Maximum TLS version allowed for the connection.
    ///
    /// **Default:** `None` (library default applied)
    pub max_tls_version: Option<TlsVersion>,

    /// Enables Pre-Shared Key (PSK) cipher suites ([RFC 4279](https://datatracker.ietf.org/doc/html/rfc4279)).
    ///
    /// Authentication relies on out-of-band pre-shared keys instead of certificates.
    ///
    /// **Default:** `false`
    pub pre_shared_key: bool,

    /// Controls whether to send a GREASE Encrypted ClientHello (ECH) extension
    /// when no supported ECH configuration is available.
    ///
    /// GREASE prevents protocol ossification by sending unknown extensions.
    ///
    /// **Default:** `false`
    pub enable_ech_grease: bool,

    /// Controls whether ClientHello extensions should be permuted.
    ///
    /// **Default:** `None` (implementation default)
    pub permute_extensions: Option<bool>,

    /// Controls whether GREASE extensions ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701))
    /// are enabled in general.
    ///
    /// **Default:** `None` (implementation default)
    pub grease_enabled: Option<bool>,

    /// Enables OCSP stapling for the connection.
    ///
    /// **Default:** `false`
    pub enable_ocsp_stapling: bool,

    /// Enables Signed Certificate Timestamps (SCT).
    ///
    /// **Default:** `false`
    pub enable_signed_cert_timestamps: bool,

    /// Sets the maximum TLS record size.
    ///
    /// **Default:** `None`
    pub record_size_limit: Option<u16>,

    /// Whether to skip session tickets when using PSK.
    ///
    /// **Default:** `false`
    pub psk_skip_session_ticket: bool,

    /// Maximum number of key shares to include in ClientHello.
    ///
    /// **Default:** `None`
    pub key_shares_limit: Option<u8>,

    /// Enables PSK with (EC)DHE key establishment (`psk_dhe_ke`).
    ///
    /// **Default:** `true`
    pub psk_dhe_ke: bool,

    /// Enables TLS renegotiation by sending the `renegotiation_info` extension.
    ///
    /// **Default:** `true`
    pub renegotiation: bool,

    /// Delegated Credentials ([RFC 9345](https://datatracker.ietf.org/doc/html/rfc9345)).
    ///
    /// Allows TLS 1.3 endpoints to use temporary delegated credentials
    /// for authentication with reduced long-term key exposure.
    ///
    /// **Default:** `None`
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// List of supported elliptic curves.
    ///
    /// **Default:** `None`
    pub curves_list: Option<Cow<'static, str>>,

    /// Cipher suite configuration string.
    ///
    /// Uses BoringSSL's mini-language to select, enable, and prioritize ciphers.
    ///
    /// **Default:** `None`
    pub cipher_list: Option<Cow<'static, str>>,

    /// List of supported signature algorithms.
    ///
    /// **Default:** `None`
    pub sigalgs_list: Option<Cow<'static, str>>,

    /// Supported certificate compression algorithms ([RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879)).
    ///
    /// **Default:** `None`
    pub certificate_compression_algorithms: Option<Cow<'static, [CertificateCompressionAlgorithm]>>,

    /// Supported TLS extensions, used for extension ordering/permutation.
    ///
    /// **Default:** `None`
    pub extension_permutation: Option<Cow<'static, [ExtensionType]>>,

    /// Overrides AES hardware acceleration.
    ///
    /// **Default:** `None`
    pub aes_hw_override: Option<bool>,

    /// Sets whether to preserve the TLS 1.3 cipher list as configured by [`Self::cipher_list`].
    ///
    /// **Default:** `None`
    pub preserve_tls13_cipher_list: Option<bool>,

    /// Overrides the random AES hardware acceleration.
    ///
    /// **Default:** `false`
    pub random_aes_hw_override: bool,
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
        self.config.session_ticket = enabled;
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

    /// Sets the pre-shared key flag.
    #[inline]
    pub fn pre_shared_key(mut self, enabled: bool) -> Self {
        self.config.pre_shared_key = enabled;
        self
    }

    /// Sets the GREASE ECH extension flag.
    #[inline]
    pub fn enable_ech_grease(mut self, enabled: bool) -> Self {
        self.config.enable_ech_grease = enabled;
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

    /// Sets the PSK skip session ticket flag.
    #[inline]
    pub fn psk_skip_session_ticket(mut self, skip: bool) -> Self {
        self.config.psk_skip_session_ticket = skip;
        self
    }

    /// Sets the key shares length limit.
    #[inline]
    pub fn key_shares_limit<T>(mut self, limit: T) -> Self
    where
        T: Into<Option<u8>>,
    {
        self.config.key_shares_limit = limit.into();
        self
    }

    /// Sets the PSK DHE key establishment flag.
    #[inline]
    pub fn psk_dhe_ke(mut self, enabled: bool) -> Self {
        self.config.psk_dhe_ke = enabled;
        self
    }

    /// Sets the renegotiation flag.
    #[inline]
    pub fn renegotiation(mut self, enabled: bool) -> Self {
        self.config.renegotiation = enabled;
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

    /// Sets the supported curves list.
    #[inline]
    pub fn curves_list<T>(mut self, curves: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.curves_list = Some(curves.into());
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

    /// Sets the supported signature algorithms.
    #[inline]
    pub fn sigalgs_list<T>(mut self, sigalgs: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.sigalgs_list = Some(sigalgs.into());
        self
    }

    /// Sets the certificate compression algorithms.
    #[inline]
    pub fn certificate_compression_algorithms<T>(mut self, algs: T) -> Self
    where
        T: Into<Cow<'static, [CertificateCompressionAlgorithm]>>,
    {
        self.config.certificate_compression_algorithms = Some(algs.into());
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

impl Default for TlsOptions {
    fn default() -> Self {
        TlsOptions {
            alpn_protocols: Some(Cow::Borrowed(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])),
            alps_protocols: None,
            alps_use_new_codepoint: false,
            session_ticket: true,
            min_tls_version: None,
            max_tls_version: None,
            pre_shared_key: false,
            enable_ech_grease: false,
            permute_extensions: None,
            grease_enabled: None,
            enable_ocsp_stapling: false,
            enable_signed_cert_timestamps: false,
            record_size_limit: None,
            psk_skip_session_ticket: false,
            key_shares_limit: None,
            psk_dhe_ke: true,
            renegotiation: true,
            delegated_credentials: None,
            curves_list: None,
            cipher_list: None,
            sigalgs_list: None,
            certificate_compression_algorithms: None,
            extension_permutation: None,
            aes_hw_override: None,
            preserve_tls13_cipher_list: None,
            random_aes_hw_override: false,
        }
    }
}
