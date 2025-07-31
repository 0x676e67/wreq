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
/// This struct provides fine-grained control over TLS connection behavior,
/// allowing customization of protocol versions, cipher suites, extensions,
/// and various security features.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub struct TlsOptions {
    /// ALPN protocols to use for the TLS connection.
    pub alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,

    /// ALPS protocols to use for the TLS connection.
    pub alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,

    /// Whether to use a new codepoint for ALPS.
    pub alps_use_new_codepoint: bool,

    /// Whether to use session tickets for TLS session resumption.
    pub session_ticket: bool,

    /// Minimum TLS version to use for the connection.
    pub min_tls_version: Option<TlsVersion>,

    /// Maximum TLS version to use for the connection.
    pub max_tls_version: Option<TlsVersion>,

    /// Whether to use pre-shared keys (PSK) for the connection.
    pub pre_shared_key: bool,

    /// Whether to enable ECH (Encrypted ClientHello) GREASE extension.
    pub enable_ech_grease: bool,

    /// Whether to permute ClientHello extensions.
    pub permute_extensions: Option<bool>,

    /// Whether to enable GREASE (Generate Random Extensions And Sustain Extensibility).
    pub grease_enabled: Option<bool>,

    /// Whether to enable OCSP stapling for the connection.
    pub enable_ocsp_stapling: bool,

    /// Whether to enable signed certificate timestamps (SCT) for the connection.
    pub enable_signed_cert_timestamps: bool,

    /// Maximum size of TLS record.
    pub record_size_limit: Option<u16>,

    /// Whether to skip session ticket for PSK (Pre-Shared Key) connections.
    pub psk_skip_session_ticket: bool,

    /// Maximum number of key shares to include in the ClientHello.
    pub key_shares_limit: Option<u8>,

    /// Whether to use PSK DHE (Diffie-Hellman Ephemeral) key establishment.
    pub psk_dhe_ke: bool,

    /// Whether to allow renegotiation of the TLS session.
    pub renegotiation: bool,

    /// Delegated credentials for the TLS connection.
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// List of curves to use for the TLS connection.
    pub curves_list: Option<Cow<'static, str>>,

    /// List of ciphers to use for the TLS connection.
    pub cipher_list: Option<Cow<'static, str>>,

    /// List of signature algorithms to use for the TLS connection.
    pub sigalgs_list: Option<Cow<'static, str>>,

    /// List of supported curves for the TLS connection.
    pub certificate_compression_algorithms: Option<Cow<'static, [CertificateCompressionAlgorithm]>>,

    /// List of supported extensions for the TLS connection.
    pub extension_permutation: Option<Cow<'static, [ExtensionType]>>,

    /// Whether to override the AES hardware acceleration.
    pub aes_hw_override: Option<bool>,

    /// Whether to prefer ChaCha20 over AES.
    pub prefer_chacha20: Option<bool>,

    /// Whether to override the random AES hardware acceleration.
    pub random_aes_hw_override: bool,
}

impl TlsOptionsBuilder {
    /// Builds the `TlsOptions` from the builder.
    pub fn build(self) -> TlsOptions {
        self.config
    }

    /// Sets the ALPN protocols to use.
    pub fn alpn_protocols<I>(mut self, alpn: I) -> Self
    where
        I: IntoIterator<Item = AlpnProtocol>,
    {
        self.config.alpn_protocols = Some(Cow::Owned(alpn.into_iter().collect()));
        self
    }

    /// Sets the ALPS protocols to use.
    pub fn alps_protocols<I>(mut self, alps: I) -> Self
    where
        I: IntoIterator<Item = AlpsProtocol>,
    {
        self.config.alps_protocols = Some(Cow::Owned(alps.into_iter().collect()));
        self
    }

    /// Sets whether to use a new codepoint for ALPS.
    pub fn alps_use_new_codepoint(mut self, enabled: bool) -> Self {
        self.config.alps_use_new_codepoint = enabled;
        self
    }
    /// Sets the session ticket flag.
    pub fn session_ticket(mut self, enabled: bool) -> Self {
        self.config.session_ticket = enabled;
        self
    }

    /// Sets the minimum TLS version to use.
    pub fn min_tls_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.min_tls_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    pub fn max_tls_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.max_tls_version = version.into();
        self
    }

    /// Sets the pre-shared key flag.
    pub fn pre_shared_key(mut self, enabled: bool) -> Self {
        self.config.pre_shared_key = enabled;
        self
    }

    /// Sets the GREASE ECH extension flag.
    pub fn enable_ech_grease(mut self, enabled: bool) -> Self {
        self.config.enable_ech_grease = enabled;
        self
    }

    /// Sets whether to permute ClientHello extensions.
    pub fn permute_extensions<T>(mut self, permute: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.permute_extensions = permute.into();
        self
    }

    /// Sets the GREASE enabled flag.
    pub fn grease_enabled<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.grease_enabled = enabled.into();
        self
    }

    /// Sets the OCSP stapling flag.
    pub fn enable_ocsp_stapling(mut self, enabled: bool) -> Self {
        self.config.enable_ocsp_stapling = enabled;
        self
    }

    /// Sets the signed certificate timestamps flag.
    pub fn enable_signed_cert_timestamps(mut self, enabled: bool) -> Self {
        self.config.enable_signed_cert_timestamps = enabled;
        self
    }

    /// Sets the record size limit.
    pub fn record_size_limit<U: Into<Option<u16>>>(mut self, limit: U) -> Self {
        self.config.record_size_limit = limit.into();
        self
    }

    /// Sets the PSK skip session ticket flag.
    pub fn psk_skip_session_ticket(mut self, skip: bool) -> Self {
        self.config.psk_skip_session_ticket = skip;
        self
    }

    /// Sets the key shares length limit.
    pub fn key_shares_limit<T>(mut self, limit: T) -> Self
    where
        T: Into<Option<u8>>,
    {
        self.config.key_shares_limit = limit.into();
        self
    }

    /// Sets the PSK DHE key establishment flag.
    pub fn psk_dhe_ke(mut self, enabled: bool) -> Self {
        self.config.psk_dhe_ke = enabled;
        self
    }

    /// Sets the renegotiation flag.
    pub fn renegotiation(mut self, enabled: bool) -> Self {
        self.config.renegotiation = enabled;
        self
    }

    /// Sets the delegated credentials.
    pub fn delegated_credentials<T>(mut self, creds: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.delegated_credentials = Some(creds.into());
        self
    }

    /// Sets the supported curves list.
    pub fn curves_list<T>(mut self, curves: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.curves_list = Some(curves.into());
        self
    }

    /// Sets the cipher list.
    pub fn cipher_list<T>(mut self, ciphers: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.cipher_list = Some(ciphers.into());
        self
    }

    /// Sets the supported signature algorithms.
    pub fn sigalgs_list<T>(mut self, sigalgs: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.sigalgs_list = Some(sigalgs.into());
        self
    }

    /// Sets the certificate compression algorithms.
    pub fn certificate_compression_algorithms<T>(mut self, algs: T) -> Self
    where
        T: Into<Cow<'static, [CertificateCompressionAlgorithm]>>,
    {
        self.config.certificate_compression_algorithms = Some(algs.into());
        self
    }

    /// Sets the extension permutation.
    pub fn extension_permutation<T>(mut self, permutation: T) -> Self
    where
        T: Into<Cow<'static, [ExtensionType]>>,
    {
        self.config.extension_permutation = Some(permutation.into());
        self
    }

    /// Sets the AES hardware override flag.
    pub fn aes_hw_override<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.aes_hw_override = enabled.into();
        self
    }

    /// Sets the random AES hardware override flag.
    pub fn random_aes_hw_override(mut self, enabled: bool) -> Self {
        self.config.random_aes_hw_override = enabled;
        self
    }

    /// Sets the preference for ChaCha20 cipher.
    ///
    /// Controls the priority of TLS 1.3 cipher suites. When set to `true`, the client prefers:
    /// AES_128_GCM, CHACHA20_POLY1305, then AES_256_GCM. Useful in environments with specific
    /// encryption requirements.
    pub fn prefer_chacha20<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.prefer_chacha20 = enabled.into();
        self
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
            prefer_chacha20: None,
            random_aes_hw_override: false,
        }
    }
}
