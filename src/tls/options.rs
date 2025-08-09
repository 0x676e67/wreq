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
    /// The **ALPN extension** [RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301) allows negotiating different
    /// **application-layer protocols** over a **single port**.
    ///
    /// **Usage Example:**
    /// - Commonly used to negotiate **HTTP/2**.
    /// - Default use all protocols (HTTP/1.1/HTTP/2).
    pub alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,

    /// The **ALPS extension** enables exchanging
    /// **application-layer settings** during the **TLS handshake**.
    ///
    /// This is specifically for applications negotiated via **ALPN**.
    pub alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,

    /// Switching to a new codepoint for TLS ALPS extension to allow adding more data
    /// in the ACCEPT_CH HTTP/2 and HTTP/3 frame. The ACCEPT_CH HTTP/2 frame with the
    /// existing TLS ALPS extension had an arithmetic overflow bug in Chrome ALPS decoder.
    /// It limits the capability to add more than 128 bytes data (in theory, the problem
    /// range is 128 bytes to 255 bytes) to the ACCEPT_CH frame.
    pub alps_use_new_codepoint: bool,

    /// **Session Tickets** (RFC 5077) allow **session resumption** without the need for
    /// server-side state.
    ///
    /// This mechanism works as follows:
    /// 1. The server maintains a **secret ticket key**.
    /// 2. The server sends the client **opaque encrypted session parameters**, referred to as a
    ///    **ticket**.
    /// 3. When resuming the session, the client sends the **ticket** to the server.
    /// 4. The server decrypts the ticket to recover the session state.
    ///
    /// **Reference:** See [RFC 5077](https://tools.ietf.org/html/rfc5077) for further details on session tickets.
    pub session_ticket: bool,

    /// Minimum TLS version to use for the connection.
    pub min_tls_version: Option<TlsVersion>,

    /// Maximum TLS version to use for the connection.
    pub max_tls_version: Option<TlsVersion>,

    /// Connections can be configured with **PSK (Pre-Shared Key)** cipher suites.
    ///
    /// **PSK cipher suites** use **out-of-band pre-shared keys** for authentication,
    /// instead of relying on certificates.
    ///
    /// **Reference:** See [RFC 4279](https://datatracker.ietf.org/doc/html/rfc4279) for details.
    pub pre_shared_key: bool,

    /// Configures whether the **client** will send a **GREASE ECH** extension
    /// when no supported **ECHConfig** is available.
    ///
    /// GREASE (Generate Random Extensions And Sustain Extensibility)
    /// helps prevent ossification of the TLS protocol by randomly
    /// introducing unknown extensions into the handshake.
    ///
    /// **ECH (Encrypted Client Hello)** improves privacy by encrypting
    /// sensitive handshake information, such as the Server Name Indication (SNI).
    ///
    /// When no valid **ECHConfig** is present, enabling this setting allows
    /// the client to still send a GREASE extension for compatibility purposes.
    ///
    /// **Reference:** See [RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701) for GREASE details.
    pub enable_ech_grease: bool,

    /// Configures whether ClientHello extensions should be permuted.
    ///
    /// Note: This is gated to non-fips because the fips feature builds with a separate
    /// version of BoringSSL which doesn't yet include these APIs.
    /// Once the submoduled fips commit is upgraded, these gates can be removed.
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

    /// Sets PSK with (EC)DHE key establishment (psk_dhe_ke)
    /// [Reference](https://github.com/openssl/openssl/issues/13918)
    pub psk_dhe_ke: bool,

    /// SSL Renegotiation is enabled by default on many servers.
    /// This setting allows the client to send a renegotiation_info extension
    pub renegotiation: bool,

    /// **Delegated Credentials** (RFC 9345) provide a mechanism for TLS 1.3 endpoints
    /// to issue temporary credentials for authentication using their existing certificate.
    ///
    /// Once issued, **delegated credentials** **cannot be revoked**.
    /// To minimize potential damage if the credential's secret key is compromised,
    /// these credentials are valid only for a **short duration** (e.g., days, hours, or minutes).
    ///
    /// **Reference:** See [RFC 9345](https://datatracker.ietf.org/doc/html/rfc9345) for details.
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// List of curves to use for the TLS connection.
    pub curves_list: Option<Cow<'static, str>>,

    /// BoringSSL uses a **mini-language** to configure **cipher suites**.
    ///
    /// This configuration language manages two ordered lists:
    /// - **Enabled Ciphers**: An ordered list of currently active cipher suites.
    /// - **Disabled but Available Ciphers**: An ordered list of cipher suites that are currently
    ///   inactive but can be enabled.
    ///
    /// Initially, **all ciphers are disabled** and follow a **default ordering**.
    ///
    /// Developers can use this mini-language to fine-tune which ciphers are enabled,
    /// their priority, and which ones are explicitly disabled.
    ///
    /// **Reference:** See [BoringSSL Cipher Suite Documentation](https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CTX_set_cipher_list) for details.
    pub cipher_list: Option<Cow<'static, str>>,

    /// List of signature algorithms to use for the TLS connection.
    pub sigalgs_list: Option<Cow<'static, str>>,

    /// List of supported certificate compression algorithms for the TLS connection.
    ///
    /// Certificate compression in TLS 1.3 is defined in [RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879).
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

    /// Sets the preference for ChaCha20 cipher.
    ///
    /// Controls the priority of TLS 1.3 cipher suites. When set to `true`, the client prefers:
    /// AES_128_GCM, CHACHA20_POLY1305, then AES_256_GCM. Useful in environments with specific
    /// encryption requirements.
    #[inline]
    pub fn prefer_chacha20<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.prefer_chacha20 = enabled.into();
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
            prefer_chacha20: None,
            random_aes_hw_override: false,
        }
    }
}
