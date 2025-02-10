use super::{AlpnProtos, AlpsProtos, RootCertStoreProvider, TlsVersion};
use boring2::ssl::{CertCompressionAlgorithm, SslCurve};
use std::borrow::Cow;
use typed_builder::TypedBuilder;

/// Configuration settings for TLS connections.
///
/// This struct defines various parameters to fine-tune the behavior of a TLS connection,
/// including the root certificate store, certificate verification, ALPN protocols, and more.
#[derive(Debug, TypedBuilder)]
pub struct TlsConfig {
    /// The root certificate store.
    /// Default use system's native certificate store.
    #[builder(default = RootCertStoreProvider::Default)]
    pub root_certs_store: RootCertStoreProvider,

    /// SSL may authenticate either endpoint with an X.509 certificate.
    /// Typically this is used to authenticate the server to the client.
    /// These functions configure certificate verification.
    #[builder(default = true)]
    pub certs_verification: bool,

    /// The server_name extension (RFC 3546) allows the client to advertise the
    /// name of the server it is connecting to. This is used in virtual hosting
    /// deployments to select one of several certificates on a single IP.
    /// Only the host_name name type is supported.
    #[builder(default = true)]
    pub tls_sni: bool,

    /// Hostname verification.
    #[builder(default = true)]
    pub verify_hostname: bool,

    /// The **ALPN extension** [RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301) allows negotiating different
    /// **application-layer protocols** over a **single port**.
    ///
    /// **Usage Example:**
    /// - Commonly used to negotiate **HTTP/2**.
    /// - Default use all protocols (HTTP/1.1/HTTP/2/HTTP/3).
    #[builder(default = AlpnProtos::ALL)]
    pub alpn_protos: AlpnProtos,

    /// The **ALPS extension** (*draft-vvv-tls-alps*) enables exchanging
    /// **application-layer settings** during the **TLS handshake**.
    ///
    /// This is specifically for applications negotiated via **ALPN**.
    #[builder(default, setter(into))]
    pub alps_protos: Option<AlpsProtos>,

    /// Switching to a new codepoint for TLS ALPS extension to allow adding more data
    /// in the ACCEPT_CH HTTP/2 and HTTP/3 frame. The ACCEPT_CH HTTP/2 frame with the
    /// existing TLS ALPS extension had an arithmetic overflow bug in Chrome ALPS decoder.
    /// It limits the capability to add more than 128 bytes data (in theory, the problem
    /// range is 128 bytes to 255 bytes) to the ACCEPT_CH frame.
    #[builder(default = false)]
    pub alps_use_new_codepoint: bool,

    /// **Session Tickets** (RFC 5077) allow **session resumption** without the need for server-side state.
    ///
    /// This mechanism works as follows:
    /// 1. The server maintains a **secret ticket key**.
    /// 2. The server sends the client **opaque encrypted session parameters**, referred to as a **ticket**.
    /// 3. When resuming the session, the client sends the **ticket** to the server.
    /// 4. The server decrypts the ticket to recover the session state.
    ///
    /// **Reference:** See [RFC 5077](https://tools.ietf.org/html/rfc5077) for further details on session tickets.
    #[builder(default = true)]
    pub session_ticket: bool,

    /// Sets the minimum protocol version for ssl to version.
    #[builder(default, setter(into))]
    pub min_tls_version: Option<TlsVersion>,

    /// Sets the maximum protocol version for ssl to version.
    #[builder(default, setter(into))]
    pub max_tls_version: Option<TlsVersion>,

    /// Connections can be configured with **PSK (Pre-Shared Key)** cipher suites.
    ///
    /// **PSK cipher suites** use **out-of-band pre-shared keys** for authentication,
    /// instead of relying on certificates.
    ///
    /// **Reference:** See [RFC 4279](https://datatracker.ietf.org/doc/html/rfc4279) for details.
    #[builder(default = false)]
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
    #[builder(default = false)]
    pub enable_ech_grease: bool,

    /// Configures whether ClientHello extensions should be permuted.
    ///
    /// Note: This is gated to non-fips because the fips feature builds with a separate
    /// version of BoringSSL which doesn't yet include these APIs.
    /// Once the submoduled fips commit is upgraded, these gates can be removed.
    #[builder(default, setter(into))]
    pub permute_extensions: Option<bool>,

    /// Set's whether the context should enable GREASE.
    #[builder(default, setter(into))]
    pub grease_enabled: Option<bool>,

    /// Enables OCSP stapling on all client SSL handshakes.
    #[builder(default = false)]
    pub enable_ocsp_stapling: bool,

    /// Sets the list of signed certificate timestamps that is sent to clients that request it
    #[builder(default = false)]
    pub enable_signed_cert_timestamps: bool,

    /// Sets the context's record size limit.
    #[builder(default, setter(into))]
    pub record_size_limit: Option<u16>,

    /// PSK session ticket skip.
    #[builder(default = false)]
    pub psk_skip_session_ticket: bool,

    /// Sets the context's key shares length limit.
    #[builder(default, setter(into))]
    pub key_shares_limit: Option<u8>,

    /// Sets PSK with (EC)DHE key establishment (psk_dhe_ke)
    /// [Reference](https://github.com/openssl/openssl/issues/13918)
    #[builder(default = true)]
    pub psk_dhe_ke: bool,

    /// SSL Renegotiation is enabled by default on many servers.
    /// This setting allows the client to send a renegotiation_info extension
    #[builder(default = true)]
    pub renegotiation: bool,

    /// **Delegated Credentials** (RFC 9345) provide a mechanism for TLS 1.3 endpoints
    /// to issue temporary credentials for authentication using their existing certificate.
    ///
    /// Once issued, **delegated credentials** **cannot be revoked**.
    /// To minimize potential damage if the credential's secret key is compromised,
    /// these credentials are valid only for a **short duration** (e.g., days, hours, or minutes).
    ///
    /// **Reference:** See [RFC 9345](https://datatracker.ietf.org/doc/html/rfc9345) for details.
    #[builder(default, setter(strip_option, into))]
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// BoringSSL uses a **mini-language** to configure **cipher suites**.
    ///
    /// This configuration language manages two ordered lists:
    /// - **Enabled Ciphers**: An ordered list of currently active cipher suites.
    /// - **Disabled but Available Ciphers**: An ordered list of cipher suites that are currently inactive but can be enabled.
    ///
    /// Initially, **all ciphers are disabled** and follow a **default ordering**.
    ///
    /// Developers can use this mini-language to fine-tune which ciphers are enabled,
    /// their priority, and which ones are explicitly disabled.
    ///
    /// **Reference:** See [BoringSSL Cipher Suite Documentation](https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CTX_set_cipher_list) for details.
    #[builder(default, setter(strip_option, into))]
    pub cipher_list: Option<Cow<'static, str>>,

    /// Sets the context's supported curves.
    #[builder(default, setter(strip_option, into))]
    pub curves: Option<Cow<'static, [SslCurve]>>,

    /// Sets the context's supported signature algorithms.
    #[builder(default, setter(strip_option, into))]
    pub sigalgs_list: Option<Cow<'static, str>>,

    /// Certificates in TLS 1.3 can be compressed [RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879).
    #[builder(default, setter(transform = |input: impl IntoCertCompressionAlgorithm| input.into()))]
    pub cert_compression_algorithm: Option<Cow<'static, [CertCompressionAlgorithm]>>,

    /// Sets the context's extension permutation indices.
    #[builder(default, setter(strip_option, into))]
    pub extension_permutation_indices: Option<Cow<'static, [u8]>>,
}

/// ====== impl TlsSettings ======c
impl Default for TlsConfig {
    fn default() -> Self {
        Self::builder().build()
    }
}

/// A trait for converting various types into an optional `Cow` containing a slice of `CertCompressionAlgorithm`.
///
/// This trait is used to provide a unified way to convert different types
/// into an optional `Cow` containing a slice of `CertCompressionAlgorithm`.
pub trait IntoCertCompressionAlgorithm {
    /// Converts the implementing type into an optional `Cow` containing a slice of `CertCompressionAlgorithm`.
    fn into(self) -> Option<Cow<'static, [CertCompressionAlgorithm]>>;
}

// Macro to implement IntoCertCompressionAlgorithm for various types
macro_rules! impl_into_cert_compression_algorithm_for_types {
    ($($t:ty => $body:expr),*) => {
        $(
            impl IntoCertCompressionAlgorithm for $t {
                fn into(self) -> Option<Cow<'static, [CertCompressionAlgorithm]>> {
                    $body(self)
                }
            }
        )*
    };
}

// Macro to implement IntoCertCompressionAlgorithm for const-sized arrays
macro_rules! impl_into_cert_compression_algorithm_for_arrays {
    ($($t:ty => $body:expr),*) => {
        $(
            impl<const N: usize> IntoCertCompressionAlgorithm for $t {
                fn into(self) -> Option<Cow<'static, [CertCompressionAlgorithm]>> {
                    $body(self)
                }
            }
        )*
    };
}

impl_into_cert_compression_algorithm_for_types!(
    &'static [CertCompressionAlgorithm] => |s| Some(Cow::Borrowed(s)),
    Option<&'static [CertCompressionAlgorithm]> => |s: Option<&'static [CertCompressionAlgorithm]>| s.map(Cow::Borrowed)
);

impl_into_cert_compression_algorithm_for_types!(
    Cow<'static, [CertCompressionAlgorithm]> => Some,
    Option<Cow<'static, [CertCompressionAlgorithm]>> => |s| s
);

impl_into_cert_compression_algorithm_for_types!(
    &'static CertCompressionAlgorithm => |s: &'static CertCompressionAlgorithm| Some(Cow::Owned(vec![*s])),
    Option<&'static CertCompressionAlgorithm> => |s: Option<&'static CertCompressionAlgorithm>| s.map(|alg| Cow::Owned(vec![*alg]))
);

impl_into_cert_compression_algorithm_for_types!(
    CertCompressionAlgorithm => |s| Some(Cow::Owned(vec![s])),
    Option<CertCompressionAlgorithm> => |s: Option<CertCompressionAlgorithm>| s.map(|alg| Cow::Owned(vec![alg]))
);

impl_into_cert_compression_algorithm_for_types!(
    Vec<CertCompressionAlgorithm> => |s| Some(Cow::Owned(s)),
    Option<Vec<CertCompressionAlgorithm>> => |s: Option<Vec<CertCompressionAlgorithm>>| s.map(Cow::Owned)
);

impl_into_cert_compression_algorithm_for_arrays!(
    &'static [CertCompressionAlgorithm; N] => |s: &'static [CertCompressionAlgorithm; N]| Some(Cow::Borrowed(&s[..])),
    Option<&'static [CertCompressionAlgorithm; N]> => |s: Option<&'static [CertCompressionAlgorithm; N]>| s.map(|s| Cow::Borrowed(&s[..]))
);

impl_into_cert_compression_algorithm_for_arrays!(
    [CertCompressionAlgorithm; N] => |s: [CertCompressionAlgorithm; N]| Some(Cow::Owned(s.to_vec())),
    Option<[CertCompressionAlgorithm; N]> => |s: Option<[CertCompressionAlgorithm; N]>| s.map(|arr| Cow::Owned(arr.to_vec()))
);
