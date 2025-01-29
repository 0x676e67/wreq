//! TLS configuration
//!
//! By default, a `Client` will make use of BoringSSL for TLS.
//!
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.

mod cert;
mod conn;
mod ext;

use crate::impl_debug;
use boring2::ssl::SslCurve;
use boring2::{
    error::ErrorStack,
    ssl::{SslConnector, SslMethod, SslOptions, SslVersion},
};
use conn::{HttpsLayer, HttpsLayerSettings};
use std::borrow::Cow;
use typed_builder::TypedBuilder;

pub use cert::{compression::CertCompressionAlgorithm, RootCertStore};
pub use conn::{HttpsConnector, MaybeHttpsStream};
pub use ext::{ConnectConfigurationExt, SslConnectorBuilderExt, SslRefExt};

type TlsResult<T> = Result<T, ErrorStack>;

/// Error handler for the boringssl functions.
fn sv_handler(r: ::std::os::raw::c_int) -> TlsResult<::std::os::raw::c_int> {
    if r == 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

/// A wrapper around a `HttpsLayer` that allows for additional config.
#[derive(Clone)]
pub(crate) struct BoringTlsConnector(HttpsLayer);

impl BoringTlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    #[inline]
    pub fn new(config: TlsConfig) -> TlsResult<BoringTlsConnector> {
        let mut connector = SslConnector::no_default_verify_builder(SslMethod::tls_client())?
            .root_cert_store(config.root_certs_store)?
            .cert_verification(config.certs_verification)?
            .alpn_protos(config.alpn_protos)?
            .min_tls_version(config.min_tls_version)?
            .max_tls_version(config.max_tls_version)?;

        if config.enable_ocsp_stapling {
            connector.enable_ocsp_stapling();
        }

        if config.enable_signed_cert_timestamps {
            connector.enable_signed_cert_timestamps();
        }

        if !config.session_ticket {
            connector.set_options(SslOptions::NO_TICKET);
        }

        if !config.psk_dhe_ke {
            connector.set_options(SslOptions::NO_PSK_DHE_KE);
        }

        if !config.renegotiation {
            connector.set_options(SslOptions::NO_RENEGOTIATION);
        }

        if let Some(grease_enabled) = config.grease_enabled {
            connector.set_grease_enabled(grease_enabled);
        }

        if let Some(permute_extensions) = config.permute_extensions {
            connector.set_permute_extensions(permute_extensions);
        }

        if let Some(curves) = config.curves.as_deref() {
            connector.set_curves(curves)?;
        }

        if let Some(sigalgs_list) = config.sigalgs_list.as_deref() {
            connector.set_sigalgs_list(sigalgs_list)?;
        }

        if let Some(delegated_credentials) = config.delegated_credentials.as_deref() {
            connector.set_delegated_credentials(delegated_credentials)?;
        }

        if let Some(cipher_list) = config.cipher_list.as_deref() {
            connector.set_cipher_list(cipher_list)?;
        }

        if let Some(cert_compression_algorithm) = config.cert_compression_algorithm {
            for algorithm in cert_compression_algorithm.iter() {
                connector = connector.add_cert_compression_alg(*algorithm)?;
            }
        }

        if let Some(record_size_limit) = config.record_size_limit {
            connector.set_record_size_limit(record_size_limit);
        }

        if let Some(limit) = config.key_shares_limit {
            connector.set_key_shares_limit(limit);
        }

        if let Some(indices) = config.extension_permutation_indices {
            connector.set_extension_permutation_indices(indices.as_ref())?;
        }

        // Create the `HttpsLayerSettings` with the default session cache capacity.
        let settings = HttpsLayerSettings::builder()
            .session_cache(config.pre_shared_key)
            .skip_session_ticket(config.psk_skip_session_ticket)
            .alpn_protos(config.alpn_protos)
            .alps_protos(config.alps_protos)
            .enable_ech_grease(config.enable_ech_grease)
            .tls_sni(config.tls_sni)
            .verify_hostname(config.verify_hostname)
            .build();

        Ok(Self(HttpsLayer::with_connector_and_settings(
            connector, settings,
        )))
    }
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsVersion(SslVersion);

// These could perhaps be From/TryFrom implementations, but those would be
// part of the public API so let's be careful
impl TlsVersion {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: TlsVersion = TlsVersion(SslVersion::TLS1);
    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: TlsVersion = TlsVersion(SslVersion::TLS1_1);
    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: TlsVersion = TlsVersion(SslVersion::TLS1_2);
    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: TlsVersion = TlsVersion(SslVersion::TLS1_3);
}

/// A TLS ALPN protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlpnProtos(&'static [u8]);

/// A `AlpnProtos` is used to set the HTTP version preference.
#[allow(non_upper_case_globals)]
impl AlpnProtos {
    /// Prefer HTTP/1.1
    pub const Http1: AlpnProtos = AlpnProtos(b"\x08http/1.1");
    /// Prefer HTTP/2
    pub const Http2: AlpnProtos = AlpnProtos(b"\x02h2");
    /// Prefer HTTP/1 and HTTP/2
    pub const All: AlpnProtos = AlpnProtos(b"\x02h2\x08http/1.1");
}

impl Default for AlpnProtos {
    fn default() -> Self {
        Self::All
    }
}

/// Application-layer protocol settings for HTTP/1.1 and HTTP/2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlpsProtos(&'static [u8]);

#[allow(non_upper_case_globals)]
impl AlpsProtos {
    /// Application Settings protocol for HTTP/1.1
    pub const Http1: AlpsProtos = AlpsProtos(b"http/1.1");
    /// Application Settings protocol for HTTP/2
    pub const Http2: AlpsProtos = AlpsProtos(b"h2");

    #[inline(always)]
    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    #[inline(always)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
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

/// Configuration settings for TLS connections.
///
/// This struct defines various parameters to fine-tune the behavior of a TLS connection,
/// including the root certificate store, certificate verification, ALPN protocols, and more.
#[derive(TypedBuilder)]
pub struct TlsConfig {
    /// The root certificate store.
    /// Default use system's native certificate store.
    #[builder(default = RootCertStore::Default)]
    pub root_certs_store: RootCertStore,

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
    #[builder(default = AlpnProtos::All)]
    pub alpn_protos: AlpnProtos,

    /// The **ALPS extension** (*draft-vvv-tls-alps*) enables exchanging
    /// **application-layer settings** during the **TLS handshake**.
    ///
    /// This is specifically for applications negotiated via **ALPN**.
    #[builder(default, setter(into))]
    pub alps_protos: Option<AlpsProtos>,

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

impl_debug!(
    TlsConfig,
    {
        certs_verification,
        tls_sni,
        verify_hostname,
        alpn_protos,
        session_ticket,
        min_tls_version,
        max_tls_version,
        alps_protos,
        psk_dhe_ke,
        pre_shared_key,
        enable_ech_grease,
        permute_extensions,
        grease_enabled,
        enable_ocsp_stapling,
        renegotiation,
        curves,
        sigalgs_list,
        cipher_list,
        enable_signed_cert_timestamps,
        cert_compression_algorithm,
        record_size_limit,
        key_shares_limit,
        psk_skip_session_ticket,
        extension_permutation_indices
    }
);

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
