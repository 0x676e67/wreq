use super::{AlpnProtos, AlpsProtos, CertStore, Identity, TlsVersion};
use boring2::ssl::{CertCompressionAlgorithm, SslCurve};
use std::{borrow::Cow, path::PathBuf};

/// Builder for `[`TlsConfig`]`.
#[must_use]
#[derive(Debug)]
pub struct TlsConfigBuilder {
    config: TlsConfig,
}

/// Configuration settings for TLS connections.
///
/// This struct defines various parameters to fine-tune the behavior of a TLS connection,
/// including the root certificate store, certificate verification, ALPN protocols, and more.
#[derive(Debug)]
pub struct TlsConfig {
    pub(crate) tls_keylog_file: Option<PathBuf>,
    pub(crate) identity: Option<Identity>,
    pub(crate) cert_store: Option<CertStore>,
    pub(crate) cert_verification: bool,
    pub(crate) tls_sni: bool,
    pub(crate) verify_hostname: bool,
    pub(crate) alpn_protos: AlpnProtos,
    pub(crate) alps_protos: Option<AlpsProtos>,
    pub(crate) alps_use_new_codepoint: bool,
    pub(crate) session_ticket: bool,
    pub(crate) min_tls_version: Option<TlsVersion>,
    pub(crate) max_tls_version: Option<TlsVersion>,
    pub(crate) pre_shared_key: bool,
    pub(crate) enable_ech_grease: bool,
    pub(crate) permute_extensions: Option<bool>,
    pub(crate) grease_enabled: Option<bool>,
    pub(crate) enable_ocsp_stapling: bool,
    pub(crate) enable_signed_cert_timestamps: bool,
    pub(crate) record_size_limit: Option<u16>,
    pub(crate) psk_skip_session_ticket: bool,
    pub(crate) key_shares_limit: Option<u8>,
    pub(crate) psk_dhe_ke: bool,
    pub(crate) renegotiation: bool,
    pub(crate) delegated_credentials: Option<Cow<'static, str>>,
    pub(crate) cipher_list: Option<Cow<'static, str>>,
    pub(crate) curves: Option<Cow<'static, [SslCurve]>>,
    pub(crate) sigalgs_list: Option<Cow<'static, str>>,
    pub(crate) cert_compression_algorithm: Option<Cow<'static, [CertCompressionAlgorithm]>>,
    pub(crate) extension_permutation_indices: Option<Cow<'static, [u8]>>,
    pub(crate) aes_hw_override: Option<bool>,
    pub(crate) random_aes_hw_override: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            tls_keylog_file: None,
            identity: None,
            cert_store: None,
            cert_verification: true,
            tls_sni: true,
            verify_hostname: true,
            alpn_protos: AlpnProtos::default(),
            alps_protos: None,
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
            cipher_list: None,
            curves: None,
            sigalgs_list: None,
            cert_compression_algorithm: None,
            extension_permutation_indices: None,
            aes_hw_override: None,
            random_aes_hw_override: false,
        }
    }
}

impl TlsConfigBuilder {
    /// Builds the `TlsConfig` from the builder.
    pub fn build(self) -> TlsConfig {
        self.config
    }

    /// Sets the file path for TLS key logging.
    pub fn tls_keylog_file<T>(mut self, path: T) -> Self
    where
        T: Into<PathBuf>,
    {
        self.config.tls_keylog_file = Some(path.into());
        self
    }

    /// Sets the certificate store used for TLS verification.
    pub fn cert_store(mut self, store: CertStore) -> Self {
        self.config.cert_store = Some(store);
        self
    }

    /// Sets the certificate verification flag.
    pub fn cert_verification(mut self, enabled: bool) -> Self {
        self.config.cert_verification = enabled;
        self
    }

    /// Sets the identity to be used for client certificate authentication.
    pub fn identity(mut self, identity: Identity) -> Self {
        self.config.identity = Some(identity);
        self
    }

    /// Sets the Server Name Indication (SNI) flag.
    pub fn tls_sni(mut self, enabled: bool) -> Self {
        self.config.tls_sni = enabled;
        self
    }

    /// Sets the hostname verification flag.
    pub fn verify_hostname(mut self, enabled: bool) -> Self {
        self.config.verify_hostname = enabled;
        self
    }
    /// Sets the ALPN protocols to use.
    pub fn alpn_protos(mut self, protos: AlpnProtos) -> Self {
        self.config.alpn_protos = protos;
        self
    }

    /// Sets the ALPS protocols to use.
    pub fn alps_protos<T>(mut self, protos: T) -> Self
    where
        T: Into<Option<AlpsProtos>>,
    {
        self.config.alps_protos = protos.into();
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

    /// Sets the cipher list.
    pub fn cipher_list<T>(mut self, ciphers: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.cipher_list = Some(ciphers.into());
        self
    }

    /// Sets the supported curves.
    pub fn curves<T>(mut self, curves: T) -> Self
    where
        T: Into<Cow<'static, [SslCurve]>>,
    {
        self.config.curves = Some(curves.into());
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
    pub fn cert_compression_algorithm<T>(mut self, algs: T) -> Self
    where
        T: IntoCertCompressionAlgorithm,
    {
        self.config.cert_compression_algorithm = algs.into();
        self
    }

    /// Sets the extension permutation indices.
    pub fn extension_permutation_indices<T>(mut self, indices: T) -> Self
    where
        T: Into<Cow<'static, [u8]>>,
    {
        self.config.extension_permutation_indices = Some(indices.into());
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
}

impl TlsConfig {
    /// Creates a new `TlsConfigBuilder` instance.
    pub fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder {
            config: TlsConfig::default(),
        }
    }
}

/// A trait for converting various types into an optional `Cow` containing a slice of `CertCompressionAlgorithm`.
///
/// This trait is used to provide a unified way to convert different types
/// into an optional `Cow` containing a slice of `CertCompressionAlgorithm`.
pub trait IntoCertCompressionAlgorithm {
    /// Converts the given value into an optional `Cow` containing a slice of `CertCompressionAlgorithm`.
    fn into(self) -> Option<Cow<'static, [CertCompressionAlgorithm]>>;
}

macro_rules! impl_into_cert_compression_algorithm {
    ($($t:ty => $body:expr),* $(,)?) => {
        $(impl IntoCertCompressionAlgorithm for $t {
            fn into(self) -> Option<Cow<'static, [CertCompressionAlgorithm]>> {
                $body(self)
            }
        })*
    };
}

impl_into_cert_compression_algorithm!(
    &'static CertCompressionAlgorithm => |s: &'static CertCompressionAlgorithm| Some(Cow::Owned(vec![*s])),
    &'static [CertCompressionAlgorithm] => |s| Some(Cow::Borrowed(s)),
    CertCompressionAlgorithm => |s| Some(Cow::Owned(vec![s])),
    Vec<CertCompressionAlgorithm> => |s| Some(Cow::Owned(s)),
);

impl<const N: usize> IntoCertCompressionAlgorithm for &'static [CertCompressionAlgorithm; N] {
    fn into(self) -> Option<Cow<'static, [CertCompressionAlgorithm]>> {
        Some(Cow::Borrowed(self))
    }
}

impl<const N: usize> IntoCertCompressionAlgorithm for [CertCompressionAlgorithm; N] {
    fn into(self) -> Option<Cow<'static, [CertCompressionAlgorithm]>> {
        Some(Cow::Owned(self.to_vec()))
    }
}

impl<T: IntoCertCompressionAlgorithm> IntoCertCompressionAlgorithm for Option<T> {
    fn into(self) -> Option<Cow<'static, [CertCompressionAlgorithm]>> {
        self.and_then(|v| v.into())
    }
}
