use super::{AlpnProtos, AlpsProtos, CertStore, TlsVersion};
use boring2::ssl::{CertCompressionAlgorithm, SslCurve};
use std::{borrow::Cow, path::PathBuf};
use typed_builder::TypedBuilder;

/// Configuration settings for TLS connections.
///
/// This struct defines various parameters to fine-tune the behavior of a TLS connection,
/// including the root certificate store, certificate verification, ALPN protocols, and more.
#[derive(Debug, TypedBuilder)]
pub struct TlsConfig {
    #[builder(default, setter(into))]
    pub(crate) tls_keylog_file: Option<PathBuf>,

    #[builder(default, setter(transform = |input: impl IntoCertStore| input.into()))]
    pub(crate) cert_store: Option<Cow<'static, CertStore>>,

    #[builder(default = true)]
    pub(crate) cert_verification: bool,

    #[builder(default = true)]
    pub(crate) tls_sni: bool,

    #[builder(default = true)]
    pub(crate) verify_hostname: bool,

    #[builder(default = AlpnProtos::default())]
    pub(crate) alpn_protos: AlpnProtos,

    #[builder(default, setter(into))]
    pub(crate) alps_protos: Option<AlpsProtos>,

    #[builder(default = false)]
    pub(crate) alps_use_new_codepoint: bool,

    #[builder(default = true)]
    pub(crate) session_ticket: bool,

    #[builder(default, setter(into))]
    pub(crate) min_tls_version: Option<TlsVersion>,

    #[builder(default, setter(into))]
    pub(crate) max_tls_version: Option<TlsVersion>,

    #[builder(default = false)]
    pub(crate) pre_shared_key: bool,

    #[builder(default = false)]
    pub(crate) enable_ech_grease: bool,

    #[builder(default, setter(into))]
    pub(crate) permute_extensions: Option<bool>,

    #[builder(default, setter(into))]
    pub(crate) grease_enabled: Option<bool>,

    #[builder(default = false)]
    pub(crate) enable_ocsp_stapling: bool,

    #[builder(default = false)]
    pub(crate) enable_signed_cert_timestamps: bool,

    #[builder(default, setter(into))]
    pub(crate) record_size_limit: Option<u16>,

    #[builder(default = false)]
    pub(crate) psk_skip_session_ticket: bool,

    #[builder(default, setter(into))]
    pub(crate) key_shares_limit: Option<u8>,

    #[builder(default = true)]
    pub(crate) psk_dhe_ke: bool,

    #[builder(default = true)]
    pub(crate) renegotiation: bool,

    #[builder(default, setter(strip_option, into))]
    pub(crate) delegated_credentials: Option<Cow<'static, str>>,

    #[builder(default, setter(strip_option, into))]
    pub(crate) cipher_list: Option<Cow<'static, str>>,

    #[builder(default, setter(strip_option, into))]
    pub(crate) curves: Option<Cow<'static, [SslCurve]>>,

    #[builder(default, setter(strip_option, into))]
    pub(crate) sigalgs_list: Option<Cow<'static, str>>,

    #[builder(default, setter(transform = |input: impl IntoCertCompressionAlgorithm| input.into()))]
    pub(crate) cert_compression_algorithm: Option<Cow<'static, [CertCompressionAlgorithm]>>,

    #[builder(default, setter(strip_option, into))]
    pub(crate) extension_permutation_indices: Option<Cow<'static, [u8]>>,

    #[builder(default, setter(into))]
    pub(crate) aes_hw_override: Option<bool>,

    #[builder(default, setter(into))]
    pub(crate) random_aes_hw_override: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl TlsConfig {
    /// Sets the file path for TLS key logging.
    pub fn set_tls_keylog_file<T>(&mut self, path: T) -> &mut Self
    where
        T: Into<PathBuf>,
    {
        self.tls_keylog_file = Some(path.into());
        self
    }

    /// Sets the certificate store used for TLS verification.
    pub fn set_cert_store<T>(&mut self, store: T) -> &mut Self
    where
        T: IntoCertStore,
    {
        self.cert_store = store.into();
        self
    }

    /// Enables or disables certificate verification.
    pub fn set_cert_verification(&mut self, enabled: bool) -> &mut Self {
        self.cert_verification = enabled;
        self
    }

    /// Enables or disables Server Name Indication (SNI).
    pub fn set_tls_sni(&mut self, enabled: bool) -> &mut Self {
        self.tls_sni = enabled;
        self
    }

    /// Enables or disables hostname verification.
    pub fn set_verify_hostname(&mut self, enabled: bool) -> &mut Self {
        self.verify_hostname = enabled;
        self
    }

    /// Sets the ALPN protocols to use.
    pub fn set_alpn_protos(&mut self, protos: AlpnProtos) -> &mut Self {
        self.alpn_protos = protos;
        self
    }

    /// Sets the ALPS protocols to use.
    pub fn set_alps_protos<T>(&mut self, protos: T) -> &mut Self
    where
        T: Into<Option<AlpsProtos>>,
    {
        self.alps_protos = protos.into();
        self
    }

    /// Enables or disables the use of a new codepoint for ALPS.
    pub fn set_alps_use_new_codepoint(&mut self, enabled: bool) -> &mut Self {
        self.alps_use_new_codepoint = enabled;
        self
    }

    /// Enables or disables TLS session tickets.
    pub fn set_session_ticket(&mut self, enabled: bool) -> &mut Self {
        self.session_ticket = enabled;
        self
    }

    /// Sets the minimum TLS version to use.
    pub fn set_min_tls_version<T>(&mut self, version: T) -> &mut Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.min_tls_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    pub fn set_max_tls_version<T>(&mut self, version: T) -> &mut Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.max_tls_version = version.into();
        self
    }

    /// Enables or disables pre-shared key authentication.
    pub fn set_pre_shared_key(&mut self, enabled: bool) -> &mut Self {
        self.pre_shared_key = enabled;
        self
    }

    /// Enables or disables GREASE ECH extension.
    pub fn set_enable_ech_grease(&mut self, enabled: bool) -> &mut Self {
        self.enable_ech_grease = enabled;
        self
    }

    /// Sets whether ClientHello extensions should be permuted.
    pub fn set_permute_extensions<T>(&mut self, permute: T) -> &mut Self
    where
        T: Into<Option<bool>>,
    {
        self.permute_extensions = permute.into();
        self
    }

    /// Enables or disables GREASE for the context.
    pub fn set_grease_enabled<T>(&mut self, enabled: T) -> &mut Self
    where
        T: Into<Option<bool>>,
    {
        self.grease_enabled = enabled.into();
        self
    }

    /// Enables or disables OCSP stapling.
    pub fn set_enable_ocsp_stapling(&mut self, enabled: bool) -> &mut Self {
        self.enable_ocsp_stapling = enabled;
        self
    }

    /// Enables or disables sending signed certificate timestamps.
    pub fn set_enable_signed_cert_timestamps(&mut self, enabled: bool) -> &mut Self {
        self.enable_signed_cert_timestamps = enabled;
        self
    }

    /// Sets the record size limit.
    pub fn set_record_size_limit<U: Into<Option<u16>>>(&mut self, limit: U) -> &mut Self {
        self.record_size_limit = limit.into();
        self
    }

    /// Enables or disables PSK session ticket skipping.
    pub fn set_psk_skip_session_ticket(&mut self, skip: bool) -> &mut Self {
        self.psk_skip_session_ticket = skip;
        self
    }

    /// Sets the key shares length limit.
    pub fn set_key_shares_limit<T>(&mut self, limit: T) -> &mut Self
    where
        T: Into<Option<u8>>,
    {
        self.key_shares_limit = limit.into();
        self
    }

    /// Enables or disables PSK with DHE key establishment.
    pub fn set_psk_dhe_ke(&mut self, enabled: bool) -> &mut Self {
        self.psk_dhe_ke = enabled;
        self
    }

    /// Enables or disables SSL renegotiation.
    pub fn set_renegotiation(&mut self, enabled: bool) -> &mut Self {
        self.renegotiation = enabled;
        self
    }

    /// Sets the delegated credentials to use.
    pub fn set_delegated_credentials<T>(&mut self, creds: T) -> &mut Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.delegated_credentials = Some(creds.into());
        self
    }

    /// Sets the cipher list to use.
    pub fn set_cipher_list<T>(&mut self, ciphers: T) -> &mut Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.cipher_list = Some(ciphers.into());
        self
    }

    /// Sets the supported curves.
    pub fn set_curves<T>(&mut self, curves: T) -> &mut Self
    where
        T: Into<Cow<'static, [SslCurve]>>,
    {
        self.curves = Some(curves.into());
        self
    }

    /// Sets the supported signature algorithms.
    pub fn set_sigalgs_list<T>(&mut self, sigalgs: T) -> &mut Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.sigalgs_list = Some(sigalgs.into());
        self
    }

    /// Sets the certificate compression algorithms.
    pub fn set_cert_compression_algorithm<T>(&mut self, algs: T) -> &mut Self
    where
        T: IntoCertCompressionAlgorithm,
    {
        self.cert_compression_algorithm = algs.into();
        self
    }

    /// Sets the extension permutation indices.
    pub fn set_extension_permutation_indices<T>(&mut self, indices: T) -> &mut Self
    where
        T: Into<Cow<'static, [u8]>>,
    {
        self.extension_permutation_indices = Some(indices.into());
        self
    }

    /// Sets whether the AES hardware override should be enabled.
    pub fn set_aes_hw_override<T>(&mut self, enabled: T) -> &mut Self
    where
        T: Into<Option<bool>>,
    {
        self.aes_hw_override = enabled.into();
        self
    }

    /// Sets whether the random AES hardware override should be enabled.
    pub fn set_random_aes_hw_override(&mut self, enabled: bool) -> &mut Self {
        self.random_aes_hw_override = enabled;
        self
    }
}

/// A trait for converting various types into an optional `Cow` containing a `CertStore`.
///
/// This trait is used to provide a unified way to convert different types
/// into an optional `Cow` containing a `CertStore`.
pub trait IntoCertStore {
    /// Converts the given value into an optional `Cow` containing a `CertStore`.
    fn into(self) -> Option<Cow<'static, CertStore>>;
}

macro_rules! impl_into_cert_store {
    ($($t:ty => $body:expr),* $(,)?) => {
        $(impl IntoCertStore for $t {
            fn into(self) -> Option<Cow<'static, CertStore>> {
                $body(self)
            }
        })*
    };
}

impl_into_cert_store!(
    &'static CertStore => |s| Some(Cow::Borrowed(s)),
    CertStore => |s| Some(Cow::Owned(s))
);

impl<T: IntoCertStore> IntoCertStore for Option<T> {
    fn into(self) -> Option<Cow<'static, CertStore>> {
        self.and_then(|v| v.into())
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
