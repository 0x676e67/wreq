#![allow(missing_debug_implementations)]
use crate::{
    tls::{cert_compression::CertCompressionAlgorithm, TlsResult, Version},
    HttpVersionPref,
};
use boring::ssl::{SslConnectorBuilder, SslCurve};
use typed_builder::TypedBuilder;

/// TLS Extension settings.
#[derive(TypedBuilder)]
pub struct TlsSettings {
    #[builder(default, setter(strip_option))]
    pub connector: Option<Box<dyn Fn() -> TlsResult<SslConnectorBuilder> + Send + Sync + 'static>>,

    #[builder(default = true)]
    pub tls_sni: bool,

    /// The HTTP version preference (setting alpn).
    #[builder(default = HttpVersionPref::All)]
    pub http_version_pref: HttpVersionPref,

    /// The minimum TLS version to use.
    #[builder(default, setter(into))]
    pub min_tls_version: Option<Version>,

    /// The maximum TLS version to use.
    #[builder(default, setter(into))]
    pub max_tls_version: Option<Version>,

    /// Enable application settings.
    #[builder(default = false)]
    pub application_settings: bool,

    /// Enable PSK.
    #[builder(default = false)]
    pub pre_shared_key: bool,

    /// Enable ECH grease.
    #[builder(default = false)]
    pub enable_ech_grease: bool,

    /// Permute extensions.
    #[builder(default = false)]
    pub permute_extensions: bool,

    /// Enable grease enabled.
    #[builder(default, setter(into))]
    pub grease_enabled: Option<bool>,

    /// Enable OCSP stapling.
    #[builder(default = false)]
    pub enable_ocsp_stapling: bool,

    /// The curves to use.
    #[builder(default, setter(into))]
    pub curves: Option<Vec<SslCurve>>,

    /// The signature algorithms list to use.
    #[builder(default, setter(into))]
    pub sigalgs_list: Option<String>,

    /// The cipher list to use.
    #[builder(default, setter(into))]
    pub cipher_list: Option<String>,

    /// Enable signed cert timestamps.
    #[builder(default = false)]
    pub enable_signed_cert_timestamps: bool,

    /// The certificate compression algorithm to use.
    #[builder(default, setter(into))]
    pub cert_compression_algorithm: Option<CertCompressionAlgorithm>,
}
