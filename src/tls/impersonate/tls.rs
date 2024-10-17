#![allow(missing_debug_implementations)]
use crate::{tls::Version, HttpVersionPref};
use boring::ssl::SslConnectorBuilder;
use typed_builder::TypedBuilder;

/// TLS Extension settings.
#[derive(TypedBuilder)]
pub struct TlsSettings {
    #[builder(default, setter(into))]
    pub(crate) connector: Option<SslConnectorBuilder>,

    #[builder(default = true)]
    pub(crate) tls_sni: bool,

    /// The HTTP version preference (setting alpn).
    #[builder(default = HttpVersionPref::All)]
    pub(crate) http_version_pref: HttpVersionPref,

    /// The minimum TLS version to use.
    #[builder(default)]
    pub(crate) min_tls_version: Option<Version>,

    /// The maximum TLS version to use.
    #[builder(default)]
    pub(crate) max_tls_version: Option<Version>,

    /// Enable application settings.
    #[builder(default = false)]
    pub(crate) application_settings: bool,

    /// Enable PSK.
    #[builder(default = false)]
    pub(crate) pre_shared_key: bool,

    /// Enable ECH grease.
    #[builder(default = false)]
    pub(crate) enable_ech_grease: bool,

    /// Permute extensions.
    #[builder(default = false)]
    pub(crate) permute_extensions: bool,
}
