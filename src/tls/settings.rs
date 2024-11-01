#![allow(missing_debug_implementations)]
use crate::{
    tls::{cert_compression::CertCompressionAlgorithm, TlsResult, Version},
    HttpVersionPref,
};
use boring::{
    ssl::{SslConnectorBuilder, SslCurve},
    x509::store::X509Store,
};
use hyper::{PseudoOrder, SettingsOrder};
use typed_builder::TypedBuilder;

// ============== TLS ==============
#[derive(TypedBuilder, Default)]
pub struct TlsSettings {
    // Option TLS connector builder
    #[builder(default, setter(strip_option))]
    pub connector: Option<Box<dyn Fn() -> TlsResult<SslConnectorBuilder> + Send + Sync + 'static>>,

    /// CA certificates store.
    #[builder(default, setter(strip_option))]
    pub ca_cert_store: Option<Box<dyn Fn() -> TlsResult<X509Store> + Send + Sync + 'static>>,

    /// Verify certificates.
    #[builder(default = true)]
    pub certs_verification: bool,

    /// Enable TLS SNI
    #[builder(default = true)]
    pub tls_sni: bool,

    /// The HTTP version preference (setting alpn).
    #[builder(default = HttpVersionPref::All)]
    pub http_version_pref: HttpVersionPref,

    /// No session ticket
    #[builder(default = false)]
    pub no_session_ticket: bool,

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

// ============== http2 ==============
#[derive(TypedBuilder, Debug)]
pub struct Http2Settings {
    // ============== windows update frame ==============
    /// The initial connection window size.
    #[builder(default, setter(into))]
    pub initial_connection_window_size: Option<u32>,

    // ============== settings frame ==============
    /// The header table size.
    #[builder(default, setter(into))]
    pub header_table_size: Option<u32>,

    /// Enable push.
    #[builder(default, setter(into))]
    pub enable_push: Option<bool>,

    /// The maximum concurrent streams.
    #[builder(default, setter(into))]
    pub max_concurrent_streams: Option<u32>,

    /// The initial stream window size.
    #[builder(default, setter(into))]
    pub initial_stream_window_size: Option<u32>,

    /// The max frame size
    #[builder(default, setter(into))]
    pub max_frame_size: Option<u32>,

    /// The maximum header list size.
    #[builder(default, setter(into))]
    pub max_header_list_size: Option<u32>,

    /// Unknown setting8.
    #[builder(default, setter(into))]
    pub unknown_setting8: Option<bool>,

    /// Unknown setting9.
    #[builder(default, setter(into))]
    pub unknown_setting9: Option<bool>,

    /// The settings order.
    #[builder(default, setter(strip_option))]
    pub settings_order: Option<[SettingsOrder; 8]>,

    // ============== headers frame ==============
    /// The priority of the headers.
    #[builder(default, setter(into))]
    pub headers_priority: Option<(u32, u8, bool)>,

    /// The pseudo header order.
    #[builder(default, setter(into))]
    pub headers_pseudo_order: Option<[PseudoOrder; 4]>,
}
