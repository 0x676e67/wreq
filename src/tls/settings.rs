#![allow(missing_debug_implementations)]
use std::borrow::Cow;

use crate::{
    tls::{cert_compression::CertCompressionAlgorithm, TlsVersion},
    HttpVersionPref,
};
use boring::{
    ssl::{SslConnectorBuilder, SslCurve},
    x509::store::X509StoreRef,
};
use hyper::{PseudoOrder, SettingsOrder};
use typed_builder::TypedBuilder;

/// A root certificates store.
pub type RootCertsStore = fn() -> Option<&'static X509StoreRef>;

// ============== TLS ==============
#[derive(TypedBuilder, Default)]
pub struct TlsSettings {
    /// The TLS connector builder.
    #[builder(default, setter(strip_option))]
    pub connector: Option<SslConnectorBuilder>,

    /// Root certificates store.
    #[builder(default, setter(strip_option))]
    pub root_certs_store: Option<RootCertsStore>,

    /// Verify certificates.
    #[builder(default = true)]
    pub certs_verification: bool,

    /// Enable TLS SNI
    #[builder(default = true)]
    pub tls_sni: bool,

    /// The HTTP version preference (setting alpn).
    #[builder(default = HttpVersionPref::All)]
    pub alpn_protos: HttpVersionPref,

    /// No session ticket
    #[builder(default, setter(into))]
    pub session_ticket: Option<bool>,

    /// The minimum TLS version to use.
    #[builder(default, setter(into))]
    pub min_tls_version: Option<TlsVersion>,

    /// The maximum TLS version to use.
    #[builder(default, setter(into))]
    pub max_tls_version: Option<TlsVersion>,

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
    #[builder(default, setter(into))]
    pub permute_extensions: Option<bool>,

    /// Enable grease enabled.
    #[builder(default, setter(into))]
    pub grease_enabled: Option<bool>,

    /// Enable OCSP stapling.
    #[builder(default = false)]
    pub enable_ocsp_stapling: bool,

    /// The curves to use.
    #[builder(default, setter(into))]
    pub curves: Option<Cow<'static, [SslCurve]>>,

    /// The signature algorithms list to use.
    #[builder(default, setter(into))]
    pub sigalgs_list: Option<Cow<'static, str>>,

    /// The cipher list to use.
    #[builder(default, setter(into))]
    pub cipher_list: Option<Cow<'static, str>>,

    /// Enable signed cert timestamps.
    #[builder(default = false)]
    pub enable_signed_cert_timestamps: bool,

    /// The certificate compression algorithm to use.
    #[builder(default, setter(into))]
    pub cert_compression_algorithm: Option<CertCompressionAlgorithm>,
}

impl std::fmt::Debug for TlsSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsSettings")
            .field("certs_verification", &self.certs_verification)
            .field("tls_sni", &self.tls_sni)
            .field("http_version_pref", &self.alpn_protos)
            .field("session_ticket", &self.session_ticket)
            .field("min_tls_version", &self.min_tls_version)
            .field("max_tls_version", &self.max_tls_version)
            .field("application_settings", &self.application_settings)
            .field("pre_shared_key", &self.pre_shared_key)
            .field("enable_ech_grease", &self.enable_ech_grease)
            .field("permute_extensions", &self.permute_extensions)
            .field("grease_enabled", &self.grease_enabled)
            .field("enable_ocsp_stapling", &self.enable_ocsp_stapling)
            .field("curves", &self.curves)
            .field("sigalgs_list", &self.sigalgs_list)
            .field("cipher_list", &self.cipher_list)
            .field(
                "enable_signed_cert_timestamps",
                &self.enable_signed_cert_timestamps,
            )
            .field(
                "cert_compression_algorithm",
                &self.cert_compression_algorithm,
            )
            .finish()
    }
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
