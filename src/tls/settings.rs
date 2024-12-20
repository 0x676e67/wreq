#![allow(missing_debug_implementations)]
use std::borrow::Cow;

use crate::{
    impl_debug,
    tls::{cert_compression::CertCompressionAlgorithm, TlsVersion},
    HttpVersionPref,
};
use boring::{
    ssl::{ExtensionType, SslConnectorBuilder, SslCurve},
    x509::store::X509Store,
};
use http::{HeaderMap, HeaderName};
use hyper::{PseudoOrder, SettingsOrder};
use typed_builder::TypedBuilder;

/// Impersonate Settings.
#[derive(TypedBuilder, Debug)]
pub struct ImpersonateSettings {
    /// The SSL connector builder.
    pub(crate) tls: TlsSettings,

    /// HTTP/2 settings.
    pub(crate) http2: Http2Settings,

    /// Http headers
    #[builder(default, setter(into))]
    pub(crate) headers: Option<Cow<'static, HeaderMap>>,

    /// Http headers order
    #[builder(default, setter(strip_option))]
    pub(crate) headers_order: Option<Cow<'static, [HeaderName]>>,
}

/// A root certificates store.
#[derive(Default)]
pub enum RootCertsStore {
    /// Use the default root certificates store.
    Owned(X509Store),

    /// Use the custom root certificates store.
    Borrowed(&'static X509Store),

    /// No root certificates store.
    #[default]
    None,
}

impl RootCertsStore {
    pub fn is_none(&self) -> bool {
        matches!(self, RootCertsStore::None)
    }
}

macro_rules! impl_root_cert_store {
    ($($type:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$type> for RootCertsStore {
                fn from(store: $type) -> Self {
                    Self::$variant(store)
                }
            }
        )*
    };

    ($($type:ty => $variant:ident, $unwrap:expr),* $(,)?) => {
        $(
            impl From<$type> for RootCertsStore {
                fn from(store: $type) -> Self {
                    $unwrap(store).map(Self::$variant).unwrap_or_default()
                }
            }
        )*
    };
}

impl_root_cert_store!(
    X509Store => Owned,
    &'static X509Store => Borrowed,
);

impl_root_cert_store!(
    Option<X509Store> => Owned, |s| s,
    Option<&'static X509Store> => Borrowed, |s| s,
);

impl<F> From<F> for RootCertsStore
where
    F: Fn() -> Option<&'static X509Store>,
{
    fn from(func: F) -> Self {
        func().map(Self::Borrowed).unwrap_or_default()
    }
}

// ============== TLS ==============
#[derive(TypedBuilder, Default)]
pub struct TlsSettings {
    /// The TLS connector builder.
    #[builder(default, setter(strip_option))]
    pub connector: Option<SslConnectorBuilder>,

    /// Root certificates store.
    #[builder(default)]
    pub root_certs_store: RootCertsStore,

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

    /// The delegated credentials algorithm to use.
    #[builder(default, setter(into))]
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// The cipher list to use.
    #[builder(default, setter(into))]
    pub cipher_list: Option<Cow<'static, str>>,

    /// Enable signed cert timestamps.
    #[builder(default = false)]
    pub enable_signed_cert_timestamps: bool,

    /// The certificate compression algorithm to use.
    #[builder(default, setter(into))]
    pub cert_compression_algorithm: Option<Cow<'static, [CertCompressionAlgorithm]>>,

    /// Set record size limit.
    #[builder(default, setter(into))]
    pub record_size_limit: Option<u16>,

    /// PSk with no session ticket.
    #[builder(default = false)]
    pub psk_skip_session_ticket: bool,

    /// The key shares length limit.
    #[builder(default, setter(into))]
    pub key_shares_length_limit: Option<u8>,

    /// The extension permutation.
    #[builder(default, setter(into))]
    pub extension_permutation: Option<Cow<'static, [ExtensionType]>>,
}

impl_debug!(
    TlsSettings,
    {
        certs_verification,
        tls_sni,
        alpn_protos,
        session_ticket,
        min_tls_version,
        max_tls_version,
        application_settings,
        pre_shared_key,
        enable_ech_grease,
        permute_extensions,
        grease_enabled,
        enable_ocsp_stapling,
        curves,
        sigalgs_list,
        cipher_list,
        enable_signed_cert_timestamps,
        cert_compression_algorithm,
        record_size_limit,
        key_shares_length_limit,
        psk_skip_session_ticket
    }
);

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
