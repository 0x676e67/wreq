use crate::{
    impl_debug,
    tls::{cert_compression::CertCompressionAlgorithm, TlsVersion},
    HttpVersionPref,
};
use boring::{ssl::SslCurve, x509::store::X509Store};
use http::{HeaderMap, HeaderName};
use hyper2::{Priority, PseudoOrder, SettingsOrder};
use std::borrow::Cow;
use typed_builder::TypedBuilder;

#[derive(TypedBuilder, Debug)]
pub struct ImpersonateSettings {
    pub(crate) tls: TlsSettings,

    pub(crate) http2: Http2Settings,

    #[builder(default, setter(into))]
    pub(crate) headers: Option<Cow<'static, HeaderMap>>,

    #[builder(default, setter(into))]
    pub(crate) headers_order: Option<Cow<'static, [HeaderName]>>,
}

#[derive(Default)]
pub enum RootCertsStore {
    Owned(X509Store),

    Borrowed(&'static X509Store),

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

#[derive(TypedBuilder, Default)]
pub struct TlsSettings {
    #[builder(default)]
    pub root_certs_store: RootCertsStore,

    #[builder(default = true)]
    pub certs_verification: bool,

    #[builder(default = true)]
    pub tls_sni: bool,

    #[builder(default = true)]
    pub verify_hostname: bool,

    #[builder(default = HttpVersionPref::All)]
    pub alpn_protos: HttpVersionPref,

    #[builder(default = true)]
    pub session_ticket: bool,

    #[builder(default, setter(into))]
    pub min_tls_version: Option<TlsVersion>,

    #[builder(default, setter(into))]
    pub max_tls_version: Option<TlsVersion>,

    #[builder(default = false)]
    pub application_settings: bool,

    #[builder(default = false)]
    pub pre_shared_key: bool,

    #[builder(default = false)]
    pub enable_ech_grease: bool,

    #[builder(default, setter(into))]
    pub permute_extensions: Option<bool>,

    #[builder(default, setter(into))]
    pub grease_enabled: Option<bool>,

    #[builder(default = false)]
    pub enable_ocsp_stapling: bool,

    #[builder(default, setter(into))]
    pub curves: Option<Cow<'static, [SslCurve]>>,

    #[builder(default, setter(into))]
    pub sigalgs_list: Option<Cow<'static, str>>,

    #[builder(default, setter(into))]
    pub delegated_credentials: Option<Cow<'static, str>>,

    #[builder(default, setter(into))]
    pub cipher_list: Option<Cow<'static, str>>,

    #[builder(default = false)]
    pub enable_signed_cert_timestamps: bool,

    #[builder(default, setter(into))]
    pub cert_compression_algorithm: Option<Cow<'static, [CertCompressionAlgorithm]>>,

    #[builder(default, setter(into))]
    pub record_size_limit: Option<u16>,

    #[builder(default = false)]
    pub psk_skip_session_ticket: bool,

    #[builder(default, setter(into))]
    pub key_shares_length_limit: Option<u8>,

    #[builder(default, setter(into))]
    pub extension_permutation_indices: Option<Cow<'static, [u8]>>,
}

impl_debug!(
    TlsSettings,
    {
        certs_verification,
        tls_sni,
        verify_hostname,
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
        psk_skip_session_ticket,
        extension_permutation_indices
    }
);

#[derive(TypedBuilder, Debug)]
pub struct Http2Settings {
    #[builder(default, setter(into))]
    pub initial_stream_id: Option<u32>,

    // ============== windows update frame ==============
    #[builder(default, setter(into))]
    pub initial_connection_window_size: Option<u32>,

    // ============== settings frame ==============
    #[builder(default, setter(into))]
    pub header_table_size: Option<u32>,

    #[builder(default, setter(into))]
    pub enable_push: Option<bool>,

    #[builder(default, setter(into))]
    pub max_concurrent_streams: Option<u32>,

    #[builder(default, setter(into))]
    pub initial_stream_window_size: Option<u32>,

    #[builder(default, setter(into))]
    pub max_frame_size: Option<u32>,

    #[builder(default, setter(into))]
    pub max_header_list_size: Option<u32>,

    #[builder(default, setter(into))]
    pub unknown_setting8: Option<bool>,

    #[builder(default, setter(into))]
    pub unknown_setting9: Option<bool>,

    #[builder(default, setter(strip_option))]
    pub settings_order: Option<[SettingsOrder; 8]>,

    // ============== headers frame ==============
    #[builder(default, setter(into))]
    pub headers_priority: Option<(u32, u8, bool)>,

    #[builder(default, setter(into))]
    pub headers_pseudo_order: Option<[PseudoOrder; 4]>,

    // ============== priority ==============
    #[builder(default, setter(into))]
    pub priority: Option<Cow<'static, [Priority]>>,
}
