#![allow(missing_debug_implementations)]
use super::{impersonate::Impersonate, Version};
use crate::client::http::HttpVersionPref;
use boring::ssl::SslConnectorBuilder;
use http::HeaderMap;
use hyper::{PseudoOrder, SettingsOrder};
use std::path::PathBuf;
use typed_builder::TypedBuilder;
use Impersonate::*;
use PseudoOrder::*;
use SettingsOrder::*;

/// The TLS connector configuration.
pub struct TlsConnectorBuilder {
    /// Verify certificates.
    pub(crate) certs_verification: bool,

    /// CA certificates file path.
    pub(crate) ca_cert_file: Option<PathBuf>,

    /// The SSL connector builder.
    pub(crate) builder: Option<(SslConnectorBuilder, TlsExtensionSettings)>,
}

// ============= SslSettings impls =============
impl Default for TlsConnectorBuilder {
    fn default() -> Self {
        Self {
            certs_verification: true,
            ca_cert_file: None,
            builder: None,
        }
    }
}

// ============= Tls impls =============
impl TlsConnectorBuilder {
    pub fn permute_extensions(&mut self) {
        self.builder
            .as_mut()
            .map(|(_, ext)| ext.permute_extensions = true);
    }

    pub fn pre_shared_key(&mut self) {
        self.builder
            .as_mut()
            .map(|(_, ext)| ext.pre_shared_key = true);
    }

    pub fn enable_ech_grease(&mut self) {
        self.builder
            .as_mut()
            .map(|(_, ext)| ext.enable_ech_grease = true);
    }

    pub fn http_version_pref(&mut self, version: HttpVersionPref) {
        self.builder
            .as_mut()
            .map(|(_, ext)| ext.http_version_pref = version);
    }

    pub fn min_tls_version(&mut self, version: Version) {
        self.builder
            .as_mut()
            .map(|(_, ext)| ext.min_tls_version = Some(version));
    }

    pub fn max_tls_version(&mut self, version: Version) {
        self.builder
            .as_mut()
            .map(|(_, ext)| ext.max_tls_version = Some(version));
    }

    pub fn tls_sni(&mut self, tls_sni: bool) {
        self.builder.as_mut().map(|(_, ext)| ext.tls_sni = tls_sni);
    }
}

/// TLS Extension settings.
#[derive(Clone, Copy, TypedBuilder)]
pub struct TlsExtensionSettings {
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

/// HTTP/2 settings.
#[derive(TypedBuilder)]
pub struct Http2Settings {
    /// The initial stream window size.
    #[builder(default, setter(into))]
    pub(crate) initial_stream_window_size: Option<u32>,

    /// The initial connection window size.
    #[builder(default, setter(into))]
    pub(crate) initial_connection_window_size: Option<u32>,

    /// The maximum concurrent streams.
    #[builder(default, setter(into))]
    pub(crate) max_concurrent_streams: Option<u32>,

    /// The maximum header list size.
    #[builder(default, setter(into))]
    pub(crate) max_header_list_size: Option<u32>,

    /// The header table size.
    #[builder(default, setter(into))]
    pub(crate) header_table_size: Option<u32>,

    /// Enable push.
    #[builder(default, setter(into))]
    pub(crate) enable_push: Option<bool>,

    /// Unknown setting8.
    #[builder(default, setter(into))]
    pub(crate) unknown_setting8: Option<bool>,

    /// Unknown setting9.
    #[builder(default, setter(into))]
    pub(crate) unknown_setting9: Option<bool>,

    /// The priority of the headers.
    #[builder(default, setter(into))]
    pub(crate) headers_priority: Option<(u32, u8, bool)>,

    /// The pseudo header order.
    #[builder(default, setter(into))]
    pub(crate) headers_pseudo_order: Option<[PseudoOrder; 4]>,

    /// The settings order.
    #[builder(default, setter(into))]
    pub(crate) settings_order: Option<Vec<SettingsOrder>>,
}

/// Impersonate Settings.
#[derive(TypedBuilder)]
pub struct ImpersonateSettings {
    /// The SSL connector builder.
    pub(crate) tls: (SslConnectorBuilder, TlsExtensionSettings),

    /// HTTP/2 settings.
    pub(crate) http2: Http2Settings,

    /// Http headers
    #[builder(default, setter(strip_option))]
    pub(crate) headers: Option<Box<dyn FnOnce(&mut HeaderMap)>>,
}

/// Impersonate config.
#[derive(TypedBuilder)]
pub struct ImpersonateConfig {
    /// TLS extension settings.
    pub(crate) tls_extension: TlsExtensionSettings,

    /// Headers frame priority.
    pub(crate) http2_headers_priority: Option<(u32, u8, bool)>,

    /// Headers frame pseudo order.
    pub(crate) http2_headers_pseudo_order: Option<[PseudoOrder; 4]>,

    /// Settings frame order.
    pub(crate) http2_settings_order: Option<Vec<SettingsOrder>>,
}

// ============= ImpersonateConfig impls =============
impl From<Impersonate> for ImpersonateConfig {
    fn from(impersonate: Impersonate) -> Self {
        let cluster = match impersonate {
            // Chrome
            Chrome100 | Chrome101 | Chrome104 | Chrome105 | Chrome106 | Chrome107 | Chrome108
            | Chrome109 | Chrome114 | Chrome116 | Chrome117 | Chrome118 | Chrome119 | Chrome120
            | Chrome123 | Chrome124 | Chrome126 | Chrome127 | Chrome128 => 0,

            // Edge
            Edge101 | Edge122 | Edge127 => 1,

            // OkHttp
            OkHttp3_9 | OkHttp3_11 | OkHttp3_13 | OkHttp3_14 | OkHttp4_9 | OkHttp4_10 | OkHttp5 => {
                2
            }

            // Safari version < 18
            SafariIos17_2 | SafariIos16_5 | SafariIos17_4_1 | Safari15_3 | Safari15_5
            | Safari15_6_1 | Safari16 | Safari16_5 | Safari17_0 | Safari17_2_1 | Safari17_4_1
            | Safari17_5 => 3,

            // Safari version >= 18
            Safari18 => 4,
        };

        // Enable application settings.
        let application_settings = matches!(cluster, 0 | 1);

        // Enable pre-shared key.
        let pre_shared_key = matches!(
            impersonate,
            Chrome116
                | Chrome117
                | Chrome120
                | Chrome123
                | Chrome124
                | Chrome126
                | Chrome127
                | Chrome128
                | Edge122
                | Edge127
        );

        // The headers frame priority.
        let headers_priority = {
            let set = match cluster {
                0..=2 | 4 => Some((255, true)),
                3 => Some((254, false)),
                _ => None,
            };

            set.map(|(stream_id, exclusive)| (0, stream_id, exclusive))
        };

        // The headers frame pseudo order.
        let headers_pseudo_order = {
            match cluster {
                0 | 1 => Some([Method, Authority, Scheme, Path]),
                2 => Some([Method, Path, Authority, Scheme]),
                3 => Some([Method, Scheme, Path, Authority]),
                4 => Some([Method, Scheme, Authority, Path]),
                _ => None,
            }
        };

        // The settings frame order.
        let settings_order = {
            match cluster {
                0..=2 => Some(vec![
                    HeaderTableSize,
                    EnablePush,
                    MaxConcurrentStreams,
                    InitialWindowSize,
                    MaxFrameSize,
                    MaxHeaderListSize,
                    EnableConnectProtocol,
                ]),
                3 => Some(vec![
                    HeaderTableSize,
                    EnablePush,
                    InitialWindowSize,
                    MaxConcurrentStreams,
                    MaxFrameSize,
                    MaxHeaderListSize,
                    EnableConnectProtocol,
                ]),
                4 => Some(vec![
                    HeaderTableSize,
                    EnablePush,
                    MaxConcurrentStreams,
                    InitialWindowSize,
                    MaxFrameSize,
                    MaxHeaderListSize,
                    EnableConnectProtocol,
                    UnknownSetting8,
                    UnknownSetting9,
                ]),
                _ => None,
            }
        };

        Self::builder()
            .tls_extension(
                TlsExtensionSettings::builder()
                    .http_version_pref(HttpVersionPref::All)
                    .application_settings(application_settings)
                    .pre_shared_key(pre_shared_key)
                    .build(),
            )
            .http2_settings_order(settings_order)
            .http2_headers_priority(headers_priority)
            .http2_headers_pseudo_order(headers_pseudo_order)
            .build()
    }
}
