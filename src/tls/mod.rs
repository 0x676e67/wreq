//! TLS configuration
//!
//! By default, a `Client` will make use of BoringSSL for TLS.
//!
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.

#![allow(missing_docs)]
mod builder;
mod cert_compression;
mod connector;
pub mod extension;
mod impersonate;

use crate::{connect::HttpConnector, HttpVersionPref};
use boring::{
    error::ErrorStack,
    ssl::{SslConnector, SslMethod},
};
pub use builder::TlsConnectorBuilder;
pub use connector::MaybeHttpsStream;
use connector::{HttpsConnector, HttpsLayer, HttpsLayerSettings};
use extension::{TlsConnectExtension, TlsExtension};
pub use impersonate::{
    http2::Http2Settings, tls::TlsExtensionSettings, tls_settings, Impersonate, ImpersonateSettings,
};

type TlsResult<T> = std::result::Result<T, ErrorStack>;

/// A wrapper around a `SslConnectorBuilder` that allows for additional settings.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct BoringTlsConnector {
    tls_sni: bool,
    enable_ech_grease: bool,
    application_settings: bool,
    http_version_pref: HttpVersionPref,
    layer: HttpsLayer,
}

impl BoringTlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    pub fn new(tls: TlsConnectorBuilder) -> TlsResult<BoringTlsConnector> {
        Ok(Self {
            tls_sni: tls.builder.as_ref().map_or(true, |(_, ext)| ext.tls_sni),
            enable_ech_grease: tls
                .builder
                .as_ref()
                .map_or(false, |(_, ext)| ext.enable_ech_grease),
            application_settings: tls
                .builder
                .as_ref()
                .map_or(false, |(_, ext)| ext.application_settings),
            http_version_pref: tls
                .builder
                .as_ref()
                .map_or(HttpVersionPref::All, |(_, ext)| ext.http_version_pref),
            layer: layer(tls)?,
        })
    }

    /// Create a new `HttpsConnector` with the settings from the `TlsContext`.
    #[inline]
    pub(crate) async fn from(&self, http: HttpConnector) -> HttpsConnector<HttpConnector> {
        // Create the `HttpsConnector` with the given `HttpConnector` and `HttpsLayer`.
        let mut http = HttpsConnector::with_connector_layer(http, self.layer.clone());

        // Set the callback to add application settings.
        let (application_settings, enable_ech_grease, http_version_pref, tls_sni) = (
            self.application_settings,
            self.enable_ech_grease,
            self.http_version_pref,
            self.tls_sni,
        );
        http.set_callback(move |conf, _| {
            conf.configure_enable_ech_grease(application_settings, enable_ech_grease)?
                .configure_add_application_settings(application_settings, http_version_pref)?
                .set_use_server_name_indication(tls_sni);
            Ok(())
        });

        http
    }
}

/// Create a new `HttpsLayer` with the given `Tls` settings.
fn layer(tls: TlsConnectorBuilder) -> TlsResult<HttpsLayer> {
    // If the builder is set, use it. Otherwise, create a new one.
    let (ssl, extension) = match tls.builder {
        Some(ssl) => ssl,
        None => (
            SslConnector::builder(SslMethod::tls_client())?,
            TlsExtensionSettings::builder()
                .http_version_pref(HttpVersionPref::All)
                .tls_sni(true)
                .build(),
        ),
    };

    // Create the `SslConnectorBuilder` and configure it.
    let builder = ssl
        .configure_ca_cert_file(tls.ca_cert_file)?
        .configure_cert_verification(tls.certs_verification)?
        .configure_alpn_protos(extension.http_version_pref)?
        .configure_min_tls_version(extension.min_tls_version)?
        .configure_max_tls_version(extension.max_tls_version)?
        .configure_permute_extensions(
            extension.application_settings,
            extension.permute_extensions,
        )?;

    // Create the `HttpsLayerSettings` with the default session cache capacity.
    let settings = HttpsLayerSettings::builder()
        .session_cache_capacity(8)
        .session_cache(extension.application_settings && extension.pre_shared_key)
        .build();

    HttpsLayer::with_connector_and_settings(builder, settings)
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(InnerVersion);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
enum InnerVersion {
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

// These could perhaps be From/TryFrom implementations, but those would be
// part of the public API so let's be careful
impl Version {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: Version = Version(InnerVersion::Tls1_0);
    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: Version = Version(InnerVersion::Tls1_1);
    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: Version = Version(InnerVersion::Tls1_2);
    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: Version = Version(InnerVersion::Tls1_3);
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
