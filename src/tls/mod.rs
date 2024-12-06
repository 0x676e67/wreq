//! TLS configuration
//!
//! By default, a `Client` will make use of BoringSSL for TLS.
//!
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.

#![allow(missing_docs)]
mod connector;
mod extension;
mod impersonate;
mod settings;

use crate::{connect::HttpConnector, HttpVersionPref};
use boring::{
    error::ErrorStack,
    ssl::{SslConnector, SslMethod, SslOptions, SslVersion},
};
pub use connector::MaybeHttpsStream;
use connector::{HttpsConnector, HttpsLayer, HttpsLayerSettings};
pub use extension::cert_compression;
use extension::{TlsConnectExtension, TlsExtension};
pub use impersonate::{
    chrome, edge, okhttp, safari, tls_settings, Impersonate, ImpersonateSettings,
};
pub use settings::{Http2Settings, TlsSettings};

type TlsResult<T> = std::result::Result<T, ErrorStack>;
type ConnectLayer = HttpsLayer;

/// A wrapper around a `SslConnectorBuilder` that allows for additional settings.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct BoringTlsConnector {
    tls_sni: bool,
    enable_ech_grease: bool,
    application_settings: bool,
    http_version_pref: HttpVersionPref,
    connect_layer: ConnectLayer,
}

impl BoringTlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    pub fn new(settings: TlsSettings) -> TlsResult<BoringTlsConnector> {
        Ok(Self {
            tls_sni: settings.tls_sni,
            enable_ech_grease: settings.enable_ech_grease,
            application_settings: settings.application_settings,
            http_version_pref: settings.http_version_pref,
            connect_layer: create_connect_layer(settings)?,
        })
    }

    /// Create a new `HttpsConnector` with the settings from the `HttpConnector`.
    #[inline]
    pub(crate) async fn create_connector(
        &self,
        http: HttpConnector,
        ws: bool,
    ) -> HttpsConnector<HttpConnector> {
        // Create the `HttpsConnector` with the given `HttpConnector` and `ConnectLayer`.
        let mut http = HttpsConnector::with_connector_layer(http, self.connect_layer.clone());

        // Set the callback to add application settings.
        let (application_settings, enable_ech_grease, http_version_pref, tls_sni) = (
            self.application_settings,
            self.enable_ech_grease,
            self.http_version_pref,
            self.tls_sni,
        );
        http.set_callback(move |conf, _| {
            conf.configure_enable_ech_grease(enable_ech_grease)?
                .set_verify_hostname(tls_sni);

            // Add application settings if it is set.
            if application_settings {
                conf.configure_add_application_settings(http_version_pref)?;
            }

            // Set websocket use http1 alpn proto
            if ws {
                conf.set_alpn_protos(b"\x08http/1.1")?;
            }

            Ok(())
        });

        http
    }
}

/// Create a new `ConnectLayer` with the given `Tls` settings.
#[inline]
fn create_connect_layer(settings: TlsSettings) -> TlsResult<ConnectLayer> {
    let tls = &settings;

    // If the connector builder is set, use it. Otherwise, create a new one.
    let connector = match &tls.connector {
        Some(connector) => connector()?,
        None => SslConnector::builder(SslMethod::tls_client())?,
    };

    // Create the `SslConnectorBuilder` and configure it.
    let mut connector = connector
        .configure_cert_verification(settings.certs_verification)?
        .configure_alpn_protos(settings.http_version_pref)?
        .configure_min_tls_version(tls.min_tls_version)?
        .configure_max_tls_version(tls.max_tls_version)?;

    // Set enable ocsp stapling if it is set.
    if tls.enable_ocsp_stapling {
        connector.enable_ocsp_stapling();
    }

    // Set enable signed cert timestamps if it is set.
    if tls.enable_signed_cert_timestamps {
        connector.enable_signed_cert_timestamps();
    }

    // Set no session ticket if it is set.
    if let Some(false) = tls.session_ticket {
        connector.set_options(SslOptions::NO_TICKET);
    }

    // Set grease enabled if it is set.
    if let Some(grease_enabled) = tls.grease_enabled {
        connector.set_grease_enabled(grease_enabled);
    }

    // Set permute extensions if it is set.
    if let Some(permute_extensions) = tls.permute_extensions {
        connector.set_permute_extensions(permute_extensions);
    }

    // Set the curves if they are set.
    if let Some(curves) = tls.curves.as_deref() {
        connector.set_curves(curves)?;
    }

    // Set the signature algorithms list if it is set.
    if let Some(sigalgs_list) = tls.sigalgs_list.as_deref() {
        connector.set_sigalgs_list(sigalgs_list)?;
    }

    // Set the cipher list if it is set.
    if let Some(cipher_list) = tls.cipher_list.as_deref() {
        connector.set_cipher_list(cipher_list)?;
    }

    // Set the certificate compression algorithm if it is set.
    if let Some(cert_compression_algorithm) = tls.cert_compression_algorithm {
        connector = connector.configure_add_cert_compression_alg(cert_compression_algorithm)?;
    }

    // Conditionally configure the TLS builder based on the "boring-tls-native-roots" feature.
    // If no custom CA cert store, use the system's native certificate store if the feature is enabled.
    let connector = if settings.ca_cert_store.is_none() {
        #[cfg(feature = "boring-tls-webpki-roots")]
        {
            // WebPKI root certificates are enabled (regardless of whether native-roots is also enabled).
            connector.configure_set_webpki_verify_cert_store()?
        }

        #[cfg(all(
            feature = "boring-tls-native-roots",
            not(feature = "boring-tls-webpki-roots")
        ))]
        {
            // Only native-roots is enabled, WebPKI is not enabled.
            connector.configure_set_native_verify_cert_store()?
        }

        #[cfg(not(any(
            feature = "boring-tls-native-roots",
            feature = "boring-tls-webpki-roots"
        )))]
        {
            // Neither native-roots nor WebPKI roots are enabled, proceed with the default builder.
            connector
        }
    } else {
        // If a custom CA certificate store is provided, configure it.
        connector.configure_ca_cert_store(settings.ca_cert_store.as_deref())?
    };

    // Create the `HttpsLayerSettings` with the default session cache capacity.
    let settings = HttpsLayerSettings::builder()
        .session_cache_capacity(8)
        .session_cache(tls.pre_shared_key)
        .build();

    HttpsLayer::with_connector_and_settings(connector, settings)
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version(SslVersion);

// These could perhaps be From/TryFrom implementations, but those would be
// part of the public API so let's be careful
impl Version {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: Version = Version(SslVersion::TLS1);
    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: Version = Version(SslVersion::TLS1_1);
    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: Version = Version(SslVersion::TLS1_2);
    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: Version = Version(SslVersion::TLS1_3);
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
