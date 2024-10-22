//! TLS configuration
//!
//! By default, a `Client` will make use of BoringSSL for TLS.
//!
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.

#![allow(missing_docs)]
mod builder;
mod connector;
mod extension;
mod impersonate;

use crate::{connect::HttpConnector, HttpVersionPref};
use boring::{
    error::ErrorStack,
    ssl::{SslConnector, SslMethod},
};
pub use builder::TlsConnectorBuilder;
pub use connector::MaybeHttpsStream;
use connector::{HttpsConnector, HttpsLayer, HttpsLayerSettings};
pub use extension::cert_compression;
use extension::{TlsConnectExtension, TlsExtension};
pub use impersonate::{
    chrome, edge, http2::Http2Settings, okhttp, safari, tls::TlsSettings, tls_settings,
    Impersonate, ImpersonateSettings,
};

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
    #[cfg(feature = "websocket")]
    ws_connect_layer: ConnectLayer,
    connect_layer: ConnectLayer,
}

impl BoringTlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    pub fn new(builder: TlsConnectorBuilder) -> TlsResult<BoringTlsConnector> {
        Ok(Self {
            tls_sni: builder.tls.tls_sni,
            enable_ech_grease: builder.tls.enable_ech_grease,
            application_settings: builder.tls.application_settings,
            http_version_pref: builder.tls.http_version_pref,
            #[cfg(feature = "websocket")]
            ws_connect_layer: new_layer(&builder, true)?,
            connect_layer: new_layer(&builder, false)?,
        })
    }

    /// Create a new `HttpsConnector` with the settings from the `TlsContext`.
    #[inline]
    pub(crate) async fn from(
        &self,
        http: HttpConnector,
        ws: bool,
    ) -> HttpsConnector<HttpConnector> {
        // Create the `HttpsConnector` with the given `HttpConnector` and `ConnectLayer`.
        let mut http = HttpsConnector::with_connector_layer(
            http,
            if ws {
                #[cfg(feature = "websocket")]
                {
                    self.ws_connect_layer.clone()
                }
                #[cfg(not(feature = "websocket"))]
                {
                    self.connect_layer.clone()
                }
            } else {
                self.connect_layer.clone()
            },
        );

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

/// Create a new `ConnectLayer` with the given `Tls` settings.
fn new_layer(builder: &TlsConnectorBuilder, ws: bool) -> TlsResult<ConnectLayer> {
    let tls = builder.tls.clone();
    // If the connector builder is set, use it. Otherwise, create a new one.
    let connector = match tls.connector {
        Some(connector) => connector()?,
        None => SslConnector::builder(SslMethod::tls_client())?,
    };

    // Set websocket use http1 alpn proto
    let http_version_pref = if ws {
        HttpVersionPref::Http1
    } else {
        tls.http_version_pref
    };

    // Create the `SslConnectorBuilder` and configure it.
    let connector = connector
        .configure_cert_verification(builder.certs_verification)?
        .configure_alpn_protos(http_version_pref)?
        .configure_min_tls_version(tls.min_tls_version)?
        .configure_max_tls_version(tls.max_tls_version)?
        .configure_permute_extensions(tls.application_settings, tls.permute_extensions)?;

    // Conditionally configure the TLS builder based on the "boring-tls-native-roots" feature.
    // If no custom CA cert store, use the system's native certificate store if the feature is enabled.
    let connector = if builder.ca_cert_store.is_none() {
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
        connector.configure_ca_cert_store(builder.ca_cert_store.clone())?
    };

    // Create the `HttpsLayerSettings` with the default session cache capacity.
    let settings = HttpsLayerSettings::builder()
        .session_cache_capacity(8)
        .session_cache(tls.application_settings && tls.pre_shared_key)
        .build();

    HttpsLayer::with_connector_and_settings(connector, settings)
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
