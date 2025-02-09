//! TLS configuration
//!
//! By default, a `Client` will make use of BoringSSL for TLS.
//!
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.

mod cert;
mod conf;
mod conn;
mod ext;

use boring2::{
    error::ErrorStack,
    ssl::{SslConnector, SslMethod, SslOptions, SslVersion},
};
use conn::{HttpsLayer, HttpsLayerSettings};

pub use self::conn::{HttpsConnector, MaybeHttpsStream};
pub use self::ext::{ConnectConfigurationExt, SslConnectorBuilderExt, SslRefExt};
pub use self::{
    cert::{RootCertStore, RootCertStoreProvider},
    conf::TlsConfig,
};

type TlsResult<T> = Result<T, ErrorStack>;

/// A wrapper around a `HttpsLayer` that allows for additional config.
#[derive(Clone)]
pub(crate) struct BoringTlsConnector(HttpsLayer);

impl BoringTlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    #[inline]
    pub fn new(config: TlsConfig) -> TlsResult<BoringTlsConnector> {
        let mut connector = SslConnector::no_default_verify_builder(SslMethod::tls_client())?
            .root_cert_store(config.root_certs_store)?
            .cert_verification(config.certs_verification)?
            .alpn_protos(config.alpn_protos)?
            .min_tls_version(config.min_tls_version)?
            .max_tls_version(config.max_tls_version)?;

        if config.enable_ocsp_stapling {
            connector.enable_ocsp_stapling();
        }

        if config.enable_signed_cert_timestamps {
            connector.enable_signed_cert_timestamps();
        }

        if !config.session_ticket {
            connector.set_options(SslOptions::NO_TICKET);
        }

        if !config.psk_dhe_ke {
            connector.set_options(SslOptions::NO_PSK_DHE_KE);
        }

        if !config.renegotiation {
            connector.set_options(SslOptions::NO_RENEGOTIATION);
        }

        if let Some(grease_enabled) = config.grease_enabled {
            connector.set_grease_enabled(grease_enabled);
        }

        if let Some(permute_extensions) = config.permute_extensions {
            connector.set_permute_extensions(permute_extensions);
        }

        if let Some(curves) = config.curves.as_deref() {
            connector.set_curves(curves)?;
        }

        if let Some(sigalgs_list) = config.sigalgs_list.as_deref() {
            connector.set_sigalgs_list(sigalgs_list)?;
        }

        if let Some(delegated_credentials) = config.delegated_credentials.as_deref() {
            connector.set_delegated_credentials(delegated_credentials)?;
        }

        if let Some(cipher_list) = config.cipher_list.as_deref() {
            connector.set_cipher_list(cipher_list)?;
        }

        if let Some(cert_compression_algorithm) = config.cert_compression_algorithm {
            for algorithm in cert_compression_algorithm.iter() {
                connector = connector.add_cert_compression_algorithm(*algorithm)?;
            }
        }

        if let Some(record_size_limit) = config.record_size_limit {
            connector.set_record_size_limit(record_size_limit);
        }

        if let Some(limit) = config.key_shares_limit {
            connector.set_key_shares_limit(limit);
        }

        if let Some(indices) = config.extension_permutation_indices {
            connector.set_extension_permutation_indices(indices.as_ref())?;
        }

        // Create the `HttpsLayerSettings` with the default session cache capacity.
        let settings = HttpsLayerSettings::builder()
            .session_cache(config.pre_shared_key)
            .skip_session_ticket(config.psk_skip_session_ticket)
            .alpn_protos(config.alpn_protos)
            .alps_protos(config.alps_protos)
            .alps_use_new_codepoint(config.alps_use_new_codepoint)
            .enable_ech_grease(config.enable_ech_grease)
            .tls_sni(config.tls_sni)
            .verify_hostname(config.verify_hostname)
            .build();

        Ok(Self(HttpsLayer::with_connector_and_settings(
            connector, settings,
        )))
    }
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsVersion(SslVersion);

// These could perhaps be From/TryFrom implementations, but those would be
// part of the public API so let's be careful
impl TlsVersion {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: TlsVersion = TlsVersion(SslVersion::TLS1);
    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: TlsVersion = TlsVersion(SslVersion::TLS1_1);
    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: TlsVersion = TlsVersion(SslVersion::TLS1_2);
    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: TlsVersion = TlsVersion(SslVersion::TLS1_3);
}

/// A TLS ALPN protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlpnProtos(&'static [u8]);

/// A `AlpnProtos` is used to set the HTTP version preference.
impl AlpnProtos {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpnProtos = AlpnProtos(b"\x08http/1.1");
    /// Prefer HTTP/2
    pub const HTTP2: AlpnProtos = AlpnProtos(b"\x02h2");
    /// Prefer HTTP/1 and HTTP/2
    pub const ALL: AlpnProtos = AlpnProtos(b"\x02h2\x08http/1.1");
}

impl Default for AlpnProtos {
    fn default() -> Self {
        Self::ALL
    }
}

/// Application-layer protocol settings for HTTP/1.1 and HTTP/2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlpsProtos(&'static [u8]);

impl AlpsProtos {
    /// Application Settings protocol for HTTP/1.1
    pub const HTTP1: AlpsProtos = AlpsProtos(b"http/1.1");
    /// Application Settings protocol for HTTP/2
    pub const HTTP2: AlpsProtos = AlpsProtos(b"h2");
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
