//! TLS configuration
//!
//! By default, a `Client` will make use of BoringSSL for TLS.
//!
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.

#![allow(missing_debug_implementations)]
#![allow(missing_docs)]
mod conn;
mod ext;

use crate::{impl_debug, tls::cert_compression::CertCompressionAlgorithm, HttpVersionPref};
use boring::{
    error::ErrorStack,
    ssl::{SslConnector, SslMethod, SslOptions, SslVersion},
};
use boring::{ssl::SslCurve, x509::store::X509Store};
use conn::{HttpsLayer, HttpsLayerSettings};
use std::borrow::Cow;
use typed_builder::TypedBuilder;

pub use crate::mimic::Impersonate;
pub use conn::{HttpsConnector, MaybeHttpsStream};
pub use ext::{cert_compression, TlsBuilderExtension, TlsConnectExtension};

type TlsResult<T> = Result<T, ErrorStack>;

/// A wrapper around a `HttpsLayer` that allows for additional settings.
#[derive(Clone)]
pub struct BoringTlsConnector(HttpsLayer);

impl BoringTlsConnector {
    /// Create a new `BoringTlsConnector` with the given function.
    #[inline]
    pub fn new(settings: TlsSettings) -> TlsResult<BoringTlsConnector> {
        let connector = if cfg!(any(feature = "native-roots", feature = "webpki-roots")) {
            SslConnector::no_default_verify_builder(SslMethod::tls_client())
        } else {
            SslConnector::builder(SslMethod::tls_client())
        }?;

        let mut connector = connector
            .configure_cert_verification(settings.certs_verification)?
            .configure_alpn_protos(settings.alpn_protos)?
            .configure_min_tls_version(settings.min_tls_version)?
            .configure_max_tls_version(settings.max_tls_version)?;

        if settings.enable_ocsp_stapling {
            connector.enable_ocsp_stapling();
        }

        if settings.enable_signed_cert_timestamps {
            connector.enable_signed_cert_timestamps();
        }

        if !settings.session_ticket {
            connector.set_options(SslOptions::NO_TICKET);
        }

        if let Some(grease_enabled) = settings.grease_enabled {
            connector.set_grease_enabled(grease_enabled);
        }

        if let Some(permute_extensions) = settings.permute_extensions {
            connector.set_permute_extensions(permute_extensions);
        }

        if let Some(curves) = settings.curves.as_deref() {
            connector.set_curves(curves)?;
        }

        if let Some(sigalgs_list) = settings.sigalgs_list.as_deref() {
            connector.set_sigalgs_list(sigalgs_list)?;
        }

        if let Some(delegated_credentials) = settings.delegated_credentials.as_deref() {
            connector.set_delegated_credentials(delegated_credentials)?;
        }

        if let Some(cipher_list) = settings.cipher_list.as_deref() {
            connector.set_cipher_list(cipher_list)?;
        }

        if let Some(cert_compression_algorithm) = settings.cert_compression_algorithm {
            for algorithm in cert_compression_algorithm.iter() {
                connector = connector.configure_add_cert_compression_alg(*algorithm)?;
            }
        }

        if let Some(record_size_limit) = settings.record_size_limit {
            connector.set_record_size_limit(record_size_limit);
        }

        if let Some(limit) = settings.key_shares_length_limit {
            connector.set_key_shares_length_limit(limit);
        }

        if let Some(indices) = settings.extension_permutation_indices {
            connector.set_extension_permutation_indices(indices.as_ref())?;
        }

        // Conditionally configure the TLS builder based on the "native-roots" feature.
        // If no custom CA cert store, use the system's native certificate store if the feature is enabled.
        let connector = if settings.root_certs_store.is_none() {
            // WebPKI root certificates are enabled (regardless of whether native-roots is also enabled).
            #[cfg(any(feature = "webpki-roots", feature = "native-roots"))]
            {
                connector.configure_set_verify_cert_store()?
            }

            // Neither native-roots nor WebPKI roots are enabled, proceed with the default builder.
            #[cfg(not(any(feature = "native-roots", feature = "webpki-roots")))]
            {
                connector
            }
        } else {
            // If a custom CA certificate store is provided, configure it.
            connector.configure_ca_cert_store(settings.root_certs_store)?
        };

        // Create the `HttpsLayerSettings` with the default session cache capacity.
        let settings = HttpsLayerSettings::builder()
            .session_cache(settings.pre_shared_key)
            .skip_session_ticket(settings.psk_skip_session_ticket)
            .alpn_protos(settings.alpn_protos)
            .application_settings(settings.application_settings)
            .enable_ech_grease(settings.enable_ech_grease)
            .tls_sni(settings.tls_sni)
            .verify_hostname(settings.verify_hostname)
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

#[derive(TypedBuilder)]
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

impl Default for TlsSettings {
    fn default() -> Self {
        Self::builder().build()
    }
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
