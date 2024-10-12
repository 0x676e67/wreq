#![allow(missing_debug_implementations)]
use super::{impersonate::tls::TlsExtensionSettings, Version};
use crate::client::http::HttpVersionPref;
use boring::{ssl::SslConnectorBuilder, x509::store::X509Store};

/// The TLS connector configuration.
pub struct TlsConnectorBuilder {
    /// Verify certificates.
    pub(crate) certs_verification: bool,

    /// CA certificates store.
    pub(crate) ca_cert_store: Option<X509Store>,

    /// The SSL connector builder.
    pub(crate) builder: (Option<SslConnectorBuilder>, TlsExtensionSettings),
}

// ============= SslSettings impls =============
impl Default for TlsConnectorBuilder {
    fn default() -> Self {
        Self {
            certs_verification: true,
            ca_cert_store: None,
            builder: (
                None,
                TlsExtensionSettings::builder()
                    .http_version_pref(HttpVersionPref::All)
                    .tls_sni(true)
                    .build(),
            ),
        }
    }
}

// ============= Tls impls =============
impl TlsConnectorBuilder {
    pub fn permute_extensions(&mut self) {
        self.builder.1.permute_extensions = true;
    }

    pub fn pre_shared_key(&mut self) {
        self.builder.1.pre_shared_key = true;
    }

    pub fn enable_ech_grease(&mut self) {
        self.builder.1.enable_ech_grease = true;
    }

    pub fn http_version_pref(&mut self, version: HttpVersionPref) {
        self.builder.1.http_version_pref = version;
    }

    pub fn min_tls_version(&mut self, version: Version) {
        self.builder.1.min_tls_version = Some(version);
    }

    pub fn max_tls_version(&mut self, version: Version) {
        self.builder.1.max_tls_version = Some(version);
    }

    pub fn tls_sni(&mut self, tls_sni: bool) {
        self.builder.1.tls_sni = tls_sni;
    }
}
