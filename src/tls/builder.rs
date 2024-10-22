#![allow(missing_debug_implementations)]
use super::{impersonate::tls::TlsSettings, TlsResult, Version};
use crate::client::http::HttpVersionPref;
use boring::x509::store::X509Store;
use std::sync::Arc;

/// The TLS connector configuration.
pub struct TlsConnectorBuilder {
    /// Verify certificates.
    pub(crate) certs_verification: bool,

    /// CA certificates store.
    pub(crate) ca_cert_store: Option<Arc<dyn Fn() -> TlsResult<X509Store>>>,

    /// The TLS connector settings.
    pub(crate) tls: TlsSettings,
}

// ============= SslSettings impls =============
impl Default for TlsConnectorBuilder {
    fn default() -> Self {
        Self {
            certs_verification: true,
            ca_cert_store: None,
            tls: TlsSettings::builder()
                .http_version_pref(HttpVersionPref::All)
                .tls_sni(true)
                .build(),
        }
    }
}

// ============= Tls impls =============
impl TlsConnectorBuilder {
    pub fn permute_extensions(&mut self) {
        self.tls.permute_extensions = true;
    }

    pub fn pre_shared_key(&mut self) {
        self.tls.pre_shared_key = true;
    }

    pub fn enable_ech_grease(&mut self) {
        self.tls.enable_ech_grease = true;
    }

    pub fn http_version_pref(&mut self, version: HttpVersionPref) {
        self.tls.http_version_pref = version;
    }

    pub fn min_tls_version(&mut self, version: Version) {
        self.tls.min_tls_version = Some(version);
    }

    pub fn max_tls_version(&mut self, version: Version) {
        self.tls.max_tls_version = Some(version);
    }

    pub fn tls_sni(&mut self, tls_sni: bool) {
        self.tls.tls_sni = tls_sni;
    }
}
