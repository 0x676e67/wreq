#![allow(missing_debug_implementations)]
use super::{impersonate::tls::TlsExtensionSettings, Version};
use crate::client::http::HttpVersionPref;
use boring::ssl::SslConnectorBuilder;
use std::path::PathBuf;

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
