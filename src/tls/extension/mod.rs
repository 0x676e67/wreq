#![allow(missing_debug_implementations)]

pub mod cert_compression;
#[cfg(any(
    feature = "boring-tls-webpki-roots",
    feature = "boring-tls-native-roots"
))]
mod cert_load;
use super::settings::RootCertsStore;
use super::{TlsResult, TlsVersion};
use crate::client::http::HttpVersionPref;
use ::std::os::raw::c_int;
use boring::error::ErrorStack;
use boring::ssl::{ConnectConfiguration, SslConnectorBuilder, SslVerifyMode};
use cert_compression::CertCompressionAlgorithm;
#[cfg(any(
    feature = "boring-tls-webpki-roots",
    feature = "boring-tls-native-roots"
))]
use cert_load::{ForeignTypeRef, LOAD_CERTS};

/// Error handler for the boringssl functions.
fn sv_handler(r: c_int) -> TlsResult<c_int> {
    if r == 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

/// TlsExtension trait for `SslConnectorBuilder`.
pub trait TlsExtension {
    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn configure_cert_verification(
        self,
        certs_verification: bool,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the ALPN and certificate settings for the given `SslConnectorBuilder`.
    fn configure_alpn_protos(self, http_version: HttpVersionPref)
        -> TlsResult<SslConnectorBuilder>;

    /// Configure the minimum TLS version for the given `SslConnectorBuilder`.
    fn configure_min_tls_version(
        self,
        min_tls_version: Option<TlsVersion>,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the maximum TLS version for the given `SslConnectorBuilder`.
    fn configure_max_tls_version(
        self,
        max_tls_version: Option<TlsVersion>,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the certificate compression algorithm for the given `SslConnectorBuilder`.
    fn configure_add_cert_compression_alg(
        self,
        cert_compression_alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the ca certificate store for the given `SslConnectorBuilder`.
    fn configure_ca_cert_store(
        self,
        ca_cert_stroe: RootCertsStore,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the webpki/native roots CA for the given `SslConnectorBuilder`.
    #[cfg(any(
        feature = "boring-tls-webpki-roots",
        feature = "boring-tls-native-roots"
    ))]
    fn configure_set_verify_cert_store(self) -> TlsResult<SslConnectorBuilder>;
}

/// TlsConnectExtension trait for `ConnectConfiguration`.
pub trait TlsConnectExtension {
    /// Configure the enable_ech_grease for the given `ConnectConfiguration`.
    fn configure_enable_ech_grease(
        &mut self,
        enable_ech_grease: bool,
    ) -> TlsResult<&mut ConnectConfiguration>;

    /// Configure the add_application_settings for the given `ConnectConfiguration`.
    fn configure_add_application_settings(
        &mut self,
        http_version: HttpVersionPref,
    ) -> TlsResult<&mut ConnectConfiguration>;
}

impl TlsExtension for SslConnectorBuilder {
    #[inline]
    fn configure_cert_verification(
        mut self,
        certs_verification: bool,
    ) -> TlsResult<SslConnectorBuilder> {
        if !certs_verification {
            self.set_verify(SslVerifyMode::NONE);
        } else {
            self.set_verify(SslVerifyMode::PEER);
        }
        Ok(self)
    }

    #[inline]
    fn configure_alpn_protos(
        mut self,
        http_version: HttpVersionPref,
    ) -> TlsResult<SslConnectorBuilder> {
        match http_version {
            HttpVersionPref::Http1 => {
                self.set_alpn_protos(b"\x08http/1.1")?;
            }
            HttpVersionPref::Http2 => {
                self.set_alpn_protos(b"\x02h2")?;
            }
            HttpVersionPref::All => {
                self.set_alpn_protos(b"\x02h2\x08http/1.1")?;
            }
        }

        Ok(self)
    }

    #[inline]
    fn configure_min_tls_version(
        mut self,
        min_tls_version: Option<TlsVersion>,
    ) -> TlsResult<SslConnectorBuilder> {
        if let Some(version) = min_tls_version {
            self.set_min_proto_version(Some(version.0))?
        }

        Ok(self)
    }

    #[inline]
    fn configure_max_tls_version(
        mut self,
        max_tls_version: Option<TlsVersion>,
    ) -> TlsResult<SslConnectorBuilder> {
        if let Some(version) = max_tls_version {
            self.set_max_proto_version(Some(version.0))?
        }

        Ok(self)
    }

    #[inline]
    fn configure_add_cert_compression_alg(
        self,
        cert_compression_alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder> {
        sv_handler(unsafe {
            boring_sys::SSL_CTX_add_cert_compression_alg(
                self.as_ptr(),
                cert_compression_alg as _,
                cert_compression_alg.compression_fn(),
                cert_compression_alg.decompression_fn(),
            )
        })
        .map(|_| self)
    }

    #[inline]
    fn configure_ca_cert_store(
        mut self,
        root_certs_stroe: RootCertsStore,
    ) -> TlsResult<SslConnectorBuilder> {
        match root_certs_stroe {
            RootCertsStore::Owned(cert_store) => {
                self.set_verify_cert_store(cert_store)?;
            }
            RootCertsStore::Borrowed(cert_store) => {
                sv_handler(unsafe {
                    boring_sys::SSL_CTX_set1_verify_cert_store(self.as_ptr(), cert_store.as_ptr())
                })?;
            }
            _ => {}
        }

        Ok(self)
    }

    #[cfg(any(
        feature = "boring-tls-webpki-roots",
        feature = "boring-tls-native-roots"
    ))]
    #[inline]
    fn configure_set_verify_cert_store(mut self) -> TlsResult<SslConnectorBuilder> {
        if let Ok(cert_store) = LOAD_CERTS.as_deref() {
            log::debug!("Using CA certs from webpki/native roots");
            unsafe {
                sv_handler(boring_sys::SSL_CTX_set1_verify_cert_store(
                    self.as_ptr(),
                    cert_store.as_ptr(),
                ))?;
            }
        } else {
            log::debug!("No CA certs provided, using system default");
            self.set_default_verify_paths()?;
        }

        Ok(self)
    }
}

impl TlsConnectExtension for ConnectConfiguration {
    #[inline]
    fn configure_enable_ech_grease(
        &mut self,
        enable_ech_grease: bool,
    ) -> TlsResult<&mut ConnectConfiguration> {
        unsafe { boring_sys::SSL_set_enable_ech_grease(self.as_ptr(), enable_ech_grease as _) }
        Ok(self)
    }

    #[inline]
    fn configure_add_application_settings(
        &mut self,
        http_version: HttpVersionPref,
    ) -> TlsResult<&mut ConnectConfiguration> {
        let (alpn, alpn_len) = match http_version {
            HttpVersionPref::Http1 => ("http/1.1", 8),
            HttpVersionPref::Http2 | HttpVersionPref::All => ("h2", 2),
        };

        sv_handler(unsafe {
            boring_sys::SSL_add_application_settings(
                self.as_ptr(),
                alpn.as_ptr(),
                alpn_len,
                std::ptr::null(),
                0,
            )
        })
        .map(|_| self)
    }
}
