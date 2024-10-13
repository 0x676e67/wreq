#![allow(missing_debug_implementations)]
use super::{cert_compression::CertCompressionAlgorithm, TlsResult, Version};
use crate::client::http::HttpVersionPref;
use ::std::os::raw::c_int;
use boring::error::ErrorStack;
use boring::ssl::{ConnectConfiguration, SslConnectorBuilder, SslVerifyMode, SslVersion};
use boring::x509::store::X509Store;
use foreign_types::ForeignTypeRef;

/// Error handler for the boringssl functions.
fn sv_handler(r: c_int) -> Result<c_int, ErrorStack> {
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
        min_tls_version: Option<Version>,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the maximum TLS version for the given `SslConnectorBuilder`.
    fn configure_max_tls_version(
        self,
        max_tls_version: Option<Version>,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the certificate compression algorithm for the given `SslConnectorBuilder`.
    fn configure_add_cert_compression_alg(
        self,
        cert_compression_alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the ca certificate store for the given `SslConnectorBuilder`.
    fn configure_ca_cert_store(
        self,
        ca_cert_stroe: Option<X509Store>,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the permute_extensions for the given `SslConnectorBuilder`.
    fn configure_permute_extensions(
        self,
        enable: bool,
        permute_extensions: bool,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the native roots CA for the given `SslConnectorBuilder`.
    #[cfg(feature = "boring-tls-native-roots")]
    fn configure_set_native_verify_cert_store(self) -> TlsResult<SslConnectorBuilder>;

    /// Configure the webpki roots CA for the given `SslConnectorBuilder`.
    #[cfg(feature = "boring-tls-webpki-roots")]
    fn configure_set_webpki_verify_cert_store(self) -> TlsResult<SslConnectorBuilder>;
}

/// TlsConnectExtension trait for `ConnectConfiguration`.
pub trait TlsConnectExtension {
    /// Configure the enable_ech_grease for the given `ConnectConfiguration`.
    fn configure_enable_ech_grease(
        &mut self,
        enable: bool,
        enable_ech_grease: bool,
    ) -> TlsResult<&mut ConnectConfiguration>;

    /// Configure the add_application_settings for the given `ConnectConfiguration`.
    fn configure_add_application_settings(
        &mut self,
        enable: bool,
        http_version: HttpVersionPref,
    ) -> TlsResult<&mut ConnectConfiguration>;
}

impl TlsExtension for SslConnectorBuilder {
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

    fn configure_min_tls_version(
        mut self,
        min_tls_version: Option<Version>,
    ) -> TlsResult<SslConnectorBuilder> {
        if let Some(version) = min_tls_version {
            let ssl_version = match version.0 {
                super::InnerVersion::Tls1_0 => SslVersion::TLS1,
                super::InnerVersion::Tls1_1 => SslVersion::TLS1_1,
                super::InnerVersion::Tls1_2 => SslVersion::TLS1_2,
                super::InnerVersion::Tls1_3 => SslVersion::TLS1_3,
            };
            self.set_min_proto_version(Some(ssl_version))?
        }

        Ok(self)
    }

    fn configure_max_tls_version(
        mut self,
        max_tls_version: Option<Version>,
    ) -> TlsResult<SslConnectorBuilder> {
        if let Some(version) = max_tls_version {
            let ssl_version = match version.0 {
                super::InnerVersion::Tls1_0 => SslVersion::TLS1,
                super::InnerVersion::Tls1_1 => SslVersion::TLS1_1,
                super::InnerVersion::Tls1_2 => SslVersion::TLS1_2,
                super::InnerVersion::Tls1_3 => SslVersion::TLS1_3,
            };

            self.set_max_proto_version(Some(ssl_version))?
        }

        Ok(self)
    }

    fn configure_add_cert_compression_alg(
        self,
        cert_compression_alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder> {
        unsafe {
            sv_handler(boring_sys::SSL_CTX_add_cert_compression_alg(
                self.as_ptr(),
                cert_compression_alg as _,
                cert_compression_alg.compression_fn(),
                cert_compression_alg.decompression_fn(),
            ))
            .map(|_| self)
        }
    }

    fn configure_ca_cert_store(
        mut self,
        ca_cert_stroe: Option<X509Store>,
    ) -> TlsResult<SslConnectorBuilder> {
        if let Some(stroe) = ca_cert_stroe {
            self.set_verify_cert_store(stroe)?;
        }

        Ok(self)
    }

    fn configure_permute_extensions(
        mut self,
        enable: bool,
        permute_extensions: bool,
    ) -> TlsResult<SslConnectorBuilder> {
        if !enable {
            return Ok(self);
        }

        self.set_permute_extensions(permute_extensions);
        Ok(self)
    }

    #[cfg(feature = "boring-tls-native-roots")]
    fn configure_set_native_verify_cert_store(mut self) -> TlsResult<SslConnectorBuilder> {
        use boring::x509::X509;
        use std::ops::Deref;
        use std::sync::LazyLock;

        static LOAD_NATIVE_CERTS: LazyLock<Result<X509Store, crate::Error>> = LazyLock::new(|| {
            let load_certs = rustls_native_certs::load_native_certs();
            load_certs_from_source(load_certs.certs.iter().map(|c| X509::from_der(c.as_ref())))
        });

        let store = configure_set_verify_cert_store(LOAD_NATIVE_CERTS.deref())?;
        self.set_verify_cert_store(store)?;

        Ok(self)
    }

    #[cfg(feature = "boring-tls-webpki-roots")]
    fn configure_set_webpki_verify_cert_store(mut self) -> TlsResult<SslConnectorBuilder> {
        use boring::x509::X509;
        use std::ops::Deref;
        use std::sync::LazyLock;

        static LOAD_WEBPKI_CERTS: LazyLock<Result<X509Store, crate::Error>> = LazyLock::new(|| {
            load_certs_from_source(
                webpki_root_certs::TLS_SERVER_ROOT_CERTS
                    .iter()
                    .map(|c| X509::from_der(c)),
            )
        });

        let stroe = configure_set_verify_cert_store(LOAD_WEBPKI_CERTS.deref())?;
        self.set_verify_cert_store(stroe)?;
        Ok(self)
    }
}

#[cfg(any(
    feature = "boring-tls-webpki-roots",
    feature = "boring-tls-native-roots"
))]
fn load_certs_from_source<I>(certs: I) -> Result<X509Store, crate::Error>
where
    I: Iterator<Item = Result<boring::x509::X509, ErrorStack>>,
{
    use boring::x509::store::X509StoreBuilder;

    let mut valid_count = 0;
    let mut invalid_count = 0;
    let mut verify_store = X509StoreBuilder::new()?;

    for cert in certs {
        match cert {
            Ok(cert) => {
                verify_store.add_cert(cert)?;
                valid_count += 1;
            }
            Err(err) => {
                invalid_count += 1;
                log::debug!("tls failed to parse DER certificate: {err:?}");
            }
        }
    }

    if valid_count == 0 && invalid_count > 0 {
        return Err(crate::Error::new(
            crate::error::Kind::Builder,
            Some("all certificates are invalid"),
        ));
    }

    Ok(verify_store.build())
}

#[cfg(any(
    feature = "boring-tls-webpki-roots",
    feature = "boring-tls-native-roots"
))]
fn configure_set_verify_cert_store(
    certs: &Result<X509Store, crate::Error>,
) -> TlsResult<X509Store> {
    use boring::x509::store::X509StoreBuilder;

    let mut verify_store = X509StoreBuilder::new()?;

    if let Some(store) = certs.as_ref().ok() {
        for cert in store.objects().iter() {
            if let Some(cert) = cert.x509() {
                verify_store.add_cert(cert.to_owned())?;
            }
        }
    } else {
        verify_store.set_default_paths()?;
    }

    Ok(verify_store.build())
}

impl TlsConnectExtension for ConnectConfiguration {
    fn configure_enable_ech_grease(
        &mut self,
        enable: bool,
        enable_ech_grease: bool,
    ) -> TlsResult<&mut ConnectConfiguration> {
        if !enable {
            return Ok(self);
        }

        unsafe { boring_sys::SSL_set_enable_ech_grease(self.as_ptr(), enable_ech_grease as _) }
        Ok(self)
    }

    fn configure_add_application_settings(
        &mut self,
        enable: bool,
        http_version: HttpVersionPref,
    ) -> TlsResult<&mut ConnectConfiguration> {
        if !enable {
            return Ok(self);
        }

        let (alpn, alpn_len) = match http_version {
            HttpVersionPref::Http1 => ("http/1.1", 8),
            HttpVersionPref::Http2 | HttpVersionPref::All => ("h2", 2),
        };

        unsafe {
            sv_handler(boring_sys::SSL_add_application_settings(
                self.as_ptr(),
                alpn.as_ptr(),
                alpn_len,
                std::ptr::null(),
                0,
            ))
            .map(|_| self)
        }
    }
}
