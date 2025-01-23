use super::cert::{compression::CertCompressionAlgorithm, load, RootCertStore};
use super::{AlpnProtos, AlpsProtos, TlsResult, TlsVersion};
use ::std::os::raw::c_int;
use boring2::error::ErrorStack;
use boring2::ssl::{ConnectConfiguration, SslConnectorBuilder, SslRef, SslVerifyMode};
use boring_sys2 as ffi;
use foreign_types::ForeignTypeRef;

/// Error handler for the boringssl functions.
fn sv_handler(r: c_int) -> TlsResult<c_int> {
    if r == 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

/// SslConnectorBuilderExt trait for `SslConnectorBuilder`.
pub trait SslConnectorBuilderExt {
    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn cert_verification(self, enable: bool) -> TlsResult<SslConnectorBuilder>;

    /// Configure the ALPN and certificate settings for the given `SslConnectorBuilder`.
    fn alpn_protos(self, alpn: AlpnProtos) -> TlsResult<SslConnectorBuilder>;

    /// Configure the minimum TLS version for the given `SslConnectorBuilder`.
    fn min_tls_version<V: Into<Option<TlsVersion>>>(
        self,
        version: V,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the maximum TLS version for the given `SslConnectorBuilder`.
    fn max_tls_version<V: Into<Option<TlsVersion>>>(
        self,
        version: V,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the certificate compression algorithm for the given `SslConnectorBuilder`.
    fn add_cert_compression_alg(
        self,
        alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the RootCertsStore for the given `SslConnectorBuilder`.
    fn root_certs_store(self, stroe: RootCertStore) -> TlsResult<SslConnectorBuilder>;
}

/// SslRefExt trait for `SslRef`.
pub trait SslRefExt {
    /// Configure the ALPN protos for the given `SslRef`.
    fn alpn_protos(&mut self, alpn: Option<AlpnProtos>) -> TlsResult<()>;
}

/// ConnectConfigurationExt trait for `ConnectConfiguration`.
pub trait ConnectConfigurationExt {
    /// Configure the enable_ech_grease for the given `ConnectConfiguration`.
    fn enable_ech_grease(&mut self, enable: bool) -> TlsResult<&mut ConnectConfiguration>;

    /// Configure the ALPS for the given `ConnectConfiguration`.
    fn alps_protos(&mut self, alps: Option<AlpsProtos>) -> TlsResult<&mut ConnectConfiguration>;

    /// Configure the no session ticket for the given `ConnectConfiguration`.
    fn skip_session_ticket(&mut self) -> TlsResult<&mut ConnectConfiguration>;
}

impl SslConnectorBuilderExt for SslConnectorBuilder {
    #[inline]
    fn cert_verification(mut self, enable: bool) -> TlsResult<SslConnectorBuilder> {
        if enable {
            self.set_verify(SslVerifyMode::PEER);
        } else {
            self.set_verify(SslVerifyMode::NONE);
        }
        Ok(self)
    }

    #[inline]
    fn alpn_protos(mut self, alpn: AlpnProtos) -> TlsResult<SslConnectorBuilder> {
        self.set_alpn_protos(alpn.0).map(|_| self)
    }

    #[inline]
    fn min_tls_version<V: Into<Option<TlsVersion>>>(
        mut self,
        version: V,
    ) -> TlsResult<SslConnectorBuilder> {
        self.set_min_proto_version(version.into().map(|v| v.0))
            .map(|_| self)
    }

    #[inline]
    fn max_tls_version<V: Into<Option<TlsVersion>>>(
        mut self,
        version: V,
    ) -> TlsResult<SslConnectorBuilder> {
        self.set_max_proto_version(version.into().map(|v| v.0))
            .map(|_| self)
    }

    #[inline]
    fn add_cert_compression_alg(
        self,
        alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder> {
        sv_handler(unsafe {
            ffi::SSL_CTX_add_cert_compression_alg(
                self.as_ptr(),
                alg as _,
                alg.compression_fn(),
                alg.decompression_fn(),
            )
        })
        .map(|_| self)
    }

    #[inline]
    fn root_certs_store(mut self, store: RootCertStore) -> TlsResult<SslConnectorBuilder> {
        // Conditionally configure the TLS builder based on the "native-roots" feature.
        // If no custom CA cert store, use the system's native certificate store if the feature is enabled.
        match store {
            RootCertStore::Default => {
                // WebPKI root certificates are enabled (regardless of whether native-roots is also enabled).
                #[cfg(any(feature = "webpki-roots", feature = "native-roots"))]
                {
                    if let Some(cert_store) = load::LOAD_CERTS.as_deref() {
                        log::debug!("Using CA certs from webpki/native roots");
                        sv_handler(unsafe {
                            ffi::SSL_CTX_set1_verify_cert_store(self.as_ptr(), cert_store.as_ptr())
                        })?;
                    } else {
                        log::debug!("No CA certs provided, using system default");
                        self.set_default_verify_paths()?;
                    }
                }

                // Neither native-roots nor WebPKI roots are enabled, proceed with the default builder.
                #[cfg(not(any(feature = "webpki-roots", feature = "native-roots")))]
                {
                    self.set_default_verify_paths()?;
                }
            }
            RootCertStore::Owned(cert_store) => {
                self.set_verify_cert_store(cert_store)?;
            }
            RootCertStore::Borrowed(cert_store) => {
                sv_handler(unsafe {
                    ffi::SSL_CTX_set1_verify_cert_store(self.as_ptr(), cert_store.as_ptr())
                })?;
            }
        }

        Ok(self)
    }
}

impl ConnectConfigurationExt for ConnectConfiguration {
    #[inline]
    fn enable_ech_grease(&mut self, enable: bool) -> TlsResult<&mut ConnectConfiguration> {
        unsafe { ffi::SSL_set_enable_ech_grease(self.as_ptr(), enable as _) }
        Ok(self)
    }

    #[inline]
    fn alps_protos(&mut self, alps: Option<AlpsProtos>) -> TlsResult<&mut ConnectConfiguration> {
        if let Some(alps) = alps {
            sv_handler(unsafe {
                ffi::SSL_add_application_settings(
                    self.as_ptr(),
                    alps.as_ptr(),
                    alps.len(),
                    std::ptr::null(),
                    0,
                )
            })?;
        }

        Ok(self)
    }

    #[inline]
    fn skip_session_ticket(&mut self) -> TlsResult<&mut ConnectConfiguration> {
        sv_handler(unsafe { ffi::SSL_set_options(self.as_ptr(), ffi::SSL_OP_NO_TICKET as _) as _ })
            .map(|_| self)
    }
}

impl SslRefExt for SslRef {
    #[inline]
    fn alpn_protos(&mut self, alpn: Option<AlpnProtos>) -> TlsResult<()> {
        let alpn = match alpn {
            Some(alpn) => alpn.0,
            None => return Ok(()),
        };

        self.set_alpn_protos(alpn).map(|_| ())
    }
}
