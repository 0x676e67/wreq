use super::cert::{compression::CertCompressionAlgorithm, RootCertStore};
use super::{sv_handler, AlpnProtos, AlpsProtos, TlsResult, TlsVersion};

use boring2::ssl::{ConnectConfiguration, SslConnectorBuilder, SslRef, SslVerifyMode};
use boring_sys2 as ffi;
use foreign_types::ForeignTypeRef;

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
    fn root_cert_store(self, stroe: RootCertStore) -> TlsResult<SslConnectorBuilder>;
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
    fn root_cert_store(mut self, store: RootCertStore) -> TlsResult<SslConnectorBuilder> {
        store.apply(&mut self)?;
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
