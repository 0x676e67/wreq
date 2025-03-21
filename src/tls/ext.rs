use super::certs::RootCertStoreProvider;
use super::{AlpnProtos, AlpsProtos, TlsResult, TlsVersion};

use boring2::ssl::{
    CertCompressionAlgorithm, ConnectConfiguration, SslConnectorBuilder, SslOptions, SslRef,
    SslVerifyMode,
};

/// SslConnectorBuilderExt trait for `SslConnectorBuilder`.
pub trait SslConnectorBuilderExt {
    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn cert_verification(self, enable: bool) -> TlsResult<SslConnectorBuilder>;

    /// Configure the ALPN and certificate config for the given `SslConnectorBuilder`.
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
    fn add_cert_compression_algorithm(
        self,
        alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder>;

    /// Configure the RootCertStoreProvider for the given `SslConnectorBuilder`.
    fn root_cert_store(self, provider: RootCertStoreProvider) -> TlsResult<SslConnectorBuilder>;
}

/// SslRefExt trait for `SslRef`.
pub trait SslRefExt {
    /// Configure the ALPN protos for the given `SslRef`.
    fn alpn_protos(&mut self, alpn: Option<AlpnProtos>) -> TlsResult<()>;
}

/// ConnectConfigurationExt trait for `ConnectConfiguration`.
pub trait ConnectConfigurationExt {
    /// Configure the ALPS for the given `ConnectConfiguration`.
    fn alps_protos(
        &mut self,
        alps: Option<AlpsProtos>,
        new_endpoint: bool,
    ) -> TlsResult<&mut ConnectConfiguration>;

    /// Configure the no session ticket for the given `ConnectConfiguration`.
    fn skip_session_ticket(&mut self) -> TlsResult<&mut ConnectConfiguration>;

    /// Configure the random aes hardware override for the given `ConnectConfiguration`.
    fn set_random_aes_hw_override(&mut self, enable: bool);
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
    fn add_cert_compression_algorithm(
        mut self,
        alg: CertCompressionAlgorithm,
    ) -> TlsResult<SslConnectorBuilder> {
        self.add_cert_compression_alg(alg).map(|_| self)
    }

    #[inline]
    fn root_cert_store(
        mut self,
        provider: RootCertStoreProvider,
    ) -> TlsResult<SslConnectorBuilder> {
        provider.apply_to_builder(&mut self).map(|_| self)
    }
}

impl ConnectConfigurationExt for ConnectConfiguration {
    #[inline]
    fn alps_protos(
        &mut self,
        alps: Option<AlpsProtos>,
        new_endpoint: bool,
    ) -> TlsResult<&mut ConnectConfiguration> {
        if let Some(alps) = alps {
            self.add_application_settings(alps.0)?;

            // By default, the old endpoint is used. Avoid unnecessary FFI calls.
            if new_endpoint {
                self.set_alps_use_new_codepoint(new_endpoint);
            }
        }

        Ok(self)
    }

    #[inline]
    fn skip_session_ticket(&mut self) -> TlsResult<&mut ConnectConfiguration> {
        self.set_options(SslOptions::NO_TICKET).map(|_| self)
    }

    #[inline]
    fn set_random_aes_hw_override(&mut self, enable: bool) {
        if enable {
            let random_bool = (crate::util::fast_random() % 2) == 0;
            self.set_aes_hw_override(random_bool);
        }
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
