use std::borrow::Cow;

use boring2::{
    error::ErrorStack,
    ssl::{
        CertCompressionAlgorithm, ConnectConfiguration, SslConnectorBuilder, SslOptions, SslRef,
        SslVerifyMode,
    },
};

#[cfg(any(feature = "webpki-roots", feature = "native-roots"))]
use super::x509::LOAD_CERTS;
use super::{AlpnProtos, AlpsProtos, CertStore, TlsVersion};

/// SslConnectorBuilderExt trait for `SslConnectorBuilder`.
pub trait SslConnectorBuilderExt {
    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn cert_verification(self, enable: bool) -> crate::Result<SslConnectorBuilder>;

    /// Configure the ALPN and certificate config for the given `SslConnectorBuilder`.
    fn alpn_protos(self, alpn: AlpnProtos) -> crate::Result<SslConnectorBuilder>;

    /// Configure the minimum TLS version for the given `SslConnectorBuilder`.
    fn min_tls_version<V: Into<Option<TlsVersion>>>(
        self,
        version: V,
    ) -> crate::Result<SslConnectorBuilder>;

    /// Configure the maximum TLS version for the given `SslConnectorBuilder`.
    fn max_tls_version<V: Into<Option<TlsVersion>>>(
        self,
        version: V,
    ) -> crate::Result<SslConnectorBuilder>;

    /// Configure the certificate compression algorithm for the given `SslConnectorBuilder`.
    fn add_cert_compression_algorithm(
        self,
        alg: CertCompressionAlgorithm,
    ) -> crate::Result<SslConnectorBuilder>;

    /// Configure the CertStore for the given `SslConnectorBuilder`.
    fn cert_store(
        self,
        provider: Option<Cow<'static, CertStore>>,
    ) -> crate::Result<SslConnectorBuilder>;
}

/// SslRefExt trait for `SslRef`.
pub trait SslRefExt {
    /// Configure the ALPN protos for the given `SslRef`.
    fn alpn_protos(&mut self, alpn: Option<AlpnProtos>) -> Result<(), ErrorStack>;
}

/// ConnectConfigurationExt trait for `ConnectConfiguration`.
pub trait ConnectConfigurationExt {
    /// Configure the ALPS for the given `ConnectConfiguration`.
    fn alps_protos(
        &mut self,
        alps: Option<AlpsProtos>,
        new_endpoint: bool,
    ) -> Result<&mut ConnectConfiguration, ErrorStack>;

    /// Configure the no session ticket for the given `ConnectConfiguration`.
    fn skip_session_ticket(&mut self) -> Result<&mut ConnectConfiguration, ErrorStack>;

    /// Configure the random aes hardware override for the given `ConnectConfiguration`.
    fn set_random_aes_hw_override(&mut self, enable: bool);
}

impl SslConnectorBuilderExt for SslConnectorBuilder {
    #[inline]
    fn cert_verification(mut self, enable: bool) -> crate::Result<SslConnectorBuilder> {
        if enable {
            self.set_verify(SslVerifyMode::PEER);
        } else {
            self.set_verify(SslVerifyMode::NONE);
        }
        Ok(self)
    }

    #[inline]
    fn alpn_protos(mut self, alpn: AlpnProtos) -> crate::Result<SslConnectorBuilder> {
        self.set_alpn_protos(alpn.0)
            .map(|_| self)
            .map_err(Into::into)
    }

    #[inline]
    fn min_tls_version<V: Into<Option<TlsVersion>>>(
        mut self,
        version: V,
    ) -> crate::Result<SslConnectorBuilder> {
        self.set_min_proto_version(version.into().map(|v| v.0))
            .map(|_| self)
            .map_err(Into::into)
    }

    #[inline]
    fn max_tls_version<V: Into<Option<TlsVersion>>>(
        mut self,
        version: V,
    ) -> crate::Result<SslConnectorBuilder> {
        self.set_max_proto_version(version.into().map(|v| v.0))
            .map(|_| self)
            .map_err(Into::into)
    }

    #[inline]
    fn add_cert_compression_algorithm(
        mut self,
        alg: CertCompressionAlgorithm,
    ) -> crate::Result<SslConnectorBuilder> {
        self.add_cert_compression_alg(alg)
            .map(|_| self)
            .map_err(Into::into)
    }

    #[inline]
    fn cert_store(
        mut self,
        store: Option<Cow<'static, CertStore>>,
    ) -> crate::Result<SslConnectorBuilder> {
        if let Some(store) = store {
            match store {
                Cow::Borrowed(store) => {
                    store.add_to_tls_ref(&mut self)?;
                }
                Cow::Owned(store) => {
                    store.add_to_tls(&mut self)?;
                }
            };
        } else {
            // WebPKI root certificates are enabled (regardless of whether native-roots is also
            // enabled).
            #[cfg(any(feature = "webpki-roots", feature = "native-roots"))]
            {
                if let Some(store) = LOAD_CERTS.as_ref() {
                    log::debug!("Using CA certs from webpki/native roots");
                    store.add_to_tls_ref(&mut self)?;
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

        Ok(self)
    }
}

impl ConnectConfigurationExt for ConnectConfiguration {
    #[inline]
    fn alps_protos(
        &mut self,
        alps: Option<AlpsProtos>,
        new_endpoint: bool,
    ) -> Result<&mut ConnectConfiguration, ErrorStack> {
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
    fn skip_session_ticket(&mut self) -> Result<&mut ConnectConfiguration, ErrorStack> {
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
    fn alpn_protos(&mut self, alpn: Option<AlpnProtos>) -> Result<(), ErrorStack> {
        let alpn = match alpn {
            Some(alpn) => alpn.0,
            None => return Ok(()),
        };

        self.set_alpn_protos(alpn).map(|_| ())
    }
}
