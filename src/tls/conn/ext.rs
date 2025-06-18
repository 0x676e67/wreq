use std::borrow::Cow;

use boring2::{
    error::ErrorStack,
    ssl::{ConnectConfiguration, SslConnectorBuilder, SslVerifyMode},
};

use crate::tls::{
    AlpsProtos, CertCompressionAlgorithm, CertStore, Identity,
    conn::cert::{BrotliCompressor, ZlibCompressor, ZstdCompressor},
};

/// SslConnectorBuilderExt trait for `SslConnectorBuilder`.
pub trait SslConnectorBuilderExt {
    /// Configure the identity for the given `SslConnectorBuilder`.
    fn identity(self, identity: Option<Identity>) -> crate::Result<SslConnectorBuilder>;

    /// Configure the CertStore for the given `SslConnectorBuilder`.
    fn cert_store(self, store: Option<CertStore>) -> crate::Result<SslConnectorBuilder>;

    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn cert_verification(self, enable: bool) -> crate::Result<SslConnectorBuilder>;

    /// Configure the certificate compression algorithm for the given `SslConnectorBuilder`.
    fn cert_compression_algorithm(
        self,
        algs: Option<Cow<'static, [CertCompressionAlgorithm]>>,
    ) -> crate::Result<SslConnectorBuilder>;
}

/// ConnectConfigurationExt trait for `ConnectConfiguration`.
pub trait ConnectConfigurationExt {
    /// Configure the ALPS for the given `ConnectConfiguration`.
    fn alps_protos(
        &mut self,
        alps: Option<AlpsProtos>,
        new_endpoint: bool,
    ) -> Result<&mut ConnectConfiguration, ErrorStack>;

    /// Configure the random aes hardware override for the given `ConnectConfiguration`.
    fn set_random_aes_hw_override(&mut self, enable: bool);
}

impl SslConnectorBuilderExt for SslConnectorBuilder {
    #[inline(always)]
    fn cert_store(mut self, store: Option<CertStore>) -> crate::Result<SslConnectorBuilder> {
        if let Some(store) = store {
            store.add_to_tls(&mut self);
        } else {
            self.set_default_verify_paths()?;
        }

        Ok(self)
    }

    #[inline(always)]
    fn cert_verification(mut self, enable: bool) -> crate::Result<SslConnectorBuilder> {
        if enable {
            self.set_verify(SslVerifyMode::PEER);
        } else {
            self.set_verify(SslVerifyMode::NONE);
        }
        Ok(self)
    }

    #[inline(always)]
    fn identity(mut self, identity: Option<Identity>) -> crate::Result<SslConnectorBuilder> {
        if let Some(identity) = identity {
            identity.add_to_tls(&mut self)?;
        }

        Ok(self)
    }

    #[inline]
    fn cert_compression_algorithm(
        mut self,
        algs: Option<Cow<'static, [CertCompressionAlgorithm]>>,
    ) -> crate::Result<SslConnectorBuilder> {
        if let Some(algs) = algs {
            for algorithm in algs.iter() {
                match algorithm {
                    CertCompressionAlgorithm::Brotli => {
                        self.add_certificate_compression_algorithm(BrotliCompressor::default())?
                    }
                    CertCompressionAlgorithm::Zlib => {
                        self.add_certificate_compression_algorithm(ZlibCompressor::default())?;
                    }
                    CertCompressionAlgorithm::Zstd => {
                        self.add_certificate_compression_algorithm(ZstdCompressor::default())?;
                    }
                }
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
    fn set_random_aes_hw_override(&mut self, enable: bool) {
        if enable {
            let random_bool = (crate::util::fast_random() % 2) == 0;
            self.set_aes_hw_override(random_bool);
        }
    }
}
