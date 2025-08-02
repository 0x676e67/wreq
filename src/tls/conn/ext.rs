use boring2::ssl::{SslConnectorBuilder, SslVerifyMode};

use crate::{
    Error,
    tls::{
        CertStore, CertificateCompressionAlgorithm,
        conn::cert_compression::{
            BrotliCertificateCompressor, ZlibCertificateCompressor, ZstdCertificateCompressor,
        },
    },
};

/// SslConnectorBuilderExt trait for `SslConnectorBuilder`.
pub trait SslConnectorBuilderExt {
    /// Configure the CertStore for the given `SslConnectorBuilder`.
    fn set_cert_store(self, store: Option<&CertStore>) -> crate::Result<SslConnectorBuilder>;

    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn set_cert_verification(self, enable: bool) -> crate::Result<SslConnectorBuilder>;

    /// Configure the certificate compression algorithm for the given `SslConnectorBuilder`.
    fn add_certificate_compression_algorithms(
        self,
        algs: Option<&[CertificateCompressionAlgorithm]>,
    ) -> crate::Result<SslConnectorBuilder>;
}

impl SslConnectorBuilderExt for SslConnectorBuilder {
    #[inline]
    fn set_cert_store(mut self, store: Option<&CertStore>) -> crate::Result<SslConnectorBuilder> {
        if let Some(store) = store {
            store.add_to_tls(&mut self);
        } else {
            self.set_default_verify_paths().map_err(Error::tls)?;
        }

        Ok(self)
    }

    #[inline]
    fn set_cert_verification(mut self, enable: bool) -> crate::Result<SslConnectorBuilder> {
        if enable {
            self.set_verify(SslVerifyMode::PEER);
        } else {
            self.set_verify(SslVerifyMode::NONE);
        }
        Ok(self)
    }

    #[inline]
    fn add_certificate_compression_algorithms(
        mut self,
        algs: Option<&[CertificateCompressionAlgorithm]>,
    ) -> crate::Result<SslConnectorBuilder> {
        if let Some(algs) = algs {
            for algorithm in algs.iter() {
                if algorithm == &CertificateCompressionAlgorithm::ZLIB {
                    self.add_certificate_compression_algorithm(
                        ZlibCertificateCompressor::default(),
                    ).map_err(Error::tls)?;
                }

                if algorithm == &CertificateCompressionAlgorithm::BROTLI {
                    self.add_certificate_compression_algorithm(
                        BrotliCertificateCompressor::default(),
                    )
                    .map_err(Error::tls)?;
                }

                if algorithm == &CertificateCompressionAlgorithm::ZSTD {
                    self.add_certificate_compression_algorithm(
                        ZstdCertificateCompressor::default(),
                    ).map_err(Error::tls)?;
                }
            }
        }

        Ok(self)
    }
}
