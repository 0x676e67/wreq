use btls::ssl::{SslConnectorBuilder, SslVerifyMode};

use crate::{
    Error,
    tls::{CertStore, compress::CertificateCompressor},
};

/// SslConnectorBuilderExt trait for `SslConnectorBuilder`.
pub trait SslConnectorBuilderExt {
    /// Configure the CertStore for the given `SslConnectorBuilder`.
    fn set_cert_store(self, store: Option<&CertStore>) -> crate::Result<SslConnectorBuilder>;

    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn set_cert_verification(self, enable: bool) -> crate::Result<SslConnectorBuilder>;

    /// Configure the certificate compressors for the given `SslConnectorBuilder`.
    fn set_cert_compressors(
        self,
        algs: Option<&[&'static dyn CertificateCompressor]>,
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
    fn set_cert_compressors(
        mut self,
        algs: Option<&[&'static dyn CertificateCompressor]>,
    ) -> crate::Result<SslConnectorBuilder> {
        if let Some(algs) = algs {
            for algorithm in algs {
                self.add_certificate_compression_algorithm(*algorithm)
                    .map_err(Error::tls)?;
            }
        }

        Ok(self)
    }
}
