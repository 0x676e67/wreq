use btls::ssl::{SslConnectorBuilder, SslVerifyMode};

use crate::{
    Error,
    tls::{
        compress::{self, CertificateCompressor},
        trust::{CertStore, Identity},
    },
};

/// SslConnectorBuilderExt trait for `SslConnectorBuilder`.
pub trait SslConnectorBuilderExt {
    /// Configure the CertStore for the given `SslConnectorBuilder`.
    fn set_cert_store(self, store: Option<&CertStore>) -> crate::Result<SslConnectorBuilder>;

    /// Configure the Identity for the given `SslConnectorBuilder`.
    fn set_identity(self, identity: Option<&Identity>) -> crate::Result<SslConnectorBuilder>;

    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn set_cert_verification(self, enable: bool) -> SslConnectorBuilder;

    /// Configure the certificate compressors for the given `SslConnectorBuilder`.
    fn set_cert_compressors(
        self,
        compressors: Option<&[&'static dyn CertificateCompressor]>,
    ) -> crate::Result<SslConnectorBuilder>;
}

impl SslConnectorBuilderExt for SslConnectorBuilder {
    fn set_cert_store(mut self, store: Option<&CertStore>) -> crate::Result<SslConnectorBuilder> {
        if let Some(store) = store {
            self.set_cert_store_ref(&store.0)
        } else {
            self.set_default_verify_paths().map_err(Error::tls)?;
        }

        Ok(self)
    }

    fn set_identity(mut self, identity: Option<&Identity>) -> crate::Result<SslConnectorBuilder> {
        if let Some(identity) = identity {
            self.set_certificate(&identity.cert).map_err(Error::tls)?;
            self.set_private_key(&identity.pkey).map_err(Error::tls)?;
            for cert in identity.chain.iter() {
                // https://www.openssl.org/docs/manmaster/man3/SSL_CTX_add_extra_chain_cert.html
                // specifies that "When sending a certificate chain, extra chain certificates are
                // sent in order following the end entity certificate."
                self.add_extra_chain_cert(cert.clone())
                    .map_err(Error::tls)?;
            }
        }
        Ok(self)
    }

    fn set_cert_verification(mut self, enable: bool) -> SslConnectorBuilder {
        self.set_verify(if enable {
            SslVerifyMode::PEER
        } else {
            SslVerifyMode::NONE
        });

        self
    }

    fn set_cert_compressors(
        mut self,
        compressors: Option<&[&'static dyn CertificateCompressor]>,
    ) -> crate::Result<SslConnectorBuilder> {
        if let Some(compressors) = compressors {
            for compressor in compressors {
                compress::register(*compressor, &mut self).map_err(Error::tls)?;
            }
        }

        Ok(self)
    }
}
