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
    /// Configure the Identity for the given `SslConnectorBuilder`.
    fn set_identity(self, identity: Option<&Identity>) -> crate::Result<SslConnectorBuilder>;

    /// Configure the CertStore for the given `SslConnectorBuilder`.
    fn set_cert_store(self, store: Option<&CertStore>) -> crate::Result<SslConnectorBuilder>;

    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn set_cert_verification(self, enable: bool) -> SslConnectorBuilder;

    /// Configure the certificate compressors for the given `SslConnectorBuilder`.
    fn set_cert_compressors(
        self,
        compressors: Option<&[&'static dyn CertificateCompressor]>,
    ) -> crate::Result<SslConnectorBuilder>;
}

impl SslConnectorBuilderExt for SslConnectorBuilder {
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

    fn set_cert_store(mut self, store: Option<&CertStore>) -> crate::Result<SslConnectorBuilder> {
        if let Some(store) = store {
            self.set_cert_store_ref(&store.0)
        } else {
            #[cfg(any(feature = "chromium-roots", feature = "webpki-roots"))]
            {
                static DEFAULT_CERT_STORE: std::sync::LazyLock<CertStore> =
                    std::sync::LazyLock::new(|| {
                        let certs = std::iter::empty::<&'static [u8]>();

                        #[cfg(feature = "chromium-roots")]
                        let certs = certs.chain(
                            chromium_roots::TLS_SERVER_ROOT_CERTS
                                .iter()
                                .map(AsRef::as_ref),
                        );

                        #[cfg(feature = "webpki-roots")]
                        let webpki_certs = webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter();

                        #[cfg(all(feature = "chromium-roots", feature = "webpki-roots"))]
                        let webpki_certs = webpki_certs
                            .filter(|cert| !chromium_roots::TLS_SERVER_ROOT_CERTS.contains(*cert));

                        #[cfg(feature = "webpki-roots")]
                        let certs = certs.chain(webpki_certs.map(AsRef::as_ref));

                        CertStore::from_der_certs(certs)
                            .expect("failed to load bundled root certificates")
                    });

                self.set_cert_store_ref(&DEFAULT_CERT_STORE.0);
            }

            #[cfg(not(any(feature = "chromium-roots", feature = "webpki-roots")))]
            {
                self.set_default_verify_paths().map_err(Error::tls)?;
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
