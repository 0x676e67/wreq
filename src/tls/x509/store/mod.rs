mod parser;

use std::{fmt::Debug, path::Path, sync::Arc};

use boring2::{
    ssl::SslConnectorBuilder,
    x509::store::{X509Store, X509StoreBuilder},
};
use parser::{
    filter_map_certs, parse_certs_with_iter, parse_certs_with_stack, process_certs_with_builder,
};

use super::{Certificate, CertificateInput};
use crate::Error;

/// A builder for constructing a `CertStore`.
///
/// This builder provides methods to add certificates to the store from various formats,
/// and to set default paths for the certificate store. Once all desired certificates
/// have been added, the `build` method can be used to create the `CertStore`.
pub struct CertStoreBuilder {
    builder: crate::Result<X509StoreBuilder>,
}

impl CertStoreBuilder {
    /// Adds a DER-encoded certificate to the certificate store.
    #[inline]
    pub fn add_der_cert<'c, C>(self, cert: C) -> Self
    where
        C: Into<CertificateInput<'c>>,
    {
        self.parse_cert(cert, Certificate::from_der)
    }

    /// Adds a PEM-encoded certificate to the certificate store.
    #[inline]
    pub fn add_pem_cert<'c, C>(self, cert: C) -> Self
    where
        C: Into<CertificateInput<'c>>,
    {
        self.parse_cert(cert, Certificate::from_pem)
    }

    /// Adds multiple DER-encoded certificates to the certificate store.
    #[inline]
    pub fn add_der_certs<'c, I>(self, certs: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<CertificateInput<'c>>,
    {
        self.parse_certs(certs, Certificate::from_der)
    }

    /// Adds multiple PEM-encoded certificates to the certificate store.
    #[inline]
    pub fn add_pem_certs<'c, I>(self, certs: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<CertificateInput<'c>>,
    {
        self.parse_certs(certs, Certificate::from_pem)
    }

    /// Adds a PEM-encoded certificate stack to the certificate store.
    pub fn add_stack_pem_certs<C>(mut self, certs: C) -> Self
    where
        C: AsRef<[u8]>,
    {
        if let Ok(ref mut builder) = self.builder {
            let result = Certificate::stack_from_pem(certs.as_ref())
                .and_then(|certs| process_certs_with_builder(certs.into_iter(), builder));

            if let Err(err) = result {
                self.builder = Err(err);
            }
        }
        self
    }

    /// Adds PEM-encoded certificates from a file to the certificate store.
    ///
    /// This method reads the file at the specified path, expecting it to contain a PEM-encoded
    /// certificate stack, and then adds the certificates to the store.
    pub fn add_file_pem_certs<P>(mut self, path: P) -> Self
    where
        P: AsRef<Path>,
    {
        match std::fs::read(path) {
            Ok(data) => return self.add_stack_pem_certs(data),
            Err(err) => {
                self.builder = Err(Error::builder(err));
            }
        }
        self
    }

    /// Load certificates from their default locations.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// environment variables if present, or defaults specified at OpenSSL
    /// build time otherwise.
    pub fn set_default_paths(mut self) -> Self {
        if let Ok(ref mut builder) = self.builder {
            if let Err(err) = builder.set_default_paths() {
                self.builder = Err(Error::tls(err));
            }
        }
        self
    }

    /// Constructs the `CertStore`.
    ///
    /// This method finalizes the builder and constructs the `CertStore`
    /// containing all the added certificates.
    pub fn build(self) -> crate::Result<CertStore> {
        let builder = self.builder?;
        Ok(CertStore(Arc::new(builder.build())))
    }

    fn parse_cert<'c, C, P>(mut self, cert: C, parser: P) -> Self
    where
        C: Into<CertificateInput<'c>>,
        P: Fn(&'c [u8]) -> crate::Result<Certificate>,
    {
        if let Ok(ref mut builder) = self.builder {
            let input = cert.into();
            let result = input
                .with_parser(parser)
                .and_then(|cert| builder.add_cert(cert.0).map_err(Error::tls));

            if let Err(err) = result {
                self.builder = Err(err);
            }
        }
        self
    }

    fn parse_certs<'c, I>(
        mut self,
        certs: I,
        parser: fn(&'c [u8]) -> crate::Result<Certificate>,
    ) -> Self
    where
        I: IntoIterator,
        I::Item: Into<CertificateInput<'c>>,
    {
        if let Ok(ref mut builder) = self.builder {
            let certs = filter_map_certs(certs, parser);
            if let Err(err) = process_certs_with_builder(certs, builder) {
                self.builder = Err(err);
            }
        }
        self
    }
}

/// A collection of certificates Store.
#[derive(Clone)]
pub struct CertStore(Arc<X509Store>);

impl Default for CertStore {
    fn default() -> Self {
        #[cfg(feature = "webpki-roots")]
        pub(super) static LOAD_CERTS: std::sync::LazyLock<CertStore> =
            std::sync::LazyLock::new(|| {
                CertStore::builder()
                    .add_der_certs(webpki_root_certs::TLS_SERVER_ROOT_CERTS)
                    .build()
                    .expect("failed to load default cert store")
            });

        #[cfg(not(feature = "webpki-roots"))]
        {
            CertStore::builder()
                .set_default_paths()
                .build()
                .expect("failed to load default cert store")
        }

        #[cfg(feature = "webpki-roots")]
        LOAD_CERTS.clone()
    }
}

impl Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore").finish()
    }
}

/// ====== impl CertStore ======
impl CertStore {
    /// Creates a new `CertStoreBuilder`.
    #[inline]
    pub fn builder() -> CertStoreBuilder {
        CertStoreBuilder {
            builder: X509StoreBuilder::new().map_err(Error::builder),
        }
    }

    /// Creates a new `CertStore` from a collection of DER-encoded certificates.
    #[inline]
    pub fn from_der_certs<'c, C>(certs: C) -> crate::Result<CertStore>
    where
        C: IntoIterator,
        C::Item: Into<CertificateInput<'c>>,
    {
        parse_certs_with_iter(certs, Certificate::from_der)
    }

    /// Creates a new `CertStore` from a collection of PEM-encoded certificates.
    #[inline]
    pub fn from_pem_certs<'c, C>(certs: C) -> crate::Result<CertStore>
    where
        C: IntoIterator,
        C::Item: Into<CertificateInput<'c>>,
    {
        parse_certs_with_iter(certs, Certificate::from_pem)
    }

    /// Creates a new `CertStore` from a PEM-encoded certificate stack.
    #[inline]
    pub fn from_pem_stack<C>(certs: C) -> crate::Result<CertStore>
    where
        C: AsRef<[u8]>,
    {
        parse_certs_with_stack(certs, Certificate::stack_from_pem)
    }

    /// Creates a new `CertStore` from a PEM-encoded certificate file.
    ///
    /// This method reads the file at the specified path, expecting it to contain a PEM-encoded
    /// certificate stack, and then constructs a `CertStore` from it.
    #[inline]
    pub fn from_pem_file<P>(path: P) -> crate::Result<CertStore>
    where
        P: AsRef<Path>,
    {
        std::fs::read(path)
            .map_err(Error::builder)
            .and_then(Self::from_pem_stack)
    }
}

impl CertStore {
    #[inline]
    pub(crate) fn add_to_tls(&self, tls: &mut SslConnectorBuilder) {
        tls.set_cert_store_ref(&self.0);
    }
}
