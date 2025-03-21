#![allow(missing_debug_implementations)]
use crate::{Error, error};
use boring2::{
    error::ErrorStack,
    x509::{
        X509,
        store::{X509Store, X509StoreBuilder},
    },
};
use std::{fmt::Debug, path::Path};

/// A builder for constructing a `RootCertStore`.
///
/// This builder provides methods to add certificates to the store from various formats,
/// and to set default paths for the certificate store. Once all desired certificates
/// have been added, the `build` method can be used to create the `RootCertStore`.
///
/// # Example
///
/// ```rust
/// use rquest::RootCertStore;
///
/// let store = RootCertStore::builder()
///     .add_der_cert(&der_cert)
///     .add_pem_cert(&pem_cert)
///     .set_default_paths()
///     .build()?;
/// ```
pub struct RootCertStoreBuilder {
    builder: Result<X509StoreBuilder, Error>,
}

impl RootCertStoreBuilder {
    /// Adds a DER-encoded certificate to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `cert`: A reference to a byte slice containing the DER-encoded certificate.
    pub fn add_der_cert<C>(mut self, cert: C) -> Self
    where
        C: AsRef<[u8]>,
    {
        if let Ok(ref mut builder) = self.builder {
            if let Some(err) = X509::from_der(cert.as_ref())
                .and_then(|cert| builder.add_cert(cert))
                .map_err(error::builder)
                .err()
            {
                self.builder = Err(err);
            }
        }
        self
    }

    /// Adds a PEM-encoded certificate to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `cert`: A reference to a byte slice containing the PEM-encoded certificate.
    pub fn add_pem_cert<C>(mut self, cert: C) -> Self
    where
        C: AsRef<[u8]>,
    {
        if let Ok(ref mut builder) = self.builder {
            if let Some(err) = X509::from_pem(cert.as_ref())
                .and_then(|cert| builder.add_cert(cert))
                .map_err(error::builder)
                .err()
            {
                self.builder = Err(err);
            }
        }
        self
    }

    /// Adds multiple DER-encoded certificates to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over DER-encoded certificates.
    pub fn add_der_certs<C>(mut self, certs: C) -> Self
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        if let Ok(ref mut builder) = self.builder {
            let certs = filter_map_certs(certs, X509::from_der);
            if let Some(err) = process_certs(certs, builder).err() {
                self.builder = Err(err);
            }
        }
        self
    }

    /// Adds multiple PEM-encoded certificates to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over PEM-encoded certificates.
    pub fn add_pem_certs<C>(mut self, certs: C) -> Self
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        if let Ok(ref mut builder) = self.builder {
            let certs = filter_map_certs(certs, X509::from_pem);
            if let Some(err) = process_certs(certs, builder).err() {
                self.builder = Err(err);
            }
        }
        self
    }

    /// Adds a PEM-encoded certificate stack to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `certs`: A PEM-encoded certificate stack.
    pub fn add_stack_pem_certs<C>(mut self, certs: C) -> Self
    where
        C: AsRef<[u8]>,
    {
        if let Ok(ref mut builder) = self.builder {
            if let Some(err) = X509::stack_from_pem(certs.as_ref())
                .map_err(error::builder)
                .and_then(|certs| process_certs(certs.into_iter(), builder))
                .err()
            {
                self.builder = Err(err);
            }
        }
        self
    }

    /// Adds PEM-encoded certificates from a file to the certificate store.
    ///
    /// This method reads the file at the specified path, expecting it to contain a PEM-encoded
    /// certificate stack, and then adds the certificates to the store.
    ///
    /// # Parameters
    ///
    /// - `path`: A reference to a path of the PEM file.
    pub fn add_file_pem_certs<P>(mut self, path: P) -> Self
    where
        P: AsRef<Path>,
    {
        match std::fs::read(path) {
            Ok(data) => return self.add_stack_pem_certs(data),
            Err(err) => {
                self.builder = Err(error::builder(err));
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
            if let Some(err) = builder.set_default_paths().err() {
                self.builder = Err(error::builder(err));
            }
        }
        self
    }

    /// Constructs the `RootCertStore`.
    ///
    /// This method finalizes the builder and constructs the `RootCertStore`
    /// containing all the added certificates.
    #[inline]
    pub fn build(self) -> Result<RootCertStore, Error> {
        self.builder.map(|builder| RootCertStore(builder.build()))
    }
}

/// A collection of certificates Store.
#[derive(Clone)]
pub struct RootCertStore(X509Store);

impl Debug for RootCertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootCertStore").finish()
    }
}

/// ====== impl RootCertStore ======
impl RootCertStore {
    /// Creates a new `RootCertStoreBuilder`.
    #[inline]
    pub fn builder() -> RootCertStoreBuilder {
        RootCertStoreBuilder {
            builder: X509StoreBuilder::new().map_err(error::builder),
        }
    }

    /// Creates a new `RootCertStore` from a collection of DER-encoded certificates.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over DER-encoded certificates.
    #[inline]
    pub fn from_der_certs<C>(certs: C) -> Result<RootCertStore, Error>
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        load_certs_from_iter(certs, X509::from_der)
    }

    /// Creates a new `RootCertStore` from a collection of PEM-encoded certificates.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over PEM-encoded certificates.
    #[inline]
    pub fn from_pem_certs<C>(certs: C) -> Result<RootCertStore, Error>
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        load_certs_from_iter(certs, X509::from_pem)
    }

    /// Creates a new `RootCertStore` from a PEM-encoded certificate stack.
    ///
    /// # Parameters
    ///
    /// - `certs`: A PEM-encoded certificate stack.
    #[inline]
    pub fn from_pem_stack<C>(certs: C) -> Result<RootCertStore, Error>
    where
        C: AsRef<[u8]>,
    {
        load_certs_from_stack(certs, X509::stack_from_pem)
    }

    /// Creates a new `RootCertStore` from a PEM-encoded certificate file.
    ///
    /// This method reads the file at the specified path, expecting it to contain a PEM-encoded
    /// certificate stack, and then constructs a `RootCertStore` from it.
    ///
    /// # Parameters
    ///
    /// - `path`: A reference to a path of the PEM file.
    #[inline]
    pub fn from_pem_file<P>(path: P) -> Result<RootCertStore, Error>
    where
        P: AsRef<Path>,
    {
        let data = std::fs::read(path).map_err(error::builder)?;
        Self::from_pem_stack(data)
    }

    pub(crate) fn as_ref(&self) -> &X509Store {
        &self.0
    }

    pub(crate) fn into_inner(self) -> X509Store {
        self.0
    }
}

fn load_certs_from_iter<C, F>(certs: C, x509: F) -> Result<RootCertStore, Error>
where
    C: IntoIterator,
    C::Item: AsRef<[u8]>,
    F: Fn(&[u8]) -> Result<X509, ErrorStack> + 'static,
{
    let mut store = X509StoreBuilder::new()?;
    let certs = filter_map_certs(certs, x509);
    process_certs(certs.into_iter(), &mut store).map(|_| RootCertStore(store.build()))
}

fn load_certs_from_stack<C, F>(certs: C, x509: F) -> Result<RootCertStore, Error>
where
    C: AsRef<[u8]>,
    F: Fn(&[u8]) -> Result<Vec<X509>, ErrorStack>,
{
    let mut store = X509StoreBuilder::new()?;
    let certs = x509(certs.as_ref())?;
    process_certs(certs.into_iter(), &mut store).map(|_| RootCertStore(store.build()))
}

fn process_certs<I>(iter: I, store: &mut X509StoreBuilder) -> Result<(), Error>
where
    I: Iterator<Item = X509>,
{
    let mut valid_count = 0;
    let mut invalid_count = 0;
    for cert in iter {
        match store.add_cert(cert) {
            Ok(_) => {
                valid_count += 1;
            }
            Err(_) => {
                invalid_count += 1;
                log::warn!("tls failed to add certificate");
            }
        }
    }

    if valid_count == 0 && invalid_count > 0 {
        return Err(error::builder("all certificates are invalid"));
    }

    Ok(())
}

fn filter_map_certs<C, F>(certs: C, f: F) -> impl Iterator<Item = X509>
where
    C: IntoIterator,
    C::Item: AsRef<[u8]>,
    F: Fn(&[u8]) -> Result<X509, ErrorStack> + 'static,
{
    certs
        .into_iter()
        .filter_map(move |data| match f(data.as_ref()) {
            Ok(cert) => Some(cert),
            Err(err) => {
                log::warn!("tls failed to parse certificate: {err:?}");
                None
            }
        })
}
