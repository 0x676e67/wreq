#![allow(missing_debug_implementations)]
use crate::{Identity, tls::error::Error};
use boring2::{
    error::ErrorStack,
    x509::{
        X509,
        store::{X509Store, X509StoreBuilder},
    },
};
use std::{fmt::Debug, path::Path};

/// A builder for constructing a `CertStore`.
///
/// This builder provides methods to add certificates to the store from various formats,
/// and to set default paths for the certificate store. Once all desired certificates
/// have been added, the `build` method can be used to create the `CertStore`.
///
/// # Example
///
/// ```rust
/// use rquest::CertStore;
///
/// let store = CertStore::builder()
///     .add_cert(&der_or_pem_cert)
///     .add_der_cert(&der_cert)
///     .add_pem_cert(&pem_cert)
///     .set_default_paths()
///     .build()?;
/// ```
pub struct CertStoreBuilder {
    builder: Option<Result<X509StoreBuilder, Error>>,
    identity: Option<Identity>,
}

impl CertStoreBuilder {
    /// Adds an identity to the certificate store.
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Adds a DER/PEM-encoded certificate to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `cert`: A reference to a byte slice containing the DER/PEM-encoded certificate.
    pub fn add_cert<C>(mut self, cert: C) -> Self
    where
        C: AsRef<[u8]>,
    {
        if let Ok(builder) = self.get_or_init() {
            if let Some(err) = detect_cert_parser(cert.as_ref())
                .and_then(|cert| builder.add_cert(cert))
                .err()
            {
                self.builder = Some(Err(err.into()));
            }
        }
        self
    }

    /// Adds a DER-encoded certificate to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `cert`: A reference to a byte slice containing the DER-encoded certificate.
    pub fn add_der_cert<C>(mut self, cert: C) -> Self
    where
        C: AsRef<[u8]>,
    {
        if let Ok(builder) = self.get_or_init() {
            if let Some(err) = X509::from_der(cert.as_ref())
                .and_then(|cert| builder.add_cert(cert))
                .err()
            {
                self.builder = Some(Err(err.into()));
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
        if let Ok(builder) = self.get_or_init() {
            if let Some(err) = X509::from_pem(cert.as_ref())
                .and_then(|cert| builder.add_cert(cert))
                .err()
            {
                self.builder = Some(Err(err.into()));
            }
        }
        self
    }

    /// Adds multiple DER/PEM-encoded certificates to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over DER/PEM-encoded certificates.
    pub fn add_certs<C>(mut self, certs: C) -> Self
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        if let Ok(builder) = self.get_or_init() {
            let certs = filter_map_certs(certs, detect_cert_parser);
            if let Some(err) = process_certs(certs, builder).err() {
                self.builder = Some(Err(err));
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
        if let Ok(builder) = self.get_or_init() {
            let certs = filter_map_certs(certs, X509::from_der);
            if let Some(err) = process_certs(certs, builder).err() {
                self.builder = Some(Err(err));
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
        if let Ok(builder) = self.get_or_init() {
            let certs = filter_map_certs(certs, X509::from_pem);
            if let Some(err) = process_certs(certs, builder).err() {
                self.builder = Some(Err(err));
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
        if let Ok(builder) = self.get_or_init() {
            match X509::stack_from_pem(certs.as_ref()) {
                Ok(certs) => {
                    if let Some(err) = process_certs(certs.into_iter(), builder).err() {
                        self.builder = Some(Err(err));
                    }
                }
                Err(err) => {
                    self.builder = Some(Err(err.into()));
                }
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
                self.builder = Some(Err(err.into()));
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
        if let Ok(builder) = self.get_or_init() {
            if let Some(err) = builder.set_default_paths().err() {
                self.builder = Some(Err(err.into()));
            }
        }
        self
    }

    fn get_or_init(&mut self) -> &mut Result<X509StoreBuilder, Error> {
        self.builder
            .get_or_insert_with(|| X509StoreBuilder::new().map_err(Into::into))
    }

    /// Constructs the `CertStore`.
    ///
    /// This method finalizes the builder and constructs the `CertStore`
    /// containing all the added certificates.
    #[inline]
    pub fn build(self) -> Result<CertStore, Error> {
        let builder = self.builder.transpose()?;
        Ok(CertStore {
            store: builder.map(|b| b.build()),
            identity: self.identity,
        })
    }
}

/// A collection of certificates Store.
#[derive(Clone)]
pub struct CertStore {
    store: Option<X509Store>,
    identity: Option<Identity>,
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
            builder: Some(X509StoreBuilder::new().map_err(Into::into)),
            identity: None,
        }
    }

    /// Creates a new `CertStore` from an `Identity`.
    ///
    /// # Parameters
    ///
    /// - `identity`: An `Identity` object.
    ///
    #[inline]
    pub fn from_identity(identity: Identity) -> CertStore {
        CertStore {
            store: None,
            identity: Some(identity),
        }
    }

    /// Creates a new `CertStore` from a collection of DER/PEM-encoded certificates.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over DER/PEM-encoded certificates.
    #[inline]
    pub fn from_certs<C>(certs: C) -> crate::Result<CertStore>
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        load_certs_from_iter(certs, detect_cert_parser).map_err(crate::error::builder)
    }

    /// Creates a new `CertStore` from a collection of DER-encoded certificates.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over DER-encoded certificates.
    #[inline]
    pub fn from_der_certs<C>(certs: C) -> crate::Result<CertStore>
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        load_certs_from_iter(certs, X509::from_der).map_err(crate::error::builder)
    }

    /// Creates a new `CertStore` from a collection of PEM-encoded certificates.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over PEM-encoded certificates.
    #[inline]
    pub fn from_pem_certs<C>(certs: C) -> crate::Result<CertStore>
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        load_certs_from_iter(certs, X509::from_pem).map_err(crate::error::builder)
    }

    /// Creates a new `CertStore` from a PEM-encoded certificate stack.
    ///
    /// # Parameters
    ///
    /// - `certs`: A PEM-encoded certificate stack.
    #[inline]
    pub fn from_pem_stack<C>(certs: C) -> crate::Result<CertStore>
    where
        C: AsRef<[u8]>,
    {
        load_certs_from_stack(certs, X509::stack_from_pem).map_err(crate::error::builder)
    }

    /// Creates a new `CertStore` from a PEM-encoded certificate file.
    ///
    /// This method reads the file at the specified path, expecting it to contain a PEM-encoded
    /// certificate stack, and then constructs a `CertStore` from it.
    ///
    /// # Parameters
    ///
    /// - `path`: A reference to a path of the PEM file.
    #[inline]
    pub fn from_pem_file<P>(path: P) -> crate::Result<CertStore>
    where
        P: AsRef<Path>,
    {
        std::fs::read(path)
            .map_err(crate::error::builder)
            .and_then(Self::from_pem_stack)
    }

    pub(crate) fn add_to_tls(
        self,
        tls: &mut boring2::ssl::SslConnectorBuilder,
    ) -> crate::Result<()> {
        if let Some(store) = self.store {
            tls.set_verify_cert_store(store)?;
        }

        if let Some(identity) = self.identity {
            identity.identity(tls)?;
        }
        Ok(())
    }

    pub(crate) fn add_to_tls_ref(
        &'static self,
        tls: &mut boring2::ssl::SslConnectorBuilder,
    ) -> crate::Result<()> {
        if let Some(ref store) = self.store {
            tls.set_verify_cert_store_ref(store)?;
        }
        if let Some(ref identity) = self.identity {
            identity.identity_ref(tls)?;
        }
        Ok(())
    }
}

fn load_certs_from_iter<C, F>(certs: C, x509: F) -> Result<CertStore, Error>
where
    C: IntoIterator,
    C::Item: AsRef<[u8]>,
    F: Fn(&[u8]) -> Result<X509, ErrorStack> + 'static,
{
    let mut store = X509StoreBuilder::new()?;
    let certs = filter_map_certs(certs, x509);
    process_certs(certs.into_iter(), &mut store).map(|_| CertStore {
        store: Some(store.build()),
        identity: None,
    })
}

fn load_certs_from_stack<C, F>(certs: C, x509: F) -> Result<CertStore, Error>
where
    C: AsRef<[u8]>,
    F: Fn(&[u8]) -> Result<Vec<X509>, ErrorStack>,
{
    let mut store = X509StoreBuilder::new()?;
    let certs = x509(certs.as_ref())?;
    process_certs(certs.into_iter(), &mut store).map(|_| CertStore {
        store: Some(store.build()),
        identity: None,
    })
}

fn process_certs<I>(iter: I, store: &mut X509StoreBuilder) -> Result<(), Error>
where
    I: Iterator<Item = X509>,
{
    let mut valid_count = 0;
    let mut invalid_count = 0;
    for cert in iter {
        if let Some(err) = store.add_cert(cert).err() {
            invalid_count += 1;
            log::warn!("tls failed to parse certificate: {err:?}");
        } else {
            valid_count += 1;
        }
    }

    if valid_count == 0 && invalid_count > 0 {
        return Err(Error::InvalidCert);
    }

    Ok(())
}

fn filter_map_certs<C, F>(certs: C, parser: F) -> impl Iterator<Item = X509>
where
    C: IntoIterator,
    C::Item: AsRef<[u8]>,
    F: Fn(&[u8]) -> Result<X509, ErrorStack> + 'static,
{
    certs
        .into_iter()
        .filter_map(move |data| match parser(data.as_ref()) {
            Ok(cert) => Some(cert),
            Err(err) => {
                log::warn!("tls failed to parse certificate: {err:?}");
                None
            }
        })
}

fn detect_cert_parser(data: &[u8]) -> Result<X509, ErrorStack> {
    let parser = if data.len() >= 10 {
        // Quick check: if data starts with "-----BEGIN"
        if data.starts_with(b"-----BEGIN") {
            X509::from_pem
        } else {
            // Try to skip leading whitespace
            let start = data
                .iter()
                .position(|&b| !b.is_ascii_whitespace())
                .unwrap_or(0);

            if data[start..].starts_with(b"-----BEGIN") {
                X509::from_pem
            } else {
                X509::from_der
            }
        }
    } else {
        X509::from_der
    };

    parser(data)
}
