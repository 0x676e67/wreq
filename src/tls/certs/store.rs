#![allow(missing_debug_implementations)]
use crate::{Error, error, tls::TlsResult};
use boring2::{
    error::ErrorStack,
    ssl::SslConnectorBuilder,
    x509::{
        X509,
        store::{X509Store, X509StoreBuilder},
    },
};
use std::path::Path;

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

/// The root certificate store.
#[derive(Default, Clone)]
pub enum RootCertStoreProvider {
    /// An owned `X509Store`.
    Owned(RootCertStore),

    /// A borrowed `X509Store`.
    Borrowed(&'static RootCertStore),

    /// Use the system's native certificate store.
    #[default]
    Default,
}

/// ====== impl RootCertStoreProvider ======
impl RootCertStoreProvider {
    /// Applies the root certificate store to the TLS builder.
    pub(crate) fn apply_to_builder(self, builder: &mut SslConnectorBuilder) -> TlsResult<()> {
        // Conditionally configure the TLS builder based on the "native-roots" feature.
        // If no custom CA cert store, use the system's native certificate store if the feature is enabled.
        match self {
            RootCertStoreProvider::Owned(cert_store) => builder.set_verify_cert_store(cert_store.0),
            RootCertStoreProvider::Borrowed(cert_store) => {
                builder.set_verify_cert_store_ref(&cert_store.0)
            }
            RootCertStoreProvider::Default => {
                // WebPKI root certificates are enabled (regardless of whether native-roots is also enabled).
                #[cfg(any(feature = "webpki-roots", feature = "native-roots"))]
                {
                    if let Some(cert_store) = super::load::LOAD_CERTS.as_ref() {
                        log::debug!("Using CA certs from webpki/native roots");
                        builder.set_verify_cert_store_ref(&cert_store.0)
                    } else {
                        log::debug!("No CA certs provided, using system default");
                        builder.set_default_verify_paths()
                    }
                }

                // Neither native-roots nor WebPKI roots are enabled, proceed with the default builder.
                #[cfg(not(any(feature = "webpki-roots", feature = "native-roots")))]
                {
                    builder.set_default_verify_paths()
                }
            }
        }
    }
}

impl std::fmt::Debug for RootCertStoreProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RootCertStoreProvider::Owned(_) => f.debug_tuple("Owned").finish(),
            RootCertStoreProvider::Borrowed(_) => f.debug_tuple("Borrowed").finish(),
            RootCertStoreProvider::Default => f.debug_tuple("Default").finish(),
        }
    }
}

macro_rules! impl_root_cert_store {
    ($($type:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$type> for RootCertStoreProvider {
                fn from(store: $type) -> Self {
                    Self::$variant(store)
                }
            }
        )*
    };

    ($($type:ty => $variant:ident, $unwrap:expr),* $(,)?) => {
        $(
            impl From<$type> for RootCertStoreProvider {
                fn from(store: $type) -> Self {
                    $unwrap(store).map(Self::$variant).unwrap_or_default()
                }
            }
        )*
    };
}

impl_root_cert_store!(
    RootCertStore => Owned,
    &'static RootCertStore => Borrowed,
);

impl_root_cert_store!(
    Option<RootCertStore> => Owned, |s| s,
    Option<&'static RootCertStore> => Borrowed, |s| s,
);

impl<F> From<F> for RootCertStoreProvider
where
    F: Fn() -> Option<&'static RootCertStore>,
{
    fn from(func: F) -> Self {
        func().map(Self::Borrowed).unwrap_or_default()
    }
}
