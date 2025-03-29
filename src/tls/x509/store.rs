#![allow(missing_debug_implementations)]
use super::{Certificate, CertificateInput};
use crate::Identity;
use boring2::x509::store::{X509Store, X509StoreBuilder};
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
#[derive(Default)]
pub struct CertStoreBuilder {
    identity: Option<Identity>,
    builder: Option<crate::Result<X509StoreBuilder>>,
}

impl CertStoreBuilder {
    /// Adds an identity to the certificate store.
    #[inline]
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Adds a DER/PEM-encoded certificate to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `cert`: A reference to a byte slice containing the DER/PEM-encoded certificate.
    #[inline]
    pub fn add_cert<'c, C>(self, cert: C) -> Self
    where
        C: Into<CertificateInput<'c>>,
    {
        self.parse_cert(cert, Certificate::from)
    }

    /// Adds a DER-encoded certificate to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `cert`: A reference to a byte slice containing the DER-encoded certificate.
    #[inline]
    pub fn add_der_cert<'c, C>(self, cert: C) -> Self
    where
        C: Into<CertificateInput<'c>>,
    {
        self.parse_cert(cert, Certificate::from_der)
    }

    /// Adds a PEM-encoded certificate to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `cert`: A reference to a byte slice containing the PEM-encoded certificate.
    #[inline]
    pub fn add_pem_cert<'c, C>(self, cert: C) -> Self
    where
        C: Into<CertificateInput<'c>>,
    {
        self.parse_cert(cert, Certificate::from_pem)
    }

    /// Adds multiple DER/PEM-encoded certificates to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over DER/PEM-encoded certificates.
    #[inline]
    pub fn add_certs<'c, I>(self, certs: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<CertificateInput<'c>>,
    {
        self.parse_certs(certs, Certificate::from)
    }

    /// Adds multiple DER-encoded certificates to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over DER-encoded certificates.
    #[inline]
    pub fn add_der_certs<'c, I>(self, certs: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<CertificateInput<'c>>,
    {
        self.parse_certs(certs, Certificate::from_der)
    }

    /// Adds multiple PEM-encoded certificates to the certificate store.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over PEM-encoded certificates.
    #[inline]
    pub fn add_pem_certs<'c, I>(self, certs: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<CertificateInput<'c>>,
    {
        self.parse_certs(certs, Certificate::from_pem)
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
            let result = Certificate::stack_from_pem(certs.as_ref())
                .and_then(|certs| process_certs(certs.into_iter(), builder));

            if let Err(err) = result {
                self.builder = Some(Err(err));
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
                self.builder = Some(Err(crate::error::builder(err)));
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
            if let Err(err) = builder.set_default_paths() {
                self.builder = Some(Err(err.into()));
            }
        }
        self
    }

    fn parse_cert<'c, C, P>(mut self, cert: C, parser: P) -> Self
    where
        C: Into<CertificateInput<'c>>,
        P: Fn(&'c [u8]) -> crate::Result<Certificate>,
    {
        if let Ok(builder) = self.get_or_init() {
            let input = cert.into();
            let result = input
                .with_parser(parser)
                .and_then(|cert| builder.add_cert(cert.0).map_err(Into::into));

            if let Err(err) = result {
                self.builder = Some(Err(err));
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
        if let Ok(builder) = self.get_or_init() {
            let certs = filter_map_certs(certs, parser);
            if let Err(err) = process_certs(certs, builder) {
                self.builder = Some(Err(err));
            }
        }
        self
    }

    fn get_or_init(&mut self) -> &mut crate::Result<X509StoreBuilder> {
        self.builder
            .get_or_insert_with(|| X509StoreBuilder::new().map_err(Into::into))
    }

    /// Constructs the `CertStore`.
    ///
    /// This method finalizes the builder and constructs the `CertStore`
    /// containing all the added certificates.
    #[inline]
    pub fn build(self) -> crate::Result<CertStore> {
        let builder = self.builder.transpose()?;
        Ok(CertStore {
            identity: self.identity,
            store: builder.map(|b| b.build()),
        })
    }
}

/// A collection of certificates Store.
#[derive(Clone)]
pub struct CertStore {
    identity: Option<Identity>,
    store: Option<X509Store>,
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
        CertStoreBuilder::default()
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
    pub fn from_certs<'c, I>(certs: I) -> crate::Result<CertStore>
    where
        I: IntoIterator,
        I::Item: Into<CertificateInput<'c>>,
    {
        parse_certs_from_iter(certs, Certificate::from)
    }

    /// Creates a new `CertStore` from a collection of DER-encoded certificates.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over DER-encoded certificates.
    #[inline]
    pub fn from_der_certs<'c, C>(certs: C) -> crate::Result<CertStore>
    where
        C: IntoIterator,
        C::Item: Into<CertificateInput<'c>>,
    {
        parse_certs_from_iter(certs, Certificate::from_der)
    }

    /// Creates a new `CertStore` from a collection of PEM-encoded certificates.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over PEM-encoded certificates.
    #[inline]
    pub fn from_pem_certs<'c, C>(certs: C) -> crate::Result<CertStore>
    where
        C: IntoIterator,
        C::Item: Into<CertificateInput<'c>>,
    {
        parse_certs_from_iter(certs, Certificate::from_pem)
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
        load_certs_from_stack(certs, Certificate::stack_from_pem)
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
}

impl CertStore {
    pub(crate) fn add_to_tls(
        self,
        tls: &mut boring2::ssl::SslConnectorBuilder,
    ) -> crate::Result<()> {
        if let Some(identity) = self.identity {
            identity.identity(tls)?;
        }

        if let Some(store) = self.store {
            tls.set_verify_cert_store(store)?;
        }

        Ok(())
    }

    pub(crate) fn add_to_tls_ref(
        &'static self,
        tls: &mut boring2::ssl::SslConnectorBuilder,
    ) -> crate::Result<()> {
        if let Some(ref identity) = self.identity {
            identity.identity_ref(tls)?;
        }

        if let Some(ref store) = self.store {
            tls.set_verify_cert_store_ref(store)?;
        }

        Ok(())
    }
}

fn parse_certs_from_iter<'c, I>(
    certs: I,
    parser: fn(&'c [u8]) -> crate::Result<Certificate>,
) -> crate::Result<CertStore>
where
    I: IntoIterator,
    I::Item: Into<CertificateInput<'c>>,
{
    let mut store = X509StoreBuilder::new()?;
    let certs = filter_map_certs(certs, parser);
    process_certs(certs.into_iter(), &mut store).map(|_| CertStore {
        store: Some(store.build()),
        identity: None,
    })
}

fn load_certs_from_stack<C, F>(certs: C, x509: F) -> crate::Result<CertStore>
where
    C: AsRef<[u8]>,
    F: Fn(C) -> crate::Result<Vec<Certificate>>,
{
    let mut store = X509StoreBuilder::new()?;
    let certs = x509(certs)?;
    process_certs(certs.into_iter(), &mut store).map(|_| CertStore {
        store: Some(store.build()),
        identity: None,
    })
}

fn process_certs<I>(iter: I, store: &mut X509StoreBuilder) -> crate::Result<()>
where
    I: Iterator<Item = Certificate>,
{
    let mut valid_count = 0;
    let mut invalid_count = 0;
    for cert in iter {
        if let Err(err) = store.add_cert(cert.0) {
            invalid_count += 1;
            log::warn!("tls failed to parse certificate: {err:?}");
        } else {
            valid_count += 1;
        }
    }

    if valid_count == 0 && invalid_count > 0 {
        return Err(crate::error::builder("invalid certificate"));
    }

    Ok(())
}

fn filter_map_certs<'c, I>(
    certs: I,
    parser: fn(&'c [u8]) -> crate::Result<Certificate>,
) -> impl Iterator<Item = Certificate>
where
    I: IntoIterator,
    I::Item: Into<CertificateInput<'c>>,
{
    certs
        .into_iter()
        .map(Into::into)
        .filter_map(move |data| match data.with_parser(parser) {
            Ok(cert) => Some(cert),
            Err(err) => {
                log::warn!("tls failed to parse certificate: {err:?}");
                None
            }
        })
}
