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

/// A collection of certificates Store.
pub struct RootCertStore(X509Store);

/// ====== impl RootCertStore ======
impl RootCertStore {
    /// Creates a new `RootCertStore` from a collection of DER-encoded certificates.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over DER-encoded certificates.
    ///
    /// # Returns
    ///
    /// A `TlsResult` containing the new `RootCertStore`.
    #[inline]
    pub fn from_der_certs<C>(certs: C) -> Result<RootCertStore, Error>
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        Self::load_certs_from_iter(certs, X509::from_der)
    }

    /// Creates a new `RootCertStore` from a collection of PEM-encoded certificates.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over PEM-encoded certificates.
    ///
    /// # Returns
    ///
    /// A `TlsResult` containing the new `RootCertStore`.
    #[inline]
    pub fn from_pem_certs<C>(certs: C) -> Result<RootCertStore, Error>
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        Self::load_certs_from_iter(certs, X509::from_pem)
    }

    /// Creates a new `RootCertStore` from a PEM-encoded certificate stack.
    ///
    /// # Parameters
    ///
    /// - `certs`: A PEM-encoded certificate stack.
    ///
    /// # Returns
    ///
    /// A `TlsResult` containing the new `RootCertStore`.
    #[inline]
    pub fn from_pem_stack<C>(certs: C) -> Result<RootCertStore, Error>
    where
        C: AsRef<[u8]>,
    {
        Self::load_certs(certs, X509::stack_from_pem)
    }

    /// Creates a new `RootCertStore` from a PEM-encoded certificate file.
    ///
    /// This method reads the file at the specified path, expecting it to contain a PEM-encoded
    /// certificate stack, and then constructs a `RootCertStore` from it.
    ///
    /// # Parameters
    ///
    /// - `path`: A reference to a path of the PEM file.
    ///
    /// # Returns
    ///
    /// A `TlsResult` containing the new `RootCertStore` if successful, or an error if the file
    /// cannot be read or parsed.
    pub fn from_pem_file<P>(path: P) -> Result<RootCertStore, Error>
    where
        P: AsRef<Path>,
    {
        let data = std::fs::read(path).map_err(error::builder)?;
        Self::from_pem_stack(data)
    }

    /// Parses a provided byte slice into multiple certificates and adds them into a new `RootCertStore`.
    ///
    /// This method uses the supplied parsing function to convert the input byte slice
    /// into a vector of certificates. It then iterates over the certificates and attempts
    /// to add each certificate to an `X509StoreBuilder`.
    ///
    /// The method keeps track of the number of certificates successfully added (valid)
    /// and those that failed (invalid). If no certificates are successfully added while
    /// having seen some errors, it falls back to setting the default certificate paths.
    ///
    /// # Parameters
    ///
    /// - `certs`: A byte slice containing the encoded certificates.
    /// - `x509`: A function that parses the byte slice into a `Vec<X509>`.
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `RootCertStore` constructed from the added certificates,
    /// or an error if parsing or building the certificate store fails.
    fn load_certs<C, F>(certs: C, x509: F) -> Result<RootCertStore, Error>
    where
        C: AsRef<[u8]>,
        F: Fn(&[u8]) -> Result<Vec<X509>, ErrorStack>,
    {
        let mut cert_store = X509StoreBuilder::new()?;

        let certs = x509(certs.as_ref())?;
        let (valid_count, invalid_count) = Self::process_certs(certs.into_iter(), &mut cert_store);

        if valid_count == 0 && invalid_count > 0 {
            log::warn!("all certificates are invalid");
            cert_store.set_default_paths()?;
        }

        Ok(RootCertStore(cert_store.build()))
    }

    /// Parses certificates from an iterator of byte slices and adds them to a new `RootCertStore`.
    ///
    /// This method works for cases where certificates are provided as an iterator.
    /// Each item is parsed individually using the supplied parsing function.
    /// Successfully parsed certificates are then added to an `X509StoreBuilder`
    /// with the outcome (success or failure) being recorded.
    ///
    /// If none of the certificates is successfully added but some attempted additions failed,
    /// the method falls back to setting the system’s default certificate paths.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator where each element is a byte slice representing an encoded certificate.
    /// - `x509`: A function that parses a certificate from the provided byte slice.
    ///
    /// # Returns
    ///
    /// A `Result` containing the constructed `RootCertStore` on success,
    /// or an error if the parsing or building process fails.
    fn load_certs_from_iter<C, F>(certs: C, x509: F) -> Result<RootCertStore, Error>
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
        F: Fn(&[u8]) -> Result<X509, ErrorStack>,
    {
        let mut cert_store = X509StoreBuilder::new()?;

        let certs = certs
            .into_iter()
            .filter_map(|data| match x509(data.as_ref()) {
                Ok(cert) => Some(cert),
                Err(err) => {
                    log::debug!("tls failed to parse certificate: {err:?}");
                    None
                }
            });
        let (valid_count, invalid_count) = Self::process_certs(certs, &mut cert_store);

        if valid_count == 0 && invalid_count > 0 {
            log::warn!("all certificates are invalid");
            cert_store.set_default_paths()?;
        }

        Ok(RootCertStore(cert_store.build()))
    }

    /// Processes an iterator of parsed certificates by attempting to add each one to the certificate store.
    ///
    /// For each certificate in the provided iterator, this method attempts to add it to the given
    /// `X509StoreBuilder`. It records the number of successful additions (`valid_count`)
    /// and the number of failures (`invalid_count`). This information is used by the calling functions
    /// to determine whether to fall back to using the default certificate paths.
    ///
    /// # Parameters
    ///
    /// - `iter`: An iterator over parsed certificates (`X509`).
    /// - `cert_store`: A mutable reference to an `X509StoreBuilder` where certificates are added.
    ///
    /// # Returns
    ///
    /// A tuple `(valid_count, invalid_count)` where:
    /// - `valid_count` is the number of certificates successfully added.
    /// - `invalid_count` is the number of certificates that failed to be added.
    fn process_certs<I>(iter: I, cert_store: &mut X509StoreBuilder) -> (i32, i32)
    where
        I: Iterator<Item = X509>,
    {
        let mut valid_count = 0;
        let mut invalid_count = 0;
        for cert in iter {
            if cert_store.add_cert(cert).is_ok() {
                valid_count += 1;
            } else {
                invalid_count += 1;
                log::debug!("tls failed to add certificate");
            }
        }
        (valid_count, invalid_count)
    }
}

/// The root certificate store.
#[derive(Default)]
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
