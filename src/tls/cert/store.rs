#![allow(missing_debug_implementations)]
#![allow(dead_code)]
use std::path::Path;

use crate::{
    error,
    tls::{cert::load, TlsResult},
    Error,
};
use boring2::{
    error::ErrorStack,
    ssl::SslConnectorBuilder,
    x509::{
        store::{X509Store, X509StoreBuilder},
        X509,
    },
};

/// A collection of certificates Store.
pub struct RootCertStore(X509Store);

/// ====== impl RootCertStore ======
impl RootCertStore {
    /// Creates a new `RootCertStore` from a collection of PEM-encoded certificates.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over PEM-encoded certificates.
    ///
    /// # Returns
    ///
    /// A `TlsResult` containing the new `RootCertStore`.
    pub fn from_pem_certificates<C>(certs: C) -> Result<RootCertStore, Error>
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        Self::load_certificates(certs.into_iter().map(|cert| X509::from_pem(cert.as_ref())))
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

    /// Creates a new `RootCertStore` from a collection of DER-encoded certificates.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over DER-encoded certificates.
    ///
    /// # Returns
    ///
    /// A `TlsResult` containing the new `RootCertStore`.
    pub fn from_der_certificates<C>(certs: C) -> Result<RootCertStore, Error>
    where
        C: IntoIterator,
        C::Item: AsRef<[u8]>,
    {
        Self::load_certificates(certs.into_iter().map(|cert| X509::from_der(cert.as_ref())))
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
    pub fn from_pem_stack<C>(certs: C) -> Result<RootCertStore, Error>
    where
        C: AsRef<[u8]>,
    {
        let mut builder = X509StoreBuilder::new()?;
        for cert in X509::stack_from_pem(certs.as_ref())? {
            builder.add_cert(cert)?;
        }

        Ok(RootCertStore(builder.build()))
    }

    /// Loads certificates from an iterator.
    ///
    /// # Parameters
    ///
    /// - `certs`: An iterator over results of `X509` certificates.
    ///
    /// # Returns
    ///
    /// A `TlsResult` containing the new `RootCertStore`.
    pub fn load_certificates<I>(certs: I) -> Result<RootCertStore, Error>
    where
        I: Iterator<Item = Result<X509, ErrorStack>>,
    {
        let mut valid_count = 0;
        let mut invalid_count = 0;
        let mut cert_store = X509StoreBuilder::new()?;

        for cert in certs {
            match cert {
                Ok(cert) => {
                    cert_store.add_cert(cert)?;
                    valid_count += 1;
                }
                Err(err) => {
                    invalid_count += 1;
                    log::debug!("tls failed to parse DER certificate: {err:?}");
                }
            }
        }

        if valid_count == 0 && invalid_count > 0 {
            log::warn!("all certificates are invalid");
            cert_store.set_default_paths()?;
        }

        Ok(RootCertStore(cert_store.build()))
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
                    if let Some(cert_store) = load::LOAD_CERTS.as_ref() {
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
