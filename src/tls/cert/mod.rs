pub mod compression;
#[cfg(any(feature = "webpki-roots", feature = "native-roots"))]
pub mod load;

use boring2::x509::store::X509Store;

/// The root certificate store.
#[allow(missing_debug_implementations)]
#[derive(Default)]
pub enum RootCertStore {
    /// An owned `X509Store`.
    Owned(X509Store),

    /// A borrowed `X509Store`.
    Borrowed(&'static X509Store),

    /// Use the system's native certificate store.
    #[default]
    Default,
}

/// ====== impl RootCertsStore ======
macro_rules! impl_root_cert_store {
    ($($type:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$type> for RootCertStore {
                fn from(store: $type) -> Self {
                    Self::$variant(store)
                }
            }
        )*
    };

    ($($type:ty => $variant:ident, $unwrap:expr),* $(,)?) => {
        $(
            impl From<$type> for RootCertStore {
                fn from(store: $type) -> Self {
                    $unwrap(store).map(Self::$variant).unwrap_or_default()
                }
            }
        )*
    };
}

impl_root_cert_store!(
    X509Store => Owned,
    &'static X509Store => Borrowed,
);

impl_root_cert_store!(
    Option<X509Store> => Owned, |s| s,
    Option<&'static X509Store> => Borrowed, |s| s,
);

impl<F> From<F> for RootCertStore
where
    F: Fn() -> Option<&'static X509Store>,
{
    fn from(func: F) -> Self {
        func().map(Self::Borrowed).unwrap_or_default()
    }
}
