mod identity;
mod store;

pub use self::identity::Identity;
pub use self::store::{CertStore, CertStoreBuilder};

#[cfg(any(feature = "webpki-roots", feature = "native-roots"))]
pub(super) static LOAD_CERTS: std::sync::LazyLock<Option<CertStore>> =
    std::sync::LazyLock::new(|| {
        #[cfg(feature = "webpki-roots")]
        let res = CertStore::from_der_certs(webpki_root_certs::TLS_SERVER_ROOT_CERTS);

        #[cfg(all(feature = "native-roots", not(feature = "webpki-roots")))]
        let res = CertStore::from_der_certs(rustls_native_certs::load_native_certs().certs);

        match res {
            Ok(store) => Some(store),
            Err(err) => {
                log::error!("tls failed to load root certificates: {err}");
                None
            }
        }
    });
