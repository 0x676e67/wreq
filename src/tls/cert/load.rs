//! Certificate imports for the boringssl.
use super::store::RootCertStore;
use std::sync::LazyLock;

pub static LOAD_CERTS: LazyLock<Option<RootCertStore>> = LazyLock::new(|| {
    #[cfg(feature = "webpki-roots")]
    let res = RootCertStore::from_der_certs(webpki_root_certs::TLS_SERVER_ROOT_CERTS);

    #[cfg(all(feature = "native-roots", not(feature = "webpki-roots")))]
    let res = RootCertStore::from_der_certs(rustls_native_certs::load_native_certs().certs);

    match res {
        Ok(store) => Some(store),
        Err(err) => {
            log::error!("tls failed to load root certificates: {err}");
            None
        }
    }
});
