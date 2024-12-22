//! Certificate imports for the boringssl.
use boring::x509::{store::X509StoreBuilder, X509};
use boring::{error::ErrorStack, x509::store::X509Store};
use std::sync::LazyLock;

pub static LOAD_CERTS: LazyLock<Result<X509Store, crate::Error>> = LazyLock::new(|| {
    #[cfg(feature = "boring-tls-webpki-roots")]
    {
        load_certs_from_source(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|c| X509::from_der(c)),
        )
    }

    #[cfg(all(
        feature = "boring-tls-native-roots",
        not(feature = "boring-tls-webpki-roots")
    ))]
    {
        load_certs_from_source(
            rustls_native_certs::load_native_certs()
                .iter()
                .map(|c| X509::from_der(&*c)),
        )
    }
});

pub fn load_certs_from_source<I>(certs: I) -> Result<X509Store, crate::Error>
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
        return Err(crate::Error::new(
            crate::error::Kind::Builder,
            Some("all certificates are invalid"),
        ));
    }

    Ok(cert_store.build())
}
