#![allow(missing_debug_implementations)]

mod identity;
mod store;

pub use self::identity::Identity;
pub use self::store::{CertStore, CertStoreBuilder};
use boring2::x509::X509;

#[cfg(any(feature = "webpki-roots", feature = "native-roots"))]
pub(super) static LOAD_CERTS: std::sync::LazyLock<Option<CertStore>> =
    std::sync::LazyLock::new(|| {
        #[cfg(feature = "webpki-roots")]
        let res = CertStore::from_der_certs(webpki_root_certs::TLS_SERVER_ROOT_CERTS);

        #[cfg(all(feature = "native-roots", not(feature = "webpki-roots")))]
        let res = CertStore::from_der_certs(&rustls_native_certs::load_native_certs().certs);

        match res {
            Ok(store) => Some(store),
            Err(err) => {
                log::error!("tls failed to load root certificates: {err}");
                None
            }
        }
    });

/// A certificate input.
pub enum CertificateInput<'c> {
    /// Raw DER or PEM data.
    Raw(&'c [u8]),
    /// An already parsed certificate.
    Parsed(Certificate),
}

impl<'a> CertificateInput<'a> {
    pub(crate) fn with_parser<F>(self, parser: F) -> crate::Result<Certificate>
    where
        F: Fn(&'a [u8]) -> crate::Result<Certificate>,
    {
        match self {
            CertificateInput::Raw(data) => parser(data),
            CertificateInput::Parsed(cert) => Ok(cert),
        }
    }
}

impl From<Certificate> for CertificateInput<'_> {
    fn from(cert: Certificate) -> Self {
        CertificateInput::Parsed(cert)
    }
}

impl<'c, T: AsRef<[u8]> + ?Sized + 'c> From<&'c T> for CertificateInput<'c> {
    fn from(value: &'c T) -> CertificateInput<'c> {
        CertificateInput::Raw(value.as_ref())
    }
}

/// A certificate.
#[derive(Clone)]
pub struct Certificate(X509);

impl Certificate {
    /// Parse a certificate from DER or PEM data.
    pub fn from<C: AsRef<[u8]>>(cert: C) -> crate::Result<Self> {
        let cert = cert.as_ref();
        let parser = if cert.len() >= 10 {
            // Quick check: if data starts with "-----BEGIN"
            if cert.starts_with(b"-----BEGIN") {
                X509::from_pem
            } else {
                // Try to skip leading whitespace
                let start = cert
                    .iter()
                    .position(|&b| !b.is_ascii_whitespace())
                    .unwrap_or(0);

                if cert[start..].starts_with(b"-----BEGIN") {
                    X509::from_pem
                } else {
                    X509::from_der
                }
            }
        } else {
            X509::from_der
        };

        parser(cert).map(Self).map_err(Into::into)
    }

    /// Parse a certificate from DER data.
    #[inline(always)]
    pub fn from_der<C: AsRef<[u8]>>(cert: C) -> crate::Result<Self> {
        X509::from_der(cert.as_ref()).map(Self).map_err(Into::into)
    }

    /// Parse a certificate from PEM data.
    #[inline(always)]
    pub fn from_pem<C: AsRef<[u8]>>(cert: C) -> crate::Result<Self> {
        X509::from_pem(cert.as_ref()).map(Self).map_err(Into::into)
    }

    /// Parse a stack of certificates from DER data.
    #[inline(always)]
    pub fn stack_from_pem<C: AsRef<[u8]>>(cert: C) -> crate::Result<Vec<Self>> {
        let certs = X509::stack_from_pem(cert.as_ref())?;
        Ok(certs.into_iter().map(Self).collect())
    }
}
