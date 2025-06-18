use std::sync::Arc;

use boring2::x509::store::X509StoreBuilder;

use super::{CertStore, Certificate, CertificateInput};
use crate::Error;

pub fn parse_certs_with_iter<'c, I>(
    certs: I,
    parser: fn(&'c [u8]) -> crate::Result<Certificate>,
) -> crate::Result<CertStore>
where
    I: IntoIterator,
    I::Item: Into<CertificateInput<'c>>,
{
    let mut store = X509StoreBuilder::new()?;
    let certs = filter_map_certs(certs, parser);
    process_certs_with_builder(certs.into_iter(), &mut store)?;
    Ok(CertStore(Arc::new(store.build())))
}

pub fn parse_certs_with_stack<C, F>(certs: C, x509: F) -> crate::Result<CertStore>
where
    C: AsRef<[u8]>,
    F: Fn(C) -> crate::Result<Vec<Certificate>>,
{
    let mut store = X509StoreBuilder::new()?;
    let certs = x509(certs)?;
    process_certs_with_builder(certs.into_iter(), &mut store)?;
    Ok(CertStore(Arc::new(store.build())))
}

pub fn process_certs_with_builder<I>(iter: I, store: &mut X509StoreBuilder) -> crate::Result<()>
where
    I: Iterator<Item = Certificate>,
{
    let mut valid_count = 0;
    let mut invalid_count = 0;
    for cert in iter {
        if let Err(_err) = store.add_cert(cert.0) {
            invalid_count += 1;
            warn!("tls failed to parse certificate: {:?}", _err);
        } else {
            valid_count += 1;
        }
    }

    if valid_count == 0 && invalid_count > 0 {
        return Err(Error::builder("invalid certificate"));
    }

    Ok(())
}

pub fn filter_map_certs<'c, I>(
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
            Err(_err) => {
                warn!("tls failed to parse certificate: {:?}", _err);
                None
            }
        })
}
