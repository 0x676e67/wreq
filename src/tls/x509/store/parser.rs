use super::{CertStore, Certificate, CertificateInput};
use boring2::x509::store::X509StoreBuilder;

pub fn parse_certs_from_iter<'c, I>(
    certs: I,
    parser: fn(&'c [u8]) -> crate::Result<Certificate>,
) -> crate::Result<CertStore>
where
    I: IntoIterator,
    I::Item: Into<CertificateInput<'c>>,
{
    let mut store = X509StoreBuilder::new()?;
    let certs = filter_map_certs(certs, parser);
    process_certs(certs.into_iter(), &mut store)?;
    Ok(CertStore(store.build()))
}

pub fn parse_certs_from_stack<C, F>(certs: C, x509: F) -> crate::Result<CertStore>
where
    C: AsRef<[u8]>,
    F: Fn(C) -> crate::Result<Vec<Certificate>>,
{
    let mut store = X509StoreBuilder::new()?;
    let certs = x509(certs)?;
    process_certs(certs.into_iter(), &mut store)?;
    Ok(CertStore(store.build()))
}

pub fn process_certs<I>(iter: I, store: &mut X509StoreBuilder) -> crate::Result<()>
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
            Err(err) => {
                log::warn!("tls failed to parse certificate: {err:?}");
                None
            }
        })
}
