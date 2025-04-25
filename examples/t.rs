use boring2::x509::{self, store::X509StoreBuilder};

fn main() {
    // time
    let now = std::time::Instant::now();
    let mut certs = Vec::with_capacity(webpki_root_certs::TLS_SERVER_ROOT_CERTS.len());
    for ele in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        let cert = x509::X509::from_der(&ele).unwrap();
        certs.push(cert);
    }
    println!("Parsed {} certs in {:?}", certs.len(), now.elapsed());

    let time = std::time::Instant::now();
    let mut builder = X509StoreBuilder::new().unwrap();
    for cert in &certs {
        builder.add_cert(cert.clone()).unwrap();
    }
    let _ = builder.build();
    println!("Built store in {:?}", time.elapsed());
}
