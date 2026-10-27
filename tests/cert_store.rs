use std::{net::SocketAddr, pin::Pin};

use btls::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{Ssl, SslAcceptor, SslMethod},
    x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use wreq::{Client, tls::trust::CertStore};

/// Self-signed certificate valid for `wreq.test` and `192.0.2.1`.
fn self_signed() -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "wreq test")
        .unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("wreq.test")
        .ip("192.0.2.1")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(&san).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();

    (builder.build(), key)
}

async fn serve(cert: &X509, key: &PKey<Private>) -> SocketAddr {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_certificate(cert).unwrap();
    acceptor.set_private_key(key).unwrap();
    let acceptor = acceptor.build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let mut stream = tokio_btls::SslStream::new(ssl, tcp).unwrap();
            tokio::spawn(async move {
                if Pin::new(&mut stream).accept().await.is_ok() {
                    let mut buf = [0; 1024];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                        .await;
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn verify_host_overrides_uri_host() {
    let (cert, key) = self_signed();
    let der = cert.to_der().unwrap();
    let url = format!("https://{}/", serve(&cert, &key).await);

    let get = |host: &'static str| {
        let store = CertStore::builder()
            .add_der_cert(&der)
            .verify_host(host)
            .build()
            .unwrap();
        let client = Client::builder()
            .tls_cert_store(store)
            .tls_verify_hostname(false)
            .no_proxy()
            .build()
            .unwrap();
        client.get(&url).send()
    };

    // The URI names 127.0.0.1, which the certificate does not cover.
    assert!(get("wreq.test").await.unwrap().status().is_success());
    assert!(get("192.0.2.1").await.unwrap().status().is_success());
    assert!(get("other.test").await.is_err());
}
