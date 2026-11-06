#![cfg(feature = "tokio-rt")]

use std::{net::SocketAddr, pin::Pin};

use btls::{
    pkey::PKey,
    ssl::{Ssl, SslAcceptor, SslAcceptorBuilder, SslMethod, SslVersion},
    x509::X509,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use wreq::{
    Client, ClientBuilder, Response,
    tls::{TlsInfo, trust::CertStore},
};

// Issued by LOCALHOST_CA for localhost and 127.0.0.1.
const LOCALHOST_CERT: &[u8] = include_bytes!("support/localhost.cert");
const LOCALHOST_KEY: &[u8] = include_bytes!("support/localhost.key");
const LOCALHOST_CA: &[u8] = include_bytes!("support/localhost-ca.cert");

/// Builds an acceptor for a DER certificate and private key.
fn acceptor(certificate: &[u8], private_key: &[u8]) -> SslAcceptorBuilder {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_der(certificate).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_der(private_key).unwrap())
        .unwrap();
    acceptor
}

/// Answers every TLS connection with an empty HTTP/1.1 response.
async fn serve_with(acceptor: SslAcceptor) -> SocketAddr {
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

/// Serves a self-signed certificate for `wreq.test` and `192.0.2.1`.
async fn serve() -> (SocketAddr, Vec<u8>) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["wreq.test".into(), "192.0.2.1".into()]).unwrap();
    let der = cert.cert.der().to_vec();
    let acceptor = acceptor(&der, &cert.signing_key.serialize_der()).build();
    (serve_with(acceptor).await, der)
}

async fn send(builder: ClientBuilder, url: &str) -> wreq::Result<Response> {
    builder.no_proxy().build().unwrap().get(url).send().await
}

/// Returns whether the request failed certificate verification.
fn is_untrusted(result: wreq::Result<Response>) -> bool {
    result.is_err_and(|err| format!("{err:?}").contains("CERTIFICATE_VERIFY_FAILED"))
}

#[tokio::test]
async fn verify_host_overrides_uri_host() {
    let (addr, der) = serve().await;
    let url = format!("https://{addr}/");

    let get = |host: &'static str| {
        let store = CertStore::builder()
            .add_der_cert(&der)
            .verify_host(host)
            .build()
            .unwrap();
        let client = Client::builder_tokio()
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

#[tokio::test]
async fn ca_issued_certificate_verifies_over_tls13() {
    // TLS 1.3 only, as in Mozilla's modern server configuration.
    let mut acceptor = acceptor(LOCALHOST_CERT, LOCALHOST_KEY);
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let url = format!("https://{}/", serve_with(acceptor.build()).await);

    // Default trust does not include the test CA; a store holding it verifies the chain and host.
    assert!(is_untrusted(send(Client::builder_tokio(), &url).await));
    let store = CertStore::builder()
        .add_der_cert(LOCALHOST_CA)
        .build()
        .unwrap();
    let response = send(Client::builder_tokio().tls_cert_store(store), &url)
        .await
        .unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn self_signed_certificate_requires_explicit_trust() {
    let (addr, der) = serve().await;
    let url = format!("https://{addr}/");

    // Default trust rejects it, and skipping the hostname check does not trust it.
    assert!(is_untrusted(send(Client::builder_tokio(), &url).await));
    assert!(is_untrusted(
        send(Client::builder_tokio().tls_verify_hostname(false), &url).await
    ));

    // Without verification the handshake succeeds; TLS info is attached only when enabled.
    let builder = Client::builder_tokio()
        .tls_cert_verification(false)
        .tls_info(true);
    let response = send(builder, &url).await.unwrap();
    let info = response.extensions().get::<TlsInfo>().unwrap();
    assert_eq!(info.peer_certificate(), Some(der.as_slice()));
    let response = send(Client::builder_tokio().tls_cert_verification(false), &url)
        .await
        .unwrap();
    assert!(response.extensions().get::<TlsInfo>().is_none());

    // A store trusting the certificate verifies the requested DNS name against its SAN.
    let store = CertStore::builder().add_der_cert(&der).build().unwrap();
    let named = |host: &'static str| {
        Client::builder_tokio()
            .resolve(host, addr)
            .tls_cert_store(store.clone())
    };
    let port = addr.port();
    let response = send(named("wreq.test"), &format!("https://wreq.test:{port}/"))
        .await
        .unwrap();
    assert!(response.status().is_success());
    let other = format!("https://other.test:{port}/");
    assert!(is_untrusted(send(named("other.test"), &other).await));
    let builder = named("other.test").tls_verify_hostname(false);
    assert!(send(builder, &other).await.unwrap().status().is_success());
}
