use std::{net::SocketAddr, pin::Pin};

use btls::{
    pkey::PKey,
    ssl::{Ssl, SslAcceptor, SslMethod},
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

async fn serve() -> (SocketAddr, Vec<u8>) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["wreq.test".into(), "192.0.2.1".into()]).unwrap();
    let der = cert.cert.der().to_vec();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_der(&der).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_der(&cert.signing_key.serialize_der()).unwrap())
        .unwrap();
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
    (addr, der)
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

/// Returns whether the request failed certificate verification.
fn is_untrusted(result: wreq::Result<Response>) -> bool {
    result.is_err_and(|err| format!("{err:?}").contains("CERTIFICATE_VERIFY_FAILED"))
}

#[tokio::test]
async fn self_signed_certificate_requires_explicit_trust() {
    let (addr, der) = serve().await;
    let url = format!("https://{addr}/");
    let send =
        async |builder: ClientBuilder| builder.no_proxy().build().unwrap().get(&url).send().await;

    // Default trust rejects it, and skipping the hostname check does not trust it.
    assert!(is_untrusted(send(Client::builder_tokio()).await));
    assert!(is_untrusted(
        send(Client::builder_tokio().tls_verify_hostname(false)).await
    ));

    // Without verification the handshake succeeds; TLS info is attached only when enabled.
    let response = send(
        Client::builder_tokio()
            .tls_cert_verification(false)
            .tls_info(true),
    )
    .await
    .unwrap();
    let info = response.extensions().get::<TlsInfo>().unwrap();
    assert_eq!(info.peer_certificate(), Some(der.as_slice()));
    let response = send(Client::builder_tokio().tls_cert_verification(false))
        .await
        .unwrap();
    assert!(response.extensions().get::<TlsInfo>().is_none());

    // A store trusting the certificate still checks the URI host, 127.0.0.1.
    let store = CertStore::builder().add_der_cert(&der).build().unwrap();
    assert!(is_untrusted(
        send(Client::builder_tokio().tls_cert_store(store.clone())).await
    ));
    let response = send(
        Client::builder_tokio()
            .tls_cert_store(store)
            .tls_verify_hostname(false),
    )
    .await
    .unwrap();
    assert!(response.status().is_success());
}
