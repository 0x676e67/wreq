#[path = "support/tls_cert.rs"]
mod tls_cert;

use std::{net::SocketAddr, pin::Pin};

use btls::{
    pkey::{PKey, Private},
    ssl::Ssl,
    x509::X509,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use wreq::{Client, tls::trust::CertStore};

async fn serve(cert: &X509, key: &PKey<Private>) -> SocketAddr {
    let acceptor = tls_cert::acceptor(cert, key);

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
    let (cert, key) = tls_cert::self_signed("wreq.test", [192, 0, 2, 1].into());
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
