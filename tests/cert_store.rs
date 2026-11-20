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
    start_tls_server(listener, acceptor)
}

fn start_tls_server(listener: TcpListener, acceptor: btls::ssl::SslAcceptor) -> SocketAddr {
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

async fn send(builder: wreq::ClientBuilder, url: &str) -> wreq::Result<wreq::Response> {
    builder.no_proxy().build().unwrap().get(url).send().await
}

fn assert_verification_failure(result: wreq::Result<wreq::Response>) {
    let error = result.unwrap_err();
    assert!(
        format!("{error:?}").contains("CERTIFICATE_VERIFY_FAILED"),
        "{error:?}"
    );
}

#[tokio::test]
async fn ca_issued_certificate_verifies_over_tls13() {
    use btls::ssl::{SslAcceptor, SslMethod, SslVersion};

    // Issued by LOCALHOST_CA for localhost and 127.0.0.1.
    const LOCALHOST_CERT: &[u8] = include_bytes!("support/localhost.cert");
    const LOCALHOST_KEY: &[u8] = include_bytes!("support/localhost.key");
    const LOCALHOST_CA: &[u8] = include_bytes!("support/localhost-ca.cert");

    let cert = X509::from_der(LOCALHOST_CERT).unwrap();
    let key = PKey::private_key_from_der(LOCALHOST_KEY).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}/", start_tls_server(listener, acceptor.build()));

    assert_verification_failure(send(Client::builder(), &url).await);
    let store = CertStore::builder()
        .add_der_cert(LOCALHOST_CA)
        .build()
        .unwrap();
    let response = send(Client::builder().tls_cert_store(store), &url)
        .await
        .unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn self_signed_certificate_requires_explicit_trust() {
    use wreq::tls::TlsInfo;

    let (cert, key) = tls_cert::self_signed("wreq.test", [127, 0, 0, 1].into());
    let addr = serve(&cert, &key).await;
    let url = format!("https://{addr}/");

    assert_verification_failure(send(Client::builder(), &url).await);
    assert_verification_failure(send(Client::builder().tls_verify_hostname(false), &url).await);

    let builder = Client::builder()
        .tls_cert_verification(false)
        .tls_info(true);
    let response = send(builder, &url).await.unwrap();
    assert!(response.status().is_success());
    let peer_cert = response
        .extensions()
        .get::<TlsInfo>()
        .and_then(TlsInfo::peer_certificate)
        .unwrap();
    assert_eq!(peer_cert, cert.to_der().unwrap().as_slice());

    let response = send(Client::builder().tls_cert_verification(false), &url)
        .await
        .unwrap();
    assert!(response.extensions().get::<TlsInfo>().is_none());

    let store = CertStore::builder().add_der_cert(peer_cert).build().unwrap();
    let named = |host: &'static str| {
        Client::builder()
            .resolve(host, addr)
            .tls_cert_store(store.clone())
    };
    let port = addr.port();
    let response = send(named("wreq.test"), &format!("https://wreq.test:{port}/"))
        .await
        .unwrap();
    assert!(response.status().is_success());
    let wrong_host = format!("https://other.test:{port}/");
    assert_verification_failure(send(named("other.test"), &wrong_host).await);
    let response = send(named("other.test").tls_verify_hostname(false), &wrong_host)
        .await
        .unwrap();
    assert!(response.status().is_success());

    // Both certificates cover loopback, but the trust store contains only the first.
    let (other_cert, other_key) = tls_cert::self_signed("wreq.test", addr.ip());
    let other_addr = serve(&other_cert, &other_key).await;
    let other_url = format!("https://{other_addr}/");
    assert_verification_failure(send(Client::builder().tls_cert_store(store), &other_url).await);
}
