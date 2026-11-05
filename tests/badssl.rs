#![cfg(feature = "tokio-rt")]

use std::{error::Error as StdError, io};

use wreq::{
    Client, retry,
    tls::{TlsInfo, trust::CertStore},
};

fn badssl_connection_reset_retry_policy() -> retry::Policy {
    retry::Policy::default()
        .max_retries_per_request(10)
        .no_budget()
        .classify_fn(|req_rep| {
            if req_rep.error().is_some_and(is_connection_reset) {
                req_rep.retryable()
            } else {
                req_rep.success()
            }
        })
}

fn is_connection_reset(err: &(dyn StdError + 'static)) -> bool {
    let mut source = Some(err);

    while let Some(err) = source {
        if let Some(io) = err.downcast_ref::<io::Error>()
            && io.kind() == io::ErrorKind::ConnectionReset
        {
            return true;
        }

        source = err.source();
    }

    false
}

#[tokio::test]
async fn test_badssl_modern() {
    let text = Client::builder_tokio()
        .no_proxy()
        .retry(badssl_connection_reset_retry_policy())
        .build()
        .unwrap()
        .get("https://mozilla-modern.badssl.com/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(text.contains("<title>mozilla-modern.badssl.com</title>"));
}

#[tokio::test]
async fn test_badssl_self_signed() {
    let text = Client::builder_tokio()
        .tls_cert_verification(false)
        .no_proxy()
        .retry(badssl_connection_reset_retry_policy())
        .build()
        .unwrap()
        .get("https://self-signed.badssl.com/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(text.contains("<title>self-signed.badssl.com</title>"));
}

#[tokio::test]
async fn test_badssl_wrong_host() {
    let text = Client::builder_tokio()
        .tls_verify_hostname(false)
        .no_proxy()
        .retry(badssl_connection_reset_retry_policy())
        .build()
        .unwrap()
        .get("https://wrong.host.badssl.com/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(text.contains("<title>wrong.host.badssl.com</title>"));

    let result = Client::builder_tokio()
        .tls_verify_hostname(false)
        .no_proxy()
        .build()
        .unwrap()
        .get("https://self-signed.badssl.com/")
        .send()
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_tls_self_signed_cert() {
    let client = Client::builder_tokio()
        .tls_cert_verification(false)
        .tls_info(true)
        .retry(badssl_connection_reset_retry_policy())
        .no_proxy()
        .build()
        .unwrap();

    let resp = client
        .get("https://self-signed.badssl.com/")
        .send()
        .await
        .unwrap();

    let peer_cert_der = resp
        .extensions()
        .get::<TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .unwrap();

    let self_signed_cert_store = CertStore::builder()
        .add_der_cert(peer_cert_der)
        .build()
        .unwrap();

    let client = Client::builder_tokio()
        .tls_cert_store(self_signed_cert_store)
        .retry(badssl_connection_reset_retry_policy())
        .no_proxy()
        .build()
        .unwrap();

    let resp = client
        .get("https://self-signed.badssl.com/")
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let res = client.get("https://www.google.com").send().await;
    assert!(res.is_err());
}
