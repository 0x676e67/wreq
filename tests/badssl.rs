use std::{error::Error as StdError, io};

use wreq::{Client, retry, tls::trust::CertStore};

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

/// Verifies a public certificate chain; local trust behavior is covered in `cert_store.rs`.
#[tokio::test]
async fn test_badssl_modern() {
    let url = "https://mozilla-modern.badssl.com/";
    let text = Client::builder_tokio()
        .no_proxy()
        .retry(badssl_connection_reset_retry_policy())
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(text.contains("<title>mozilla-modern.badssl.com</title>"));

    // A custom store replaces the default roots.
    let result = Client::builder_tokio()
        .tls_cert_store(CertStore::builder().build().unwrap())
        .no_proxy()
        .build()
        .unwrap()
        .get(url)
        .send()
        .await;

    assert!(result.is_err());
}
