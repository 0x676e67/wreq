#![cfg(not(target_arch = "wasm32"))]
mod support;

use std::time::Duration;

use http::header::{AUTHORIZATION, CACHE_CONTROL, REFERER};
use http_body_util::BodyExt;
use wreq::{CertStore, EmulationProvider, TlsConfig, TlsInfo};
use support::server;

#[tokio::test]
async fn update_headers() {
    let _ = env_logger::try_init();
    let server = server::http(move |req| async move {
        assert_eq!(
            req.headers().get(http::header::ACCEPT).unwrap(),
            "application/json"
        );
        http::Response::default()
    });

    let client = wreq::Client::new();

    client
        .update()
        .headers(|headers| {
            headers.insert(
                http::header::ACCEPT,
                http::HeaderValue::from_static("application/json"),
            );
        })
        .apply()
        .unwrap();

    let url = format!("http://{}", server.addr());
    let resp = client.get(url).send().await.unwrap();
    assert!(resp.status().is_success());
    assert!(client.headers().contains_key(http::header::ACCEPT));

    let client2 = client.clone();
    tokio::spawn(async move {
        client2
            .update()
            .headers(|headers| {
                headers.insert(
                    http::header::ACCEPT_ENCODING,
                    http::HeaderValue::from_static("gzip"),
                );
            })
            .apply()
            .unwrap();
    })
    .await
    .unwrap();

    let server = server::http(move |req| async move {
        assert_eq!(
            req.headers().get(http::header::ACCEPT_ENCODING).unwrap(),
            "gzip"
        );
        http::Response::default()
    });

    let url = format!("http://{}", server.addr());
    let resp = client.get(url).send().await.unwrap();
    assert!(resp.status().is_success());
    assert!(client.headers().contains_key(http::header::ACCEPT_ENCODING));
}

#[tokio::test]
async fn test_headers_order_with_client_update() {
    use http::{HeaderName, HeaderValue};
    use wreq::Client;
    use wreq::header::{ACCEPT, CONTENT_TYPE, USER_AGENT};

    let server = server::http(move |req| async move {
        assert_eq!(req.method(), "POST");

        let expected_headers = vec![
            ("user-agent", "my-test-client"),
            ("accept", "*/*"),
            ("cookie", "cookie1=cookie1"),
            ("cookie", "cookie2=cookie2"),
            ("content-type", "application/json"),
            ("authorization", "Bearer test-token"),
            ("referer", "https://example.com"),
            ("cache-control", "no-cache"),
        ];

        for (i, (expected_key, expected_value)) in expected_headers.iter().enumerate() {
            let (key, value) = req.headers().iter().nth(i).unwrap();
            assert_eq!(key.as_str(), *expected_key);
            assert_eq!(value.as_bytes(), expected_value.as_bytes());
        }

        let full: Vec<u8> = req
            .into_body()
            .collect()
            .await
            .expect("must succeed")
            .to_bytes()
            .to_vec();

        assert_eq!(full, br#"{"message":"hello"}"#);

        http::Response::default()
    });

    let url = format!("http://{}/test", server.addr());

    let client = Client::builder().no_proxy().build().unwrap();

    client
        .update()
        .headers(|headers| {
            headers.clear();
            headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(USER_AGENT, HeaderValue::from_static("my-test-client"));
            headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer test-token"));
            headers.insert(REFERER, HeaderValue::from_static("https://example.com"));
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            headers.append("cookie", HeaderValue::from_static("cookie1=cookie1"));
            headers.append("cookie", HeaderValue::from_static("cookie2=cookie2"));
        })
        .headers_order(vec![
            HeaderName::from_static("user-agent"),
            HeaderName::from_static("accept"),
            HeaderName::from_static("cookie"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("authorization"),
            HeaderName::from_static("referer"),
            HeaderName::from_static("cache-control"),
        ])
        .apply()
        .unwrap();

    let res = client
        .post(&url)
        .body(r#"{"message":"hello"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn update_emulation() {
    let _ = env_logger::try_init();
    let server = server::http(move |req| async move {
        assert_eq!(
            req.headers().get(http::header::ACCEPT).unwrap(),
            "application/json"
        );
        http::Response::default()
    });

    let client = wreq::Client::new();

    client
        .update()
        .emulation(
            EmulationProvider::builder()
                .tls_config(TlsConfig::default())
                .default_headers({
                    let mut headers = http::HeaderMap::new();
                    headers.insert(
                        http::header::ACCEPT,
                        http::HeaderValue::from_static("application/json"),
                    );
                    headers
                })
                .build(),
        )
        .apply()
        .unwrap();

    let url = format!("http://{}", server.addr());
    let resp = client.get(url).send().await.unwrap();
    assert!(resp.status().is_success());
    assert!(client.headers().contains_key(http::header::ACCEPT));

    let client2 = client.clone();
    tokio::spawn(async move {
        client2
            .update()
            .emulation(
                EmulationProvider::builder()
                    .tls_config(TlsConfig::default())
                    .default_headers({
                        let mut headers = http::HeaderMap::new();
                        headers.insert(
                            http::header::ACCEPT_ENCODING,
                            http::HeaderValue::from_static("gzip"),
                        );
                        headers
                    })
                    .build(),
            )
            .apply()
            .unwrap();
    })
    .await
    .unwrap();

    let server = server::http(move |req| async move {
        assert_eq!(
            req.headers().get(http::header::ACCEPT_ENCODING).unwrap(),
            "gzip"
        );
        http::Response::default()
    });

    let url = format!("http://{}", server.addr());
    let resp = client.get(url).send().await.unwrap();
    assert!(resp.status().is_success());
    assert!(client.headers().contains_key(http::header::ACCEPT_ENCODING));
}

#[tokio::test]
async fn updatea_cloned() {
    let _ = env_logger::try_init();
    let server = server::http(move |req| async move {
        assert_eq!(
            req.headers().get(http::header::ACCEPT).unwrap(),
            "application/json"
        );
        http::Response::default()
    });

    let client = wreq::Client::new();

    client
        .update()
        .emulation(
            EmulationProvider::builder()
                .tls_config(TlsConfig::default())
                .default_headers({
                    let mut headers = http::HeaderMap::new();
                    headers.insert(
                        http::header::ACCEPT,
                        http::HeaderValue::from_static("application/json"),
                    );
                    headers
                })
                .build(),
        )
        .apply()
        .unwrap();

    let url = format!("http://{}", server.addr());
    let resp = client.get(url).send().await.unwrap();
    assert!(resp.status().is_success());
    assert!(client.headers().contains_key(http::header::ACCEPT));

    let client2 = client.cloned();
    client2
        .update()
        .emulation(
            EmulationProvider::builder()
                .tls_config(TlsConfig::default())
                .default_headers({
                    let mut headers = http::HeaderMap::new();
                    headers.insert(
                        http::header::ACCEPT_ENCODING,
                        http::HeaderValue::from_static("gzip"),
                    );
                    headers
                })
                .build(),
        )
        .apply()
        .unwrap();

    let server = server::http(move |req| async move {
        assert_ne!(
            req.headers().get(http::header::ACCEPT_ENCODING),
            Some(&http::HeaderValue::from_static("gzip"))
        );
        http::Response::default()
    });

    let url = format!("http://{}", server.addr());
    let resp = client.get(url).send().await.unwrap();
    assert!(resp.status().is_success());
    assert!(!client.headers().contains_key(http::header::ACCEPT_ENCODING));
}

#[tokio::test]
async fn update_ssl_verify() {
    let client = wreq::Client::builder()
        .connect_timeout(Duration::from_secs(360))
        .cert_verification(false)
        .no_proxy()
        .build()
        .unwrap();

    let res = client.get("https://self-signed.badssl.com/").send().await;
    assert!(res.is_ok());

    client
        .update()
        .emulation(EmulationProvider::default())
        .apply()
        .unwrap();

    let res = client.get("https://self-signed.badssl.com/").send().await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn update_ssl_certs_verify_stroe() {
    let client = wreq::Client::builder()
        .connect_timeout(Duration::from_secs(360))
        .cert_verification(false)
        .tls_info(true)
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

    let store = CertStore::builder()
        .add_der_cert(peer_cert_der)
        .build()
        .unwrap();

    let client = wreq::Client::builder()
        .cert_store(store)
        .connect_timeout(Duration::from_secs(360))
        .no_proxy()
        .build()
        .unwrap();

    let res = client.get("https://self-signed.badssl.com/").send().await;
    assert!(res.is_ok());

    client
        .update()
        .emulation(EmulationProvider::default())
        .apply()
        .unwrap();

    let res = client.get("https://self-signed.badssl.com/").send().await;
    assert!(res.is_ok());
}
