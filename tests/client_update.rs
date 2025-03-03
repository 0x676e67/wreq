#![cfg(not(target_arch = "wasm32"))]
mod support;

use rquest::{EmulationProvider, TlsConfig};
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

    let client = rquest::Client::new();

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
async fn update_emulation() {
    let _ = env_logger::try_init();
    let server = server::http(move |req| async move {
        assert_eq!(
            req.headers().get(http::header::ACCEPT).unwrap(),
            "application/json"
        );
        http::Response::default()
    });

    let client = rquest::Client::new();

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
