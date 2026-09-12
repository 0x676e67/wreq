mod support;

#[cfg(feature = "json")]
use std::collections::HashMap;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, StatusCode, Version,
    header::{
        self, ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, REFERER,
        TRANSFER_ENCODING, USER_AGENT,
    },
};
use http_body_util::{BodyExt, Full};
use pretty_env_logger::env_logger;
use support::server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wreq::{Client, PoolStrategy, header::OrigHeaderMap, http1::Http1Options, tls::TlsInfo};

#[tokio::test]
async fn auto_headers() {
    let server = server::http(move |req| async move {
        assert_eq!(req.method(), "GET");

        assert_eq!(req.headers()["accept"], "*/*");
        assert_eq!(req.headers().get("user-agent"), None);
        if cfg!(feature = "gzip") {
            assert!(
                req.headers()["accept-encoding"]
                    .to_str()
                    .unwrap()
                    .contains("gzip")
            );
        }
        if cfg!(feature = "brotli") {
            assert!(
                req.headers()["accept-encoding"]
                    .to_str()
                    .unwrap()
                    .contains("br")
            );
        }
        if cfg!(feature = "zstd") {
            assert!(
                req.headers()["accept-encoding"]
                    .to_str()
                    .unwrap()
                    .contains("zstd")
            );
        }
        if cfg!(feature = "deflate") {
            assert!(
                req.headers()["accept-encoding"]
                    .to_str()
                    .unwrap()
                    .contains("deflate")
            );
        }

        http::Response::default()
    });

    let url = format!("http://{}/1", server.addr());
    let res = Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(&url)
        .header(wreq::header::ACCEPT, "*/*")
        .send()
        .await
        .unwrap();

    assert_eq!(res.uri(), url.as_str());
    assert_eq!(res.status(), wreq::StatusCode::OK);
    assert_eq!(res.remote_addr(), Some(server.addr()));
}

#[tokio::test]
async fn test_headers_order_with_client() {
    use http::HeaderValue;
    use wreq::{
        Client,
        header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
    };

    let server = server::http(move |req| async move {
        assert_eq!(req.method(), "POST");

        let expected_headers = [
            ("cookie", "cookie1=cookie1-value"),
            ("cookie", "cookie2=cookie2-value"),
            ("user-agent", "my-test-client"),
            ("accept", "*/*"),
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

    let client = Client::builder()
        .no_proxy()
        .default_headers({
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(USER_AGENT, HeaderValue::from_static("my-test-client"));
            headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer test-token"));
            headers.insert(REFERER, HeaderValue::from_static("https://example.com"));
            headers.append("cookie", HeaderValue::from_static("cookie1=cookie1-value"));
            headers.append("cookie", HeaderValue::from_static("cookie2=cookie2-value"));
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            headers
        })
        .orig_headers({
            let mut orig_headers = OrigHeaderMap::new();
            orig_headers.insert("cookie");
            orig_headers.insert("user-agent");
            orig_headers.insert("accept");
            orig_headers.insert("content-type");
            orig_headers.insert("authorization");
            orig_headers.insert("referer");
            orig_headers.insert("cache-control");
            orig_headers
        })
        .build()
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
async fn test_headers_order_with_request() {
    use http::HeaderValue;
    use wreq::{
        Client,
        header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
    };

    let server = server::http(move |req| async move {
        assert_eq!(req.method(), "POST");

        let expected_headers = [
            ("user-agent", "my-test-client"),
            ("accept", "*/*"),
            ("content-type", "application/json"),
            ("authorization", "Bearer test-token"),
            ("referer", "https://example.com"),
            ("cookie", "cookie1=cookie1"),
            ("cookie", "cookie2=cookie2"),
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

    let res = client
        .post(&url)
        .headers({
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(USER_AGENT, HeaderValue::from_static("my-test-client"));
            headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer test-token"));
            headers.insert(REFERER, HeaderValue::from_static("https://example.com"));
            headers.append("cookie", HeaderValue::from_static("cookie1=cookie1"));
            headers.append("cookie", HeaderValue::from_static("cookie2=cookie2"));
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            headers
        })
        .orig_headers({
            let mut orig_headers = OrigHeaderMap::new();
            orig_headers.insert("user-agent");
            orig_headers.insert("accept");
            orig_headers.insert("content-type");
            orig_headers.insert("authorization");
            orig_headers.insert("referer");
            orig_headers.insert("cookie");
            orig_headers.insert("cache-control");
            orig_headers
        })
        .body(r#"{"message":"hello"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn test_overwrite_headers() {
    let server = server::http(move |req| async move {
        let path = req.uri().path();
        match path {
            "/1" => {
                assert_eq!(req.method(), "GET");
                assert_eq!(req.headers()[USER_AGENT], "my-custom-agent");
                let mut cookies = req.headers().get_all(COOKIE).iter();
                assert_eq!(cookies.next().unwrap(), "a=b");
                assert_eq!(cookies.next().unwrap(), "c=d");
                assert_eq!(cookies.next(), None);
            }
            "/2" => {
                assert_eq!(req.method(), "GET");
                assert_eq!(req.headers()[USER_AGENT], "my-custom-agent");
                let mut cookies = req.headers().get_all(COOKIE).iter();
                assert_eq!(cookies.next().unwrap(), "e=f");
                assert_eq!(cookies.next().unwrap(), "g=h");
                assert_eq!(cookies.next(), None);
            }
            "/3" => {
                assert_eq!(req.method(), "GET");
                assert_eq!(req.headers()[USER_AGENT], "default-agent");
                let mut cookies = req.headers().get_all(COOKIE).iter();
                assert_eq!(cookies.next().unwrap(), "a=b");
                assert_eq!(cookies.next().unwrap(), "c=d");
                assert_eq!(cookies.next(), None);
            }
            "/4" => {
                assert_eq!(req.method(), "GET");
                assert_eq!(req.headers()[USER_AGENT], "default-agent");
                let mut cookies = req.headers().get_all(COOKIE).iter();
                assert_eq!(cookies.next().unwrap(), "e=f");
                assert_eq!(cookies.next().unwrap(), "g=h");
                assert_eq!(cookies.next(), None);
            }
            _ => {
                unreachable!("Unexpected request path: {}", path);
            }
        }

        http::Response::default()
    });

    let mut default_headers = header::HeaderMap::new();
    default_headers.insert(
        USER_AGENT,
        header::HeaderValue::from_static("default-agent"),
    );
    default_headers.insert(COOKIE, header::HeaderValue::from_static("a=b"));
    default_headers.append(COOKIE, header::HeaderValue::from_static("c=d"));

    let client = Client::builder()
        .no_proxy()
        .default_headers(default_headers)
        .build()
        .unwrap();

    let url = format!("http://{}/1", server.addr());
    let res = client
        .get(&url)
        .header(USER_AGENT, "my-custom-agent")
        .send()
        .await
        .unwrap();
    assert_eq!(res.uri(), url.as_str());
    assert_eq!(res.status(), wreq::StatusCode::OK);

    let url = format!("http://{}/2", server.addr());
    let res = client
        .get(&url)
        .header(USER_AGENT, "my-custom-agent")
        .header(COOKIE, "e=f")
        .header(COOKIE, "g=h")
        .send()
        .await
        .unwrap();
    assert_eq!(res.uri(), url.as_str());
    assert_eq!(res.status(), wreq::StatusCode::OK);

    let url = format!("http://{}/3", server.addr());
    let res = client.get(&url).send().await.unwrap();
    assert_eq!(res.uri(), url.as_str());
    assert_eq!(res.status(), wreq::StatusCode::OK);

    let url = format!("http://{}/4", server.addr());
    let res = client
        .get(&url)
        .header(COOKIE, "e=f")
        .header(COOKIE, "g=h")
        .send()
        .await
        .unwrap();
    assert_eq!(res.uri(), url.as_str());
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn donot_set_content_length_0_if_have_no_body() {
    let server = server::http(move |req| async move {
        let headers = req.headers();
        assert_eq!(headers.get(CONTENT_LENGTH), None);
        assert!(headers.get(CONTENT_TYPE).is_none());
        assert!(headers.get(TRANSFER_ENCODING).is_none());
        http::Response::default()
    });

    let url = format!("http://{}/content-length", server.addr());
    let res = Client::builder()
        .no_proxy()
        .build()
        .expect("client builder")
        .get(&url)
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn user_agent() {
    let server = server::http(move |req| async move {
        assert_eq!(req.headers()["user-agent"], "wreq-test-agent");
        http::Response::default()
    });

    let url = format!("http://{}/ua", server.addr());
    let res = Client::builder()
        .user_agent("wreq-test-agent")
        .build()
        .expect("client builder")
        .get(&url)
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn response_text() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let client = Client::new();

    let res = client
        .get(format!("http://{}/text", server.addr()))
        .send()
        .await
        .expect("Failed to get");
    assert_eq!(res.content_length(), Some(5));
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}

#[tokio::test]
async fn response_bytes() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let client = Client::new();

    let res = client
        .get(format!("http://{}/bytes", server.addr()))
        .send()
        .await
        .expect("Failed to get");
    assert_eq!(res.content_length(), Some(5));
    let bytes = res.bytes().await.expect("res.bytes()");
    assert_eq!("Hello", bytes);
}

#[tokio::test]
#[cfg(feature = "json")]
async fn response_json() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::new("\"Hello\"".into()) });

    let client = Client::new();

    let res = client
        .get(format!("http://{}/json", server.addr()))
        .send()
        .await
        .expect("Failed to get");
    let text = res.json::<String>().await.expect("Failed to get json");
    assert_eq!("Hello", text);
}

#[tokio::test]
async fn body_pipe_response() {
    let _ = env_logger::try_init();

    let server = server::http(move |req| async move {
        if req.uri() == "/get" {
            http::Response::new("pipe me".into())
        } else {
            assert_eq!(req.uri(), "/pipe");
            assert_eq!(req.headers()["content-length"], "7");

            let full: Vec<u8> = req
                .into_body()
                .collect()
                .await
                .expect("must succeed")
                .to_bytes()
                .to_vec();

            assert_eq!(full, b"pipe me");

            http::Response::default()
        }
    });

    let client = Client::new();

    let res1 = client
        .get(format!("http://{}/get", server.addr()))
        .send()
        .await
        .expect("get1");

    assert_eq!(res1.status(), wreq::StatusCode::OK);
    assert_eq!(res1.content_length(), Some(7));

    // and now ensure we can "pipe" the response to another request
    let res2 = client
        .post(format!("http://{}/pipe", server.addr()))
        .body(res1)
        .send()
        .await
        .expect("res2");

    assert_eq!(res2.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn overridden_dns_resolution_with_gai() {
    let _ = env_logger::builder().is_test(true).try_init();
    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let overridden_domain = "rust-lang.org";
    let url = format!(
        "http://{overridden_domain}:{}/domain_override",
        server.addr().port()
    );
    let client = Client::builder()
        .no_proxy()
        .resolve(overridden_domain, server.addr())
        .build()
        .expect("client builder");
    let req = client.get(&url);
    let res = req.send().await.expect("request");

    assert_eq!(res.status(), wreq::StatusCode::OK);
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}

#[tokio::test]
async fn overridden_dns_resolution_with_gai_multiple() {
    let _ = env_logger::builder().is_test(true).try_init();
    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let overridden_domain = "rust-lang.org";
    let url = format!(
        "http://{overridden_domain}:{}/domain_override",
        server.addr().port()
    );
    // the server runs on IPv4 localhost, so provide both IPv4 and IPv6 and let the happy eyeballs
    // algorithm decide which address to use.
    let client = Client::builder()
        .no_proxy()
        .resolve_to_addrs(
            overridden_domain,
            [
                std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    server.addr().port(),
                ),
                server.addr(),
            ],
        )
        .build()
        .expect("client builder");
    let req = client.get(&url);
    let res = req.send().await.expect("request");

    assert_eq!(res.status(), wreq::StatusCode::OK);
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}

#[cfg(feature = "hickory-dns")]
#[tokio::test]
async fn overridden_dns_resolution_with_hickory_dns() {
    let _ = env_logger::builder().is_test(true).try_init();
    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let overridden_domain = "rust-lang.org";
    let url = format!(
        "http://{overridden_domain}:{}/domain_override",
        server.addr().port()
    );
    let client = Client::builder()
        .no_proxy()
        .resolve(overridden_domain, server.addr())
        .build()
        .expect("client builder");
    let req = client.get(&url);
    let res = req.send().await.expect("request");

    assert_eq!(res.status(), wreq::StatusCode::OK);
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}

#[cfg(feature = "hickory-dns")]
#[tokio::test]
async fn overridden_dns_resolution_with_hickory_dns_multiple() {
    let _ = env_logger::builder().is_test(true).try_init();
    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let overridden_domain = "rust-lang.org";
    let url = format!(
        "http://{overridden_domain}:{}/domain_override",
        server.addr().port()
    );
    // the server runs on IPv4 localhost, so provide both IPv4 and IPv6 and let the happy eyeballs
    // algorithm decide which address to use.
    let client = Client::builder()
        .no_proxy()
        .resolve_to_addrs(
            overridden_domain,
            [
                std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    server.addr().port(),
                ),
                server.addr(),
            ],
        )
        .build()
        .expect("client builder");
    let req = client.get(&url);
    let res = req.send().await.expect("request");

    assert_eq!(res.status(), wreq::StatusCode::OK);
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}

#[test]
#[cfg(feature = "json")]
fn add_json_default_content_type_if_not_set_manually() {
    let mut map = HashMap::new();
    map.insert("body", "json");
    let content_type = http::HeaderValue::from_static("application/vnd.api+json");
    let req = Client::new()
        .post("https://google.com/")
        .header(CONTENT_TYPE, &content_type)
        .json(&map)
        .build()
        .expect("request is not valid");

    assert_eq!(content_type, req.headers().get(CONTENT_TYPE).unwrap());
}

#[test]
#[cfg(feature = "json")]
fn update_json_content_type_if_set_manually() {
    let mut map = HashMap::new();
    map.insert("body", "json");
    let req = Client::new()
        .post("https://google.com/")
        .json(&map)
        .build()
        .expect("request is not valid");

    assert_eq!("application/json", req.headers().get(CONTENT_TYPE).unwrap());
}

#[tokio::test]
async fn test_tls_info() {
    let resp = Client::builder()
        .tls_info(true)
        .build()
        .expect("client builder")
        .get("https://google.com")
        .send()
        .await
        .expect("response");
    let tls_info = resp.extensions().get::<TlsInfo>().unwrap();
    let peer_certificate = tls_info.peer_certificate();
    assert!(peer_certificate.is_some());
    let der = peer_certificate.unwrap();
    assert_eq!(der[0], 0x30); // ASN.1 SEQUENCE

    let resp = Client::builder()
        .build()
        .expect("client builder")
        .get("https://google.com")
        .send()
        .await
        .expect("response");
    let tls_info = resp.extensions().get::<TlsInfo>();
    assert!(tls_info.is_none());
}

#[tokio::test]
async fn close_connection_after_idle_timeout() {
    let mut server = server::http(move |_| async move { http::Response::default() });

    let client = Client::builder()
        .pool_idle_timeout(std::time::Duration::from_secs(1))
        .build()
        .unwrap();

    let url = format!("http://{}", server.addr());

    client.get(&url).send().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    assert!(
        server
            .events()
            .iter()
            .any(|e| matches!(e, server::Event::ConnectionClosed))
    );
}

#[tokio::test]
async fn http1_reason_phrase() {
    let server = server::low_level_with_response(|_raw_request, client_socket| {
        Box::new(async move {
            client_socket
                .write_all(b"HTTP/1.1 418 I'm not a teapot\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("response write_all failed");
        })
    });

    let client = Client::new();

    let res = client
        .get(format!("http://{}", server.addr()))
        .send()
        .await
        .expect("Failed to get");

    assert_eq!(
        res.error_for_status().unwrap_err().to_string(),
        format!(
            "HTTP status client error (418 I'm not a teapot) for uri (http://{}/)",
            server.addr()
        )
    );
}

#[tokio::test]
async fn error_has_url() {
    let u = "http://does.not.exist.local/ever";
    let err = wreq::get(u).send().await.unwrap_err();
    assert_eq!(
        err.uri().map(ToString::to_string).as_deref(),
        Some(u),
        "{err:?}"
    );
}

#[tokio::test]
async fn http1_only() {
    let mut server = server::http(move |request| async move {
        http::Response::builder()
            .header("x-wire-version", format!("{:?}", request.version()))
            .body(Default::default())
            .unwrap()
    });
    let client = Client::builder()
        .http1_only()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://{}", server.addr());

    // The protocol sender caps later requests after the peer answers with HTTP/1.0.
    for (version, wire_version) in [
        (Version::HTTP_11, Version::HTTP_11),
        (Version::HTTP_10, Version::HTTP_10),
        (Version::HTTP_11, Version::HTTP_10),
    ] {
        let response = client
            .get(&url)
            .version(version)
            .header(header::CONNECTION, "keep-alive")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.headers()["x-wire-version"],
            format!("{wire_version:?}")
        );
        response.bytes().await.unwrap();
    }
    let accepted = server
        .events()
        .iter()
        .filter(|event| matches!(event, server::Event::ConnectionAccepted))
        .count();
    assert_eq!(
        accepted, 1,
        "HTTP/1 minor versions share a reusable connection"
    );

    let resp = wreq::get(url)
        .version(Version::HTTP_11)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.version(), wreq::Version::HTTP_11);
}

#[tokio::test]
async fn request_version_configuration_survives_clone_and_conversion() {
    for version in [
        None,
        Some(Version::HTTP_10),
        Some(Version::HTTP_11),
        Some(Version::HTTP_2),
    ] {
        let mut request =
            wreq::Request::new(http::Method::POST, "http://localhost/".parse().unwrap());
        *request.version_mut() = version;
        *request.body_mut() = Some("payload".into());
        let mut cloned = request.try_clone().unwrap();
        assert_eq!(cloned.version(), version);
        *cloned.version_mut() = Some(Version::HTTP_2);
        assert_eq!(request.version(), version);
        *cloned.version_mut() = version;
        let converted = http::Request::<wreq::Body>::from(cloned);
        assert_eq!(converted.version(), version.unwrap_or(Version::HTTP_11));
        let converted = wreq::Request::from(converted);
        assert_eq!(converted.version(), version);
    }

    let server = server::http(|_| async { http::Response::default() });
    let client = Client::builder().http2_only().no_proxy().build().unwrap();
    let request = wreq::Request::new(
        http::Method::GET,
        format!("http://{}", server.addr()).parse().unwrap(),
    );
    let request = wreq::Request::from(http::Request::<wreq::Body>::from(request));
    assert_eq!(request.version(), None);
    let response = client.execute(request).await.unwrap();
    assert_eq!(response.version(), Version::HTTP_2);

    let request = http::Request::builder()
        .uri(format!("http://{}", server.addr()))
        .version(Version::HTTP_11)
        .body(wreq::Body::default())
        .unwrap();
    let request = wreq::Request::from(request);
    assert_eq!(request.version(), None);
    let resp = client.execute(request).await.unwrap();
    assert_eq!(resp.version(), wreq::Version::HTTP_2);

    let mut request = client
        .get(format!("http://{}", server.addr()))
        .version(Version::HTTP_2)
        .build()
        .unwrap();
    *request.version_mut() = None;
    let resp = Client::builder()
        .http1_only()
        .no_proxy()
        .build()
        .unwrap()
        .execute(request)
        .await
        .unwrap();
    assert_eq!(resp.version(), wreq::Version::HTTP_11);

    let layered_client = Client::builder()
        .http2_only()
        .layer(tower::util::MapRequestLayer::new(
            |mut request: http::Request<wreq::Body>| {
                *request.version_mut() = Version::HTTP_11;
                request
            },
        ))
        .build()
        .unwrap();
    let resp = layered_client
        .get(format!("http://{}", server.addr()))
        .version(Version::HTTP_2)
        .send()
        .await
        .unwrap();
    // Wire mutations do not replace the explicit request-level protocol configuration.
    assert_eq!(resp.version(), wreq::Version::HTTP_2);

    let err = client
        .get(format!("http://{}", server.addr()))
        .version(Version::HTTP_3)
        .send()
        .await
        .unwrap_err();
    assert!(err.is_request());
    assert!(!err.is_connect());
}

#[tokio::test]
async fn http2_only() {
    let server = server::http(move |_| async move { http::Response::default() });

    let resp = Client::builder()
        .http2_only()
        .build()
        .unwrap()
        .get(format!("http://{}", server.addr()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.version(), wreq::Version::HTTP_2);

    let resp = Client::builder()
        .http1_only()
        .build()
        .unwrap()
        .get(format!("http://{}", server.addr()))
        .version(Version::HTTP_2)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.version(), wreq::Version::HTTP_2);
}

#[tokio::test]
async fn connection_pool_respects_https_version_policy() {
    use std::{borrow::Cow, sync::Mutex};

    use wreq::tls::{AlpnProtocol, TlsOptions};

    /// Echoes the cookie serialization version into the request headers.
    /// Lets the server verify that cookies follow the negotiated wire protocol.
    /// Holds no cookie state and ignores response updates.
    #[cfg(feature = "cookies")]
    struct VersionCookies;

    #[cfg(feature = "cookies")]
    impl wreq::cookie::CookieStore for VersionCookies {
        fn set_cookies(&self, _: &mut dyn Iterator<Item = &http::HeaderValue>, _: &http::Uri) {}

        fn cookies(&self, _: &http::Uri, version: Version) -> wreq::cookie::Cookies {
            wreq::cookie::Cookies::Compressed(http::HeaderValue::from_static(
                if version == Version::HTTP_2 {
                    "h2=1"
                } else {
                    "h1=1"
                },
            ))
        }
    }

    let both = b"\x02h2\x08http/1.1".as_slice();
    let h1 = b"\x08http/1.1".as_slice();
    let h2 = b"\x02h2".as_slice();
    let protocols = Some([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1].as_slice());
    for (alpn, client_version, tls_alpn, configured_offer) in [
        (both, None, protocols, both),
        (h1, None, protocols, both),
        (b"", None, protocols, both),
        (both, Some(Version::HTTP_11), protocols, both),
        (both, Some(Version::HTTP_2), protocols, both),
        (both, None, Some([AlpnProtocol::HTTP1].as_slice()), h1),
        (both, None, Some([AlpnProtocol::HTTP2].as_slice()), h2),
        (
            both,
            None,
            Some([AlpnProtocol::HTTP1, AlpnProtocol::HTTP2].as_slice()),
            b"\x08http/1.1\x02h2",
        ),
        (
            both,
            None,
            Some(
                [
                    AlpnProtocol::HTTP1,
                    AlpnProtocol::HTTP2,
                    AlpnProtocol::HTTP1,
                ]
                .as_slice(),
            ),
            b"\x08http/1.1\x02h2\x08http/1.1",
        ),
        (both, None, None, both),
        (both, None, Some([].as_slice()), both),
        (both, Some(Version::HTTP_11), None, both),
        (both, Some(Version::HTTP_2), None, both),
        (both, Some(Version::HTTP_11), Some([].as_slice()), both),
        (both, Some(Version::HTTP_2), Some([].as_slice()), both),
        (
            both,
            Some(Version::HTTP_11),
            Some([AlpnProtocol::HTTP2].as_slice()),
            h2,
        ),
        (
            both,
            Some(Version::HTTP_2),
            Some([AlpnProtocol::HTTP1].as_slice()),
            h1,
        ),
    ] {
        let offers = Arc::new(Mutex::new(Vec::new()));
        let acceptor = server::tls_acceptor_with_alpn(alpn, {
            let offers = offers.clone();
            move |offered| offers.lock().unwrap().push(offered.to_vec())
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}/upload?part=1", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            // One transport per request policy; extra dialing cannot pass as reuse.
            for id in ["0", "1", "2"] {
                let (socket, _) = listener.accept().await.unwrap();
                let stream = server::tls_accept(&acceptor, socket).await;
                let version = match stream.ssl().selected_alpn_protocol() {
                    Some(b"h2") => Version::HTTP_2,
                    Some(b"http/1.1") | None => Version::HTTP_11,
                    alpn => panic!("unexpected ALPN: {alpn:?}"),
                };
                connections.spawn(async move {
                    // RFC 9113 section 3.2: select HTTPS from ALPN, not wire sniffing.
                    // https://www.rfc-editor.org/rfc/rfc9113.html#section-3.2
                    server::serve_connection(
                        stream,
                        version,
                        move |request: http::Request<hyper::body::Incoming>| {
                            assert_eq!(request.version(), version);
                            assert_eq!(request.method(), http::Method::POST);
                            assert_eq!(request.uri().path_and_query().unwrap(), "/upload?part=1");
                            #[cfg(feature = "cookies")]
                            assert_eq!(
                                request.headers()[http::header::COOKIE],
                                if version == Version::HTTP_2 {
                                    "h2=1"
                                } else {
                                    "h1=1"
                                }
                            );
                            async move {
                                assert_eq!(
                                    request.into_body().collect().await.unwrap().to_bytes(),
                                    "payload"
                                );
                                http::Response::new(Full::new(Bytes::from_static(id.as_bytes())))
                            }
                        },
                    )
                    .await
                    .unwrap();
                });
            }
            while let Some(result) = connections.join_next().await {
                result.unwrap();
            }
        });
        let builder = Client::builder().http_version(match client_version {
            Some(Version::HTTP_11) => wreq::HttpVersion::Http1,
            Some(Version::HTTP_2) => wreq::HttpVersion::Http2,
            _ => wreq::HttpVersion::Auto,
        });
        #[cfg(feature = "cookies")]
        let builder = builder.cookie_provider(VersionCookies);
        let tls = tls_alpn.map(|protocols| {
            let mut tls = TlsOptions::default();
            tls.alpn_protocols = Some(Cow::Borrowed(protocols));
            tls
        });
        let client = builder
            .tls_options(tls)
            .no_proxy()
            .tls_cert_verification(false)
            .pool_idle_timeout(None)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let preference_offer = if client_version == Some(Version::HTTP_2) {
            h2
        } else {
            configured_offer
        };
        let client_offer = match client_version {
            Some(Version::HTTP_11) => h1,
            Some(Version::HTTP_2) => h2,
            _ => configured_offer,
        };
        for (version, id, offer) in [
            (Some(Version::HTTP_2), "0", preference_offer),
            (Some(Version::HTTP_11), "1", h1),
            (Some(Version::HTTP_2), "0", preference_offer),
            (Some(Version::HTTP_11), "1", h1),
            (None, "2", client_offer),
            (None, "2", client_offer),
        ] {
            let mut request = client.post(&url).body("payload");
            if let Some(version) = version {
                request = request.version(version);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let expected = match btls::ssl::select_next_proto(alpn, offer) {
                Some(b"h2") => Version::HTTP_2,
                _ => Version::HTTP_11,
            };
            assert_eq!(
                response.version(),
                expected,
                "server ALPN={alpn:?}, client={client_version:?}, TLS ALPN={tls_alpn:?}, request={version:?}, offer={offer:?}",
            );
            assert_eq!(response.bytes().await.unwrap(), id);
        }
        drop(client);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            *offers.lock().unwrap(),
            [preference_offer, h1, client_offer]
        );
    }
}

#[tokio::test]
async fn connection_pool_http2_errors_respect_negotiation() {
    use std::error::Error as _;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for (request_version, extended_connect, forced) in [
        (None, false, true),
        (Some(Version::HTTP_2), false, true),
        (Some(Version::HTTP_2), true, true),
        (Some(Version::HTTP_2), true, false),
    ] {
        let acceptor = server::tls_acceptor(b"");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = server::tls_accept(&acceptor, socket).await;
            assert!(stream.ssl().selected_alpn_protocol().is_none());
            if forced {
                let mut preface = [0; 24];
                stream.read_exact(&mut preface).await.unwrap();
                assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            } else {
                // H1 ignores the H2 extension and encodes an ordinary CONNECT.
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await.unwrap());
                }
                let head = String::from_utf8(head).unwrap();
                assert_eq!(
                    head.lines().next().unwrap(),
                    format!("CONNECT {} HTTP/1.1", listener.local_addr().unwrap())
                );
                assert!(!head.contains("websocket"));
            }
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            // Drain input so a TCP reset cannot hide the protocol parsing error.
            let mut buffer = [0; 1024];
            while stream.read(&mut buffer).await.unwrap_or_default() != 0 {}
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });

        let builder = if forced {
            Client::builder().http2_only()
        } else {
            Client::builder()
        };
        let client = builder
            .no_proxy()
            .tls_cert_verification(false)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let mut request = client.get(url);
        if let Some(version) = request_version {
            request = request.version(version);
        }
        let mut request = request.build().unwrap();
        if extended_connect {
            *request.method_mut() = http::Method::CONNECT;
            request
                .extensions_mut()
                .insert(http2::ext::Protocol::from_static("websocket"));
        }
        let result = client.execute(request).await;
        if forced {
            let error = result.unwrap_err();
            assert!(!error.is_timeout(), "{error:?}");
            let mut source = error.source();
            let mut has_context = false;
            let mut has_protocol_error = false;
            while let Some(error) = source {
                has_context |= error.to_string().contains("without reported h2 ALPN");
                has_protocol_error |= error
                    .downcast_ref::<http2::Error>()
                    .is_some_and(|error| error.reason() == Some(http2::Reason::FRAME_SIZE_ERROR));
                source = error.source();
            }
            assert!(has_context && has_protocol_error, "{error:?}");
        } else {
            let response = result.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.version(), Version::HTTP_11);
            response.bytes().await.unwrap();
        }
        drop(client);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn connection_pool_reuses_and_discards_poisoned_connections() {
    let mut server = server::http(move |_| async move { http::Response::default() });
    let url = format!("http://{}", server.addr());

    let http1 = Client::builder().http1_only().build().unwrap();
    for _ in 0..2 {
        http1.get(&url).send().await.unwrap().bytes().await.unwrap();
    }

    let http2 = Client::builder().http2_only().build().unwrap();
    let responses = futures_util::future::join_all((0..8).map(|_| http2.get(&url).send())).await;
    for response in responses {
        response.unwrap();
    }

    let accepted = server
        .events()
        .iter()
        .filter(|event| matches!(event, server::Event::ConnectionAccepted))
        .count();
    assert_eq!(accepted, 2);

    for client in [&http1, &http2] {
        let response = client.get(&url).send().await.unwrap();
        response.forbid_recycle();
        response.bytes().await.unwrap();

        for _ in 0..2 {
            client
                .get(&url)
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
        }
    }

    let replacement_connections = server
        .events()
        .iter()
        .filter(|event| matches!(event, server::Event::ConnectionAccepted))
        .count();
    assert_eq!(replacement_connections, 2);
}

#[tokio::test]
async fn connection_pool_reuse_first_waits_for_busy_http1_connection() {
    let requests = Arc::new(AtomicUsize::new(0));
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let mut server = server::http({
        let requests = requests.clone();
        let first_started = first_started.clone();
        let release_first = release_first.clone();
        move |_| {
            let requests = requests.clone();
            let first_started = first_started.clone();
            let release_first = release_first.clone();
            async move {
                if requests.fetch_add(1, Ordering::SeqCst) == 0 {
                    first_started.notify_one();
                    release_first.notified().await;
                }
                http::Response::default()
            }
        }
    });
    let client = Client::builder()
        .http1_only()
        .pool_strategy(PoolStrategy::ReuseFirst(Duration::from_secs(3)))
        .build()
        .unwrap();
    let url = format!("http://{}", server.addr());

    let first = tokio::spawn({
        let client = client.clone();
        let url = url.clone();
        async move { client.get(url).send().await }
    });
    tokio::time::timeout(Duration::from_secs(1), first_started.notified())
        .await
        .expect("an empty pool should connect without the reuse delay");

    let mut second = Box::pin(client.get(url).send());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), second.as_mut())
            .await
            .is_err(),
        "the busy HTTP/1 connection should keep the second request waiting"
    );
    release_first.notify_one();

    tokio::time::timeout(Duration::from_secs(1), first)
        .await
        .expect("released response should complete promptly")
        .unwrap()
        .unwrap()
        .bytes()
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .expect("returned connection should wake the waiting request")
        .unwrap()
        .bytes()
        .await
        .unwrap();

    let accepted = server
        .events()
        .iter()
        .filter(|event| matches!(event, server::Event::ConnectionAccepted))
        .count();
    assert_eq!(accepted, 1);
}

#[tokio::test]
async fn connection_pool_applies_client_http1_options() {
    use std::error::Error as _;

    let responses = Arc::new(AtomicUsize::new(0));
    let server = server::low_level_with_response(move |_, stream| {
        let response = if responses.fetch_add(1, Ordering::Relaxed).is_multiple_of(2) {
            b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".as_slice()
        } else {
            b"HTTP/1.1 200 OK\r\nX-0: 0\r\nX-1: 1\r\nX-2: 2\r\nX-3: 3\r\nX-4: 4\r\nX-5: 5\r\nX-6: 6\r\nX-7: 7\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".as_slice()
        };
        Box::new(async move {
            stream.write_all(response).await.unwrap();
            stream.shutdown().await.unwrap();
        })
    });
    let url = format!("http://{}", server.addr());

    for max_headers in [4, 16] {
        let client = Client::builder()
            .http1_only()
            .no_proxy()
            .http1_options(Http1Options::builder().max_headers(max_headers).build())
            .build()
            .unwrap();

        client
            .get(&url)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        // Connection: close forces the next handshake to reuse the client's options.
        let response = client.get(&url).send().await;
        if max_headers == 4 {
            let error = response.unwrap_err();
            assert!(
                std::iter::successors(error.source(), |&source| source.source()).any(|source| {
                    source
                        .downcast_ref::<wreq_proto::Error>()
                        .is_some_and(wreq_proto::Error::is_parse)
                }),
                "{error:?}"
            );
        } else {
            assert_eq!(response.unwrap().headers()["x-7"], "7");
        }
    }
}

#[tokio::test]
async fn connection_pool_closes_idle_transports() {
    // Adapted from hyper-util tests/legacy_client.rs: drop_client_closes_idle_connections
    // and no_keep_alive_closes_connection.
    for version in [Version::HTTP_11, Version::HTTP_2] {
        for keep_alive in [true, false] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let mut server = tokio::spawn(async move {
                let (io, _) = listener.accept().await.unwrap();
                server::serve_connection(io, version, |_| async {
                    http::Response::new(Full::new(Bytes::from_static(b"body")))
                })
                .await
                .unwrap();
            });
            let client = Client::builder()
                .no_proxy()
                .pool_idle_timeout(None)
                .pool_max_idle_per_host(if keep_alive { 1 } else { 0 })
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap();
            let response = client.get(&url).version(version).send().await.unwrap();
            assert_eq!(response.version(), version);
            assert_eq!(response.bytes().await.unwrap(), "body");

            if keep_alive {
                let clone = client.clone();
                drop(client);
                assert!(futures_util::poll!(&mut server).is_pending());
                // The listener accepts only once, so this must reuse the live socket.
                tokio::time::timeout(Duration::from_secs(2), async {
                    clone
                        .get(&url)
                        .version(version)
                        .send()
                        .await
                        .unwrap()
                        .bytes()
                        .await
                        .unwrap();
                })
                .await
                .unwrap();
                drop(clone);
            }

            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .expect("the transport must close without an idle timer")
                .unwrap();
        }
    }
}

#[tokio::test]
async fn connection_pool_cancellation_closes_http1_transport() {
    // Adapted from hyper-util tests/legacy_client.rs:
    // drop_response_future_closes_in_progress_connection
    // and drop_response_body_closes_in_progress_connection (Hyper #1353).
    for response_started in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (received, request_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut io, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(io.read_u8().await.unwrap());
            }
            if response_started {
                io.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .await
                    .unwrap();
            }
            received.send(()).unwrap();
            let mut byte = [0];
            match io.read(&mut byte).await {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                result => panic!("canceled transport remained open: {result:?}"),
            }
        });
        let client = Client::builder().http1_only().no_proxy().build().unwrap();
        let mut request = Box::pin(client.get(url).send());
        tokio::time::timeout(Duration::from_secs(2), async {
            if response_started {
                drop(request.as_mut().await.unwrap());
            } else {
                tokio::select! {
                    _ = request_received => {}
                    result = request.as_mut() => panic!("unexpected response: {result:?}"),
                }
            }
        })
        .await
        .unwrap();
        drop(request);

        // Keep Client alive: cancellation itself must close the busy transport.
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("cancellation must release the transport")
            .unwrap();
        drop(client);
    }
}

#[tokio::test]
async fn connection_pool_preserves_upload_after_response_headers() {
    // Adapted from hyper-util tests/legacy_client.rs:
    // client_keep_alive_when_response_before_request_body_ends.
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (uploaded, mut upload_received) = tokio::sync::oneshot::channel();
        let uploaded = Arc::new(std::sync::Mutex::new(Some(uploaded)));
        let server = tokio::spawn(async move {
            let (io, _) = listener.accept().await.unwrap();
            server::serve_connection(
                io,
                version,
                move |request: http::Request<hyper::body::Incoming>| {
                    if request.method() == http::Method::POST {
                        let uploaded = uploaded.lock().unwrap().take().unwrap();
                        tokio::spawn(async move {
                            uploaded
                                .send(request.into_body().collect().await.unwrap().to_bytes())
                                .unwrap();
                        });
                    }
                    async { http::Response::new(Full::new(Bytes::new())) }
                },
            )
            .await
            .unwrap();
        });
        let client = Client::builder()
            .no_proxy()
            .pool_idle_timeout(None)
            .pool_strategy(PoolStrategy::ReuseFirst(Duration::from_secs(30)))
            .build()
            .unwrap();
        let (release, upload) = tokio::sync::oneshot::channel();
        let body = wreq::Body::wrap(http_body_util::StreamBody::new(futures_util::stream::once(
            async { upload.await.map(http_body::Frame::data) },
        )));
        tokio::time::timeout(Duration::from_secs(2), async {
            client
                .post(&url)
                .version(version)
                .body(body)
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
        })
        .await
        .expect("response headers must not wait for the upload");
        assert!(futures_util::poll!(&mut upload_received).is_pending());

        let mut second = Box::pin(client.get(&url).version(version).send());
        if version == Version::HTTP_11 {
            assert!(futures_util::poll!(second.as_mut()).is_pending());
        } else {
            tokio::time::timeout(Duration::from_secs(2), second.as_mut())
                .await
                .unwrap()
                .unwrap()
                .bytes()
                .await
                .unwrap();
        }
        release.send(Bytes::from_static(b"upload")).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), upload_received)
                .await
                .unwrap()
                .unwrap(),
            "upload"
        );
        if version == Version::HTTP_11 {
            tokio::time::timeout(Duration::from_secs(2), second.as_mut())
                .await
                .unwrap()
                .unwrap()
                .bytes()
                .await
                .unwrap();
        }
        drop(second);
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn http1_send_case_sensitive_headers() {
    // Create a request with a case-sensitive header
    let mut orig_headers = OrigHeaderMap::new();
    orig_headers.insert("X-custom-header");
    orig_headers.insert("Host");

    let resp = wreq::get("https://tls.browserleaks.com")
        .header("X-Custom-Header", "value")
        .orig_headers(orig_headers)
        .version(Version::HTTP_11)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(resp.contains("X-custom-header"));
    assert!(resp.contains("Host"));
}

#[tokio::test]
async fn tunnel_includes_proxy_auth_with_multiple_proxies() {
    let url = "http://hyper.rs.local/prox";
    let server1 = server::http(move |req| {
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), url);
        assert_eq!(req.headers()["host"], "hyper.rs.local");
        assert_eq!(
            req.headers()["proxy-authorization"],
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
        assert_eq!(req.headers()["proxy-header"], "proxy2");
        async { http::Response::default() }
    });

    let proxy_url = format!("http://Aladdin:open%20sesame@{}", server1.addr());

    let mut headers1 = wreq::header::HeaderMap::new();
    headers1.insert("proxy-header", "proxy1".parse().unwrap());

    let mut headers2 = wreq::header::HeaderMap::new();
    headers2.insert("proxy-header", "proxy2".parse().unwrap());

    let client = Client::builder()
        // When processing proxy headers, the first one is iterated,
        // and if the current URL does not match, the proxy is skipped
        .proxy(
            wreq::Proxy::https(&proxy_url)
                .unwrap()
                .custom_http_headers(headers1.clone()),
        )
        // When processing proxy headers, the second one is iterated,
        // and for the current URL matching, the proxy will be used
        .proxy(
            wreq::Proxy::http(&proxy_url)
                .unwrap()
                .custom_http_headers(headers2.clone()),
        )
        .build()
        .unwrap();

    let res = client.get(url).send().await.unwrap();

    assert_eq!(res.uri(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);

    let client = Client::builder()
        // When processing proxy headers, the first one is iterated,
        // and for the current URL matching, the proxy will be used
        .proxy(
            wreq::Proxy::http(&proxy_url)
                .unwrap()
                .custom_http_headers(headers2),
        )
        // When processing proxy headers, the second one is iterated,
        // and if the current URL does not match, the proxy is skipped
        .proxy(
            wreq::Proxy::https(&proxy_url)
                .unwrap()
                .custom_http_headers(headers1),
        )
        .build()
        .unwrap();

    let res = client.get(url).send().await.unwrap();

    assert_eq!(res.uri(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn skip_default_headers() {
    let server = server::http(move |req| async move {
        let path = req.uri().path();
        match path {
            "/skip" => {
                assert_eq!(req.method(), "GET");
                assert_eq!(req.headers().get(USER_AGENT), None);
                assert_eq!(req.headers().get(ACCEPT), None);
            }
            "/no_skip" => {
                assert_eq!(req.method(), "GET");
                assert_eq!(req.headers()[USER_AGENT], "test-agent");
                assert_eq!(req.headers()[ACCEPT], "*/*");
            }
            _ => unreachable!("Unexpected request path: {path}"),
        }

        http::Response::default()
    });

    let client = Client::builder()
        .default_headers({
            let mut headers = wreq::header::HeaderMap::new();
            headers.insert(USER_AGENT, "test-agent".parse().unwrap());
            headers.insert(ACCEPT, "*/*".parse().unwrap());
            headers
        })
        .no_proxy()
        .build()
        .unwrap();

    let url = format!("http://{}/skip", server.addr());
    let res = client
        .get(&url)
        .default_headers(false)
        .send()
        .await
        .unwrap();
    assert_eq!(res.uri(), url.as_str());
    assert_eq!(res.status(), wreq::StatusCode::OK);

    let url = format!("http://{}/no_skip", server.addr());
    let res = client.get(&url).send().await.unwrap();
    assert_eq!(res.uri(), url.as_str());
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn test_client_same_header_values_append() {
    let server = server::http(move |req| async move {
        let path = req.uri().path();
        match path {
            "/duplicate-cookies" => {
                let cookie_values: Vec<_> = req.headers().get_all(header::COOKIE).iter().collect();
                assert_eq!(cookie_values.len(), 1);
                assert_eq!(cookie_values[0], "duplicate=same_value");
            }
            "/no-duplicate-cookies" => {
                let cookie_values: Vec<_> = req.headers().get_all(header::COOKIE).iter().collect();
                assert_eq!(cookie_values.len(), 3);
                assert_eq!(cookie_values[0], "duplicate=same_value");
                assert_eq!(cookie_values[1], "unique1=value1");
                assert_eq!(cookie_values[2], "unique2=value2");
            }
            _ => unreachable!("Unexpected request path: {}", path),
        }

        http::Response::default()
    });

    let client = Client::builder()
        .no_proxy()
        .default_headers({
            let mut headers = HeaderMap::new();
            headers.insert(
                header::COOKIE,
                HeaderValue::from_static("duplicate=same_value"),
            );
            headers.append(header::COOKIE, HeaderValue::from_static("unique1=value1"));
            headers.append(header::COOKIE, HeaderValue::from_static("unique2=value2"));
            headers
        })
        .build()
        .unwrap();

    let res = client
        .get(format!("http://{}/duplicate-cookies", server.addr()))
        .header(header::COOKIE, "duplicate=same_value")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), wreq::StatusCode::OK);

    let res = client
        .get(format!("http://{}/no-duplicate-cookies", server.addr()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[cfg(all(
    feature = "gzip",
    feature = "brotli",
    feature = "deflate",
    feature = "zstd"
))]
#[tokio::test]
async fn test_client_default_accept_encoding() {
    let server = server::http(move |req| async move {
        let accept_encoding = req.headers().get(header::ACCEPT_ENCODING).unwrap();
        if req.uri() == "/default" {
            assert_eq!(accept_encoding, "zstd");
        }

        if req.uri() == "/custom" {
            assert_eq!(accept_encoding, "gzip");
        }

        http::Response::default()
    });

    let client = Client::builder()
        .default_headers({
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("zstd"));
            headers
        })
        .no_proxy()
        .build()
        .unwrap();

    let _ = client
        .get(format!("http://{}/default", server.addr()))
        .send()
        .await
        .unwrap();

    let _ = client
        .get(format!("http://{}/custom", server.addr()))
        .header(header::ACCEPT_ENCODING, "gzip")
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn response_trailers() {
    let server = server::http(move |req| async move {
        assert_eq!(req.uri().path(), "/trailers");

        let body = Full::new(Bytes::from("HelloWorld!")).with_trailers(async move {
            let mut trailers = http::HeaderMap::new();
            trailers.insert("chunky-trailer1", HeaderValue::from_static("value1"));
            trailers.insert("chunky-trailer2", HeaderValue::from_static("value2"));
            Some(Ok(trailers))
        });
        let mut resp = http::Response::new(wreq::Body::wrap(body));
        resp.headers_mut().insert(
            header::TRAILER,
            header::HeaderValue::from_static("chunky-trailer1, chunky-trailer2"),
        );
        resp.headers_mut().insert(
            header::TRANSFER_ENCODING,
            header::HeaderValue::from_static("chunked"),
        );

        resp
    });

    let mut res = wreq::get(format!("http://{}/trailers", server.addr()))
        .header(header::TE, "trailers")
        .send()
        .await
        .expect("Failed to get response");

    assert_eq!(res.status(), StatusCode::OK);

    let mut body_content = Vec::new();
    let mut trailers = HeaderMap::default();
    while let Some(chunk) = res.frame().await {
        match chunk
            .unwrap()
            .into_data()
            .map_err(|frame| frame.into_trailers())
        {
            Ok(res) => {
                body_content.extend_from_slice(&res);
            }
            Err(Ok(res)) => {
                trailers.extend(res);
            }
            _ => (),
        }
    }

    let body = String::from_utf8(body_content).expect("Invalid UTF-8");
    assert_eq!(body, "HelloWorld!");
    assert_eq!(trailers["chunky-trailer1"], "value1");
    assert_eq!(trailers["chunky-trailer2"], "value2");
}

#[tokio::test]
async fn dns_resolution_failure_is_dns_error() {
    let _ = env_logger::builder().is_test(true).try_init();

    struct FailingResolver;

    impl wreq::dns::Resolve for FailingResolver {
        fn resolve(&self, _name: wreq::dns::Name) -> reqwest::dns::Resolving {
            Box::pin(async { Err("simulated resolver failure".into()) })
        }
    }

    let client = Client::builder()
        .no_proxy()
        .dns_resolver(FailingResolver)
        .build()
        .expect("client builder");

    let err = client.get("http://hyper.rs").send().await.unwrap_err();

    assert!(err.is_dns(), "expected a DNS error, got: {err:?}");
    assert!(err.is_connect(), "expected is_connect() to also be true");
}
