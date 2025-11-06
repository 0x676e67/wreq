mod support;

#[cfg(feature = "json")]
use std::collections::HashMap;

use http::{
    HeaderMap, HeaderValue, Version,
    header::{
        self, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, REFERER,
        TRANSFER_ENCODING,
    },
};
use http_body_util::BodyExt;
use pretty_env_logger::env_logger;
use support::server;
use tokio::io::AsyncWriteExt;
use wreq::{Client, Extension, header::OrigHeaderMap, tls::TlsInfo};

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
    use http_body_util::BodyExt;
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
    let Extension(tls_info) = resp.extension::<TlsInfo>().unwrap();
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
    let tls_info = resp.extension::<TlsInfo>();
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
    let server = server::http(move |_| async move { http::Response::default() });

    let resp = Client::builder()
        .http1_only()
        .build()
        .unwrap()
        .get(format!("http://{}", server.addr()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.version(), wreq::Version::HTTP_11);

    let resp = Client::builder()
        .build()
        .unwrap()
        .get(format!("http://{}", server.addr()))
        .version(Version::HTTP_11)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.version(), wreq::Version::HTTP_11);
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
async fn connection_pool_cache() {
    let client = Client::default();
    let url = "https://hyper.rs";

    let resp = client
        .get(url)
        .version(http::Version::HTTP_2)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), wreq::StatusCode::OK);
    assert_eq!(resp.version(), http::Version::HTTP_2);

    let resp = client
        .get(url)
        .version(http::Version::HTTP_11)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), wreq::StatusCode::OK);
    assert_eq!(resp.version(), http::Version::HTTP_11);

    let resp = client
        .get(url)
        .version(http::Version::HTTP_2)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), wreq::StatusCode::OK);
    assert_eq!(resp.version(), http::Version::HTTP_2);
}

#[tokio::test]
#[ignore = "The server is shuddown, this test is not needed anymore"]
async fn http1_send_case_sensitive_headers() {
    // Create a request with a case-sensitive header
    let mut orig_headers = OrigHeaderMap::new();
    orig_headers.insert("X-custom-header");
    orig_headers.insert("Host");

    let resp = wreq::get("https://tls.peet.ws/api/all")
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
        if req.uri() != "/skip" && req.uri() != "/no_skip" {
            panic!("Unexpected request URI: {}", req.uri());
        }

        if req.uri() == "/skip" {
            assert_eq!(req.method(), "GET");
            assert_eq!(req.headers().get("user-agent"), None);
            assert_eq!(req.headers().get("accept"), None);
        }

        if req.uri() == "/no_skip" {
            assert_eq!(req.method(), "GET");
            assert_eq!(
                req.headers().get("user-agent"),
                Some(&"test-agent".parse().unwrap())
            );
            assert_eq!(req.headers().get("accept"), Some(&"*/*".parse().unwrap()));
        }

        http::Response::default()
    });

    let url = format!("http://{}/skip", server.addr());
    let client = Client::builder()
        .default_headers({
            let mut headers = wreq::header::HeaderMap::new();
            headers.insert("user-agent", "test-agent".parse().unwrap());
            headers.insert("accept", "*/*".parse().unwrap());
            headers
        })
        .no_proxy()
        .build()
        .unwrap();

    let res = client
        .get(&url)
        .default_headers(false)
        .send()
        .await
        .unwrap();
    assert_eq!(res.uri(), url.as_str());
    assert_eq!(res.status(), wreq::StatusCode::OK);

    let url = format!("http://{}/no_skip", server.addr());
    let client = Client::builder()
        .default_headers({
            let mut headers = wreq::header::HeaderMap::new();
            headers.insert("user-agent", "test-agent".parse().unwrap());
            headers.insert("accept", "*/*".parse().unwrap());
            headers
        })
        .no_proxy()
        .build()
        .unwrap();

    let res = client.get(&url).send().await.unwrap();
    assert_eq!(res.uri(), url.as_str());
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn test_client_same_header_values_append() {
    let server = server::http(move |req| async move {
        let cookie_values: Vec<_> = req.headers().get_all(header::COOKIE).iter().collect();
        assert_eq!(cookie_values.len(), 4);

        assert_eq!(cookie_values[0], "duplicate=same_value");
        assert_eq!(cookie_values[1], "duplicate=same_value");
        assert_eq!(cookie_values[2], "unique1=value1");
        assert_eq!(cookie_values[3], "unique2=value2");

        http::Response::default()
    });

    let url = format!("http://{}/duplicate-cookies", server.addr());

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
        .get(&url)
        .header(header::COOKIE, "duplicate=same_value")
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
