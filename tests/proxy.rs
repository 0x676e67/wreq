#![cfg(feature = "tokio-rt")]

mod support;
use std::{env, error::Error as StdError, sync::LazyLock};

use support::server;
use tokio::sync::Mutex;
use wreq::{
    Client,
    tls::{Tls13Cipher, TlsOptions},
};

// serialize tests that read from / write to environment variables
static HTTP_PROXY_ENV_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

struct NoResolver;

impl wreq::dns::Resolve for NoResolver {
    fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
        panic!("unexpected DNS lookup: {name}");
    }
}

fn invalid_tls_options() -> TlsOptions {
    TlsOptions::builder()
        .tls13_cipher_list(&[Tls13Cipher::AES_256_GCM_SHA384; 2])
        .build()
}

#[tokio::test]
async fn request_tls_config_error_follows_stream_route() {
    let client = Client::builder_tokio()
        .no_proxy()
        .http1_only()
        .dns_resolver(NoResolver)
        .build()
        .unwrap();
    for (proxy, target, forward) in [
        (None, "https://origin.invalid/", false),
        (
            Some("http://proxy.invalid:8080"),
            "http://origin.invalid/",
            true,
        ),
        (
            Some("https://proxy.invalid:8443"),
            "http://origin.invalid/",
            true,
        ),
        (
            Some("https://proxy.invalid:8443"),
            "https://origin.invalid/",
            false,
        ),
    ] {
        let mut request = client.get(target).emulation(invalid_tls_options());
        if let Some(proxy) = proxy {
            request = request.proxy(wreq::Proxy::all(proxy).unwrap());
        }
        let error = request.send().await.unwrap_err();
        assert!(
            std::iter::successors(error.source(), |&source| source.source())
                .any(|source| source.is::<btls::error::ErrorStack>()),
            "{proxy:?} -> {target}: {error:?}"
        );
        assert_eq!(
            error.is_proxy_connect(),
            forward,
            "{proxy:?} -> {target}: {error:?}"
        );
        assert_eq!(
            error.is_connect(),
            !forward,
            "{proxy:?} -> {target}: {error:?}"
        );
    }
}

#[cfg(feature = "http3")]
#[tokio::test]
async fn quic_proxy_rejects_stream_requests_before_dns() {
    for proxy in ["quic://proxy.invalid:443", "QUIC://proxy.invalid:443"] {
        let client = Client::builder_tokio()
            .no_proxy()
            .http1_only()
            .dns_resolver(NoResolver)
            .proxy(wreq::Proxy::all(proxy).unwrap())
            .build()
            .unwrap();
        for target in ["http://origin.invalid/", "https://origin.invalid/"] {
            for tls in [None, Some(invalid_tls_options())] {
                let mut request = client.get(target);
                if let Some(tls) = tls {
                    request = request.emulation(tls);
                }
                let error = request.send().await.unwrap_err();
                assert!(error.is_request() && !error.is_proxy_connect(), "{error:?}");
                assert!(!error.is_connect(), "{error:?}");
                assert!(
                    support::error::inspect(error)
                        .iter()
                        .any(|source| source.contains("QUIC proxies require HTTP/3"))
                );
            }
        }
    }
}

#[tokio::test]
async fn https_proxy_keeps_transport_and_target_alpn_separate() {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wreq::{
        Version,
        tls::{AlpnProtocol, TlsOptions},
    };

    for tunnel in [false, true] {
        let offers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let acceptor = server::tls_acceptor_with_alpn(b"\x02h2\x08http/1.1", {
            let offers = offers.clone();
            move |offer| offers.lock().unwrap().push(offer.to_vec())
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let proxy = format!("https://{proxy_addr}");
        let url = if tunnel {
            "https://target.invalid/resource"
        } else {
            "http://target.invalid/resource"
        };
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = server::tls_accept(&acceptor, socket).await;
            assert!(stream.ssl().selected_alpn_protocol().is_none());
            let requests = AtomicUsize::new(0);
            let handler = move |request: http::Request<hyper::body::Incoming>| {
                let index = requests.fetch_add(1, Ordering::Relaxed);
                async move {
                    assert!(index < 2);
                    assert_eq!(request.version(), Version::HTTP_11);
                    if tunnel {
                        assert_eq!(request.uri(), "/resource");
                        assert!(
                            !request
                                .headers()
                                .contains_key(http::header::PROXY_AUTHORIZATION)
                        );
                        assert!(!request.headers().contains_key("x-proxy-header"));
                    } else {
                        assert_eq!(request.uri(), url);
                        assert_eq!(
                            request.headers()[http::header::PROXY_AUTHORIZATION],
                            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
                        );
                        assert_eq!(request.headers()["x-proxy-header"], "proxy-only");
                    }
                    let response = http::Response::builder();
                    let response = if index == 1 {
                        response.header(http::header::CONNECTION, "close")
                    } else {
                        response
                    };
                    response.body(wreq::Body::from("body")).unwrap()
                }
            };
            if tunnel {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await.unwrap());
                }
                let head = String::from_utf8(head).unwrap();
                assert!(head.starts_with("CONNECT target.invalid:443 HTTP/1.1\r\n"));
                for (name, value) in [
                    ("proxy-authorization", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
                    ("x-proxy-header", "proxy-only"),
                ] {
                    assert!(head.lines().any(|line| {
                        line.split_once(':').is_some_and(|(header, actual)| {
                            header.eq_ignore_ascii_case(name) && actual.trim() == value
                        })
                    }));
                }
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                let stream = server::tls_accept(&acceptor, stream).await;
                assert_eq!(
                    stream.ssl().selected_alpn_protocol(),
                    Some(b"http/1.1".as_slice())
                );
                server::serve_connection(stream, Version::HTTP_11, handler)
                    .await
                    .unwrap();
            } else {
                server::serve_connection(stream, Version::HTTP_11, handler)
                    .await
                    .unwrap();
            }
        });
        let client = Client::builder_tokio()
            .proxy(
                wreq::Proxy::all(proxy)
                    .unwrap()
                    .basic_auth("Aladdin", "open sesame")
                    .custom_http_headers({
                        let mut headers = http::HeaderMap::new();
                        headers.insert("x-proxy-header", "proxy-only".parse().unwrap());
                        headers
                    }),
            )
            .tls_cert_verification(false)
            .tls_options(
                TlsOptions::builder()
                    .alpn_protocols([AlpnProtocol::HTTP1])
                    .build(),
            )
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        for _ in 0..2 {
            let response = client
                .get(url)
                .version(if tunnel && cfg!(feature = "http2") {
                    Version::HTTP_2
                } else {
                    Version::HTTP_11
                })
                .send()
                .await
                .unwrap();
            assert_eq!(response.version(), Version::HTTP_11);
            // Both routes report the socket to the proxy, beneath its TLS.
            assert_eq!(response.remote_addr(), Some(proxy_addr));
            assert_eq!(response.bytes().await.unwrap(), "body");
        }
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        drop(client);
        let expected: Vec<_> = if tunnel {
            vec![b"\x08http/1.1".as_slice()]
        } else {
            Vec::new()
        };
        assert_eq!(*offers.lock().unwrap(), expected);
    }
}

#[tokio::test]
async fn http_proxy() {
    let url = "http://hyper.rs.local/prox";
    let server = server::http(move |req| {
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), url);
        assert_eq!(req.headers()["host"], "hyper.rs.local");

        async { http::Response::default() }
    });

    let proxy = format!("http://{}", server.addr());

    let res = Client::builder_tokio()
        .proxy(wreq::Proxy::http(&proxy).unwrap())
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap();

    assert_eq!(res.uri(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn http_proxy_basic_auth() {
    let url = "http://hyper.rs.local/prox";
    let server = server::http(move |req| {
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), url);
        assert_eq!(req.headers()["host"], "hyper.rs.local");
        assert_eq!(
            req.headers()["proxy-authorization"],
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );

        async { http::Response::default() }
    });

    let proxy = format!("http://{}", server.addr());

    let res = Client::builder_tokio()
        .proxy(
            wreq::Proxy::http(&proxy)
                .unwrap()
                .basic_auth("Aladdin", "open sesame"),
        )
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap();

    assert_eq!(res.uri(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn http_proxy_basic_auth_parsed() {
    let url = "http://hyper.rs.local/prox";
    let server = server::http(move |req| {
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), url);
        assert_eq!(req.headers()["host"], "hyper.rs.local");
        assert_eq!(
            req.headers()["proxy-authorization"],
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );

        async { http::Response::default() }
    });

    let proxy = format!("http://Aladdin:open%20sesame@{}", server.addr());

    let res = Client::builder_tokio()
        .proxy(wreq::Proxy::http(&proxy).unwrap())
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap();

    assert_eq!(res.uri(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);

    let res = wreq::Client::new(wreq::rt::tokio::TokioRuntime)
        .get(url)
        .proxy(wreq::Proxy::http(&proxy).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(res.uri(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn system_http_proxy_basic_auth_parsed() {
    let url = "http://hyper.rs.local/prox";
    let server = server::http(move |req| {
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), url);
        assert_eq!(req.headers()["host"], "hyper.rs.local");
        assert_eq!(
            req.headers()["proxy-authorization"],
            "Basic QWxhZGRpbjpvcGVuc2VzYW1l"
        );

        async { http::Response::default() }
    });

    // avoid races with other tests that change "http_proxy"
    let _env_lock = HTTP_PROXY_ENV_MUTEX.lock().await;

    // save system setting first.
    let system_proxy = env::var("http_proxy");

    // set-up http proxy.
    unsafe {
        env::set_var(
            "http_proxy",
            format!("http://Aladdin:opensesame@{}", server.addr()),
        )
    }

    let res = Client::builder_tokio()
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap();

    assert_eq!(res.uri(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);

    // reset user setting.
    unsafe {
        match system_proxy {
            Err(_) => env::remove_var("http_proxy"),
            Ok(proxy) => env::set_var("http_proxy", proxy),
        }
    }
}

#[tokio::test]
async fn test_no_proxy() {
    let server = server::http(move |req| {
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/4");

        async { http::Response::default() }
    });
    let proxy = format!("http://{}", server.addr());
    let url = format!("http://{}/4", server.addr());

    // set up proxy and use no_proxy to clear up client builder proxies.
    let res = Client::builder_tokio()
        .proxy(wreq::Proxy::http(&proxy).unwrap())
        .no_proxy()
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .unwrap();

    assert_eq!(res.uri(), url.as_str());
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn test_using_system_proxy() {
    let url = "http://not.a.real.sub.hyper.rs.local/prox";
    let server = server::http(move |req| {
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), url);
        assert_eq!(req.headers()["host"], "not.a.real.sub.hyper.rs.local");

        async { http::Response::default() }
    });

    // avoid races with other tests that change "http_proxy"
    let _env_lock = HTTP_PROXY_ENV_MUTEX.lock().await;

    // save system setting first.
    let system_proxy = env::var("http_proxy");
    // set-up http proxy.
    unsafe {
        env::set_var("http_proxy", format!("http://{}", server.addr()));
    }
    // system proxy is used by default
    let res = wreq::Client::new(wreq::rt::tokio::TokioRuntime)
        .get(url)
        .send()
        .await
        .unwrap();

    assert_eq!(res.uri(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);

    // reset user setting.
    unsafe {
        match system_proxy {
            Err(_) => env::remove_var("http_proxy"),
            Ok(proxy) => env::set_var("http_proxy", proxy),
        }
    }
}

#[tokio::test]
async fn http_over_http() {
    let url = "http://hyper.rs.local/prox";

    let server = server::http(move |req| {
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), url);
        assert_eq!(req.headers()["host"], "hyper.rs.local");

        async { http::Response::default() }
    });

    let proxy = format!("http://{}", server.addr());

    let res = Client::builder_tokio()
        .proxy(wreq::Proxy::http(&proxy).unwrap())
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap();

    assert_eq!(res.uri(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn http_proxy_custom_headers() {
    let url = "http://hyper.rs.local/prox";
    let server = server::http(move |req| {
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), url);
        assert_eq!(req.headers()["host"], "hyper.rs.local");
        assert_eq!(
            req.headers()["proxy-authorization"],
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
        assert_eq!(req.headers()["x-custom-header"], "value");

        async { http::Response::default() }
    });

    let proxy = format!("http://Aladdin:open%20sesame@{}", server.addr());

    let proxy = wreq::Proxy::http(&proxy).unwrap().custom_http_headers({
        let mut headers = http::HeaderMap::new();
        headers.insert("x-custom-header", "value".parse().unwrap());
        headers
    });

    let res = Client::builder_tokio()
        .proxy(proxy.clone())
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap();

    assert_eq!(res.uri(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);

    let res = wreq::Client::new(wreq::rt::tokio::TokioRuntime)
        .get(url)
        .proxy(proxy)
        .send()
        .await
        .unwrap();

    assert_eq!(res.uri(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn tunnel_detects_auth_required() {
    let url = "https://hyper.rs.local/prox";

    let server = server::http(move |req| {
        assert_eq!(req.method(), "CONNECT");
        assert_eq!(req.uri(), "hyper.rs.local:443");
        assert!(
            !req.headers()
                .contains_key(http::header::PROXY_AUTHORIZATION)
        );

        async {
            let mut res = http::Response::default();
            *res.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
            res
        }
    });

    let proxy = format!("http://{}", server.addr());

    let err = Client::builder_tokio()
        .proxy(wreq::Proxy::https(&proxy).unwrap())
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap_err();

    let err = support::error::inspect(err).pop().unwrap();
    assert!(
        err.contains("auth"),
        "proxy auth err expected, got: {err:?}"
    );
}

#[tokio::test]
async fn tunnel_includes_proxy_auth() {
    let url = "https://hyper.rs.local/prox";

    let server = server::http(move |req| {
        assert_eq!(req.method(), "CONNECT");
        assert_eq!(req.uri(), "hyper.rs.local:443");
        assert_eq!(
            req.headers()["proxy-authorization"],
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );

        async {
            // return 400 to not actually deal with TLS tunneling
            let mut res = http::Response::default();
            *res.status_mut() = http::StatusCode::BAD_REQUEST;
            res
        }
    });

    let proxy = format!("http://Aladdin:open%20sesame@{}", server.addr());

    let err = Client::builder_tokio()
        .proxy(wreq::Proxy::https(&proxy).unwrap())
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap_err();

    let err = support::error::inspect(err).pop().unwrap();
    assert!(
        err.contains("unsuccessful"),
        "tunnel unsuccessful expected, got: {err:?}"
    );
}

#[tokio::test]
async fn tunnel_includes_user_agent() {
    let url = "https://hyper.rs.local/prox";

    let server = server::http(move |req| {
        assert_eq!(req.method(), "CONNECT");
        assert_eq!(req.uri(), "hyper.rs.local:443");
        assert_eq!(req.headers()["user-agent"], "wreq-test");

        async {
            // return 400 to not actually deal with TLS tunneling
            let mut res = http::Response::default();
            *res.status_mut() = http::StatusCode::BAD_REQUEST;
            res
        }
    });

    let proxy = format!("http://{}", server.addr());

    let err = Client::builder_tokio()
        .proxy(wreq::Proxy::https(&proxy).unwrap().custom_http_headers({
            let mut headers = http::HeaderMap::new();
            headers.insert("user-agent", "wreq-test".parse().unwrap());
            headers
        }))
        .user_agent("wreq-test")
        .build()
        .unwrap()
        .get(url)
        .send()
        .await
        .unwrap_err();

    let err = support::error::inspect(err).pop().unwrap();
    assert!(
        err.contains("unsuccessful"),
        "tunnel unsuccessful expected, got: {err:?}"
    );
}

/// A connect deadline that expires while a proxy is resolved or dialed is a proxy failure, like
/// any failure of that dial. Once the proxy accepts the connection, an expiry in its handshake or
/// in the target's TLS handshake is a plain connect failure.
#[tokio::test]
async fn connect_timeout_while_dialing_a_proxy_is_a_proxy_failure() {
    use std::{net::SocketAddr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    /// Never resolves `proxy.test`; resolves the target at once for SOCKS routes that look it up.
    struct Resolver;

    impl wreq::dns::Resolve for Resolver {
        fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
            Box::pin(async move {
                if name.as_str() == "proxy.test" {
                    std::future::pending::<()>().await;
                }
                Ok(
                    Box::new(std::iter::once(SocketAddr::from(([127, 0, 0, 1], 443))))
                        as wreq::dns::Addrs,
                )
            })
        }
    }

    // A full accept queue makes the kernel drop SYNs, so the TCP handshake never completes.
    #[cfg(target_os = "linux")]
    let pending = {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        socket
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
            .unwrap();
        socket.listen(0).unwrap();
        let addr = socket.local_addr().unwrap().as_socket().unwrap();
        let queued = std::net::TcpStream::connect(addr).unwrap();
        (socket, queued, addr)
    };

    // The kernel completes the TCP handshake, but nothing answers.
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();

    // Opens a CONNECT or SOCKS5 tunnel, then never answers the target's TLS handshake.
    let tunnel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = tunnel.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = tunnel.accept().await.unwrap();
            tokio::spawn(async move {
                if stream.read_u8().await.unwrap() == 5 {
                    let mut methods = vec![0; usize::from(stream.read_u8().await.unwrap())];
                    stream.read_exact(&mut methods).await.unwrap();
                    stream.write_all(&[5, 0]).await.unwrap();
                    let mut head = [0; 4];
                    stream.read_exact(&mut head).await.unwrap();
                    let len = match head[3] {
                        1 => 4,
                        4 => 16,
                        _ => usize::from(stream.read_u8().await.unwrap()),
                    };
                    let mut address = vec![0; len + 2];
                    stream.read_exact(&mut address).await.unwrap();
                    stream
                        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                } else {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(stream.read_u8().await.unwrap());
                    }
                    stream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await
                        .unwrap();
                }
                let _ = stream.read_to_end(&mut Vec::new()).await;
            });
        }
    });

    let client = Client::builder_tokio()
        .no_proxy()
        .dns_resolver(Resolver)
        .connect_timeout(Duration::from_millis(200))
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let send = |proxy: String, target: &'static str| {
        client
            .get(target)
            .proxy(wreq::Proxy::all(proxy).unwrap())
            .send()
    };

    // CONNECT, forwarding and SOCKS routes all dial the proxy first.
    let mut dialing = vec![
        ("http://proxy.test:8080".to_owned(), "https://target.test/"),
        ("https://proxy.test:8443".to_owned(), "http://target.test/"),
    ];
    #[cfg(feature = "socks")]
    for scheme in ["socks4", "socks4a", "socks5", "socks5h"] {
        dialing.push((
            format!("{scheme}://proxy.test:1080"),
            "https://target.test/",
        ));
    }
    #[cfg(target_os = "linux")]
    for (scheme, target) in [
        ("http", "https://target.test/"),
        ("http", "http://target.test/"),
        #[cfg(feature = "socks")]
        ("socks5h", "https://target.test/"),
    ] {
        dialing.push((format!("{scheme}://{}", pending.2), target));
    }
    for (proxy, target) in dialing {
        let error = send(proxy.clone(), target).await.unwrap_err();
        assert!(
            error.is_proxy_connect() && error.is_timeout(),
            "{proxy} -> {target}: {error:?}"
        );
    }

    // The proxy accepted the connection: a silent handshake or target is not a failed dial.
    let connected = [
        format!("http://{silent_addr}"),
        format!("http://{tunnel_addr}"),
        #[cfg(feature = "socks")]
        format!("socks5h://{tunnel_addr}"),
    ];
    for proxy in connected {
        let target = "https://target.test/";
        let error = send(proxy.clone(), target).await.unwrap_err();
        assert!(
            error.is_connect() && error.is_timeout() && !error.is_proxy_connect(),
            "{proxy} -> {target}: {error:?}"
        );
    }
}

#[tokio::test]
async fn proxy_tunnel_connect_error() {
    struct Resolver;

    impl wreq::dns::Resolve for Resolver {
        fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
            Box::pin(async move {
                match name.as_str() {
                    "invalid.proxy" => Err("simulated proxy DNS failure".into()),
                    "target.invalid" => {
                        Ok(Box::new(std::iter::once("192.0.2.1:0".parse().unwrap()))
                            as wreq::dns::Addrs)
                    }
                    name => panic!("unexpected DNS lookup: {name}"),
                }
            })
        }
    }

    let client = Client::builder_tokio()
        .tls_cert_verification(false)
        .no_proxy()
        .dns_resolver(Resolver)
        .build()
        .unwrap();

    let invalid_proxies = [
        "http://invalid.proxy:8080",
        "https://invalid.proxy:8080",
        #[cfg(feature = "socks")]
        "socks4://invalid.proxy:8080",
        #[cfg(feature = "socks")]
        "socks4a://invalid.proxy:8080",
        #[cfg(feature = "socks")]
        "socks5://invalid.proxy:8080",
        #[cfg(feature = "socks")]
        "socks5h://invalid.proxy:8080",
    ];

    let target_urls = ["https://target.invalid", "http://target.invalid"];

    for proxy in invalid_proxies {
        for url in target_urls {
            let err = client
                .get(url)
                .proxy(wreq::Proxy::all(proxy).unwrap())
                .send()
                .await
                .unwrap_err();

            assert!(
                err.is_proxy_connect(),
                "proxy connect error expected, got: {err:?}"
            );
            assert!(err.is_dns(), "DNS source must remain visible: {err:?}");
            assert!(
                support::error::inspect(err)
                    .iter()
                    .any(|source| source.contains("simulated proxy DNS failure"))
            );
        }
    }
}

#[tokio::test]
async fn dropped_tunnel_connect_closes_proxy_connection() {
    use std::time::Duration;

    use tokio::{io::AsyncReadExt, runtime::Handle};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let client = Client::builder_tokio()
        .proxy(wreq::Proxy::all(proxy).unwrap())
        .build()
        .unwrap();
    let tasks = Handle::current().metrics().num_alive_tasks();

    // The proxy reads the CONNECT request and never answers it.
    let accept = async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
        }
        assert!(head.starts_with(b"CONNECT target.invalid:443 HTTP/1.1\r\n"));
        socket
    };
    // `select!` drops the pending request, and with it the connect future.
    let mut socket = tokio::select! {
        socket = accept => socket,
        result = client.get("https://target.invalid/").send() => {
            panic!("connect finished before the proxy answered: {result:?}")
        }
    };

    let read = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut [0; 1]))
        .await
        .expect("the dropped connect future left the proxy connection open")
        .unwrap();
    assert_eq!(read, 0);
    assert_eq!(Handle::current().metrics().num_alive_tasks(), tasks);
}

#[cfg(feature = "socks")]
#[tokio::test]
async fn socks_preserves_dns_auth_and_connection_reuse() {
    use std::{
        net::SocketAddr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wreq::dns::{Addrs, Name, Resolve, Resolving};

    struct Resolver(Arc<Mutex<Vec<String>>>);

    impl Resolve for Resolver {
        fn resolve(&self, name: Name) -> Resolving {
            self.0.lock().unwrap().push(name.as_str().to_owned());
            let address: SocketAddr = match name.as_str() {
                "proxy.invalid" => "127.0.0.1:0".parse().unwrap(),
                "target.invalid" => "192.0.2.7:0".parse().unwrap(),
                name => panic!("unexpected DNS lookup: {name}"),
            };
            Box::pin(async move { Ok(Box::new(std::iter::once(address)) as Addrs) })
        }
    }

    for (scheme, v4, remote) in [
        ("socks4", true, false),
        ("socks4a", true, true),
        ("socks5", false, false),
        ("socks5h", false, true),
    ] {
        for target in ["target.invalid", "192.0.2.7"] {
            let domain = remote && target == "target.invalid";
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            // One accepted socket must carry both HTTP requests after the handshake.
            let server = tokio::spawn(async move {
                let (mut stream, peer) = listener.accept().await.unwrap();
                #[cfg(target_os = "linux")]
                assert_eq!(peer.ip(), std::net::Ipv4Addr::new(127, 0, 0, 2));
                #[cfg(not(target_os = "linux"))]
                let _ = peer;
                if v4 {
                    let mut head = [0; 8];
                    stream.read_exact(&mut head).await.unwrap();
                    assert_eq!(&head[..2], &[4, 1]);
                    assert_eq!(u16::from_be_bytes([head[2], head[3]]), 8081);
                    assert_eq!(
                        &head[4..],
                        if domain {
                            &[0, 0, 0, 1]
                        } else {
                            &[192, 0, 2, 7]
                        }
                    );
                    let mut user = [0; 8];
                    stream.read_exact(&mut user).await.unwrap();
                    assert_eq!(&user, b"Aladdin\0");
                    if domain {
                        let mut host = vec![0; target.len() + 1];
                        stream.read_exact(&mut host).await.unwrap();
                        assert_eq!(&host[..target.len()], target.as_bytes());
                        assert_eq!(host[target.len()], 0);
                    }
                    stream.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await.unwrap();
                } else {
                    assert_eq!(stream.read_u8().await.unwrap(), 5);
                    let mut methods = vec![0; stream.read_u8().await.unwrap() as usize];
                    stream.read_exact(&mut methods).await.unwrap();
                    assert!(methods.contains(&2));
                    stream.write_all(&[5, 2]).await.unwrap();
                    assert_eq!(stream.read_u8().await.unwrap(), 1);
                    for expected in [b"Aladdin".as_slice(), b"open sesame".as_slice()] {
                        let mut value = vec![0; stream.read_u8().await.unwrap() as usize];
                        stream.read_exact(&mut value).await.unwrap();
                        assert_eq!(value, expected);
                    }
                    stream.write_all(&[1, 0]).await.unwrap();

                    let mut head = [0; 4];
                    stream.read_exact(&mut head).await.unwrap();
                    assert_eq!(head, [5, 1, 0, if domain { 3 } else { 1 }]);
                    if domain {
                        let mut host = vec![0; stream.read_u8().await.unwrap() as usize];
                        stream.read_exact(&mut host).await.unwrap();
                        assert_eq!(host, target.as_bytes());
                    } else {
                        let mut address = [0; 4];
                        stream.read_exact(&mut address).await.unwrap();
                        assert_eq!(address, [192, 0, 2, 7]);
                    }
                    assert_eq!(stream.read_u16().await.unwrap(), 8081);
                    stream
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                }

                let requests = AtomicUsize::new(0);
                server::serve_connection(stream, http::Version::HTTP_11, move |request| {
                    let index = requests.fetch_add(1, Ordering::Relaxed);
                    async move {
                        assert!(index < 2);
                        assert_eq!(request.uri(), "/resource");
                        assert_eq!(request.headers()["host"], format!("{target}:8081"));
                        assert!(
                            !request
                                .headers()
                                .contains_key(http::header::PROXY_AUTHORIZATION)
                        );
                        let response = http::Response::builder();
                        let response = if index == 1 {
                            response.header(http::header::CONNECTION, "close")
                        } else {
                            response
                        };
                        response.body(wreq::Body::from("through socks")).unwrap()
                    }
                })
                .await
                .unwrap();
            });
            let lookups = Arc::new(Mutex::new(Vec::new()));
            let client = Client::builder_tokio()
                .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
                .no_proxy()
                .proxy(
                    wreq::Proxy::all(format!("{scheme}://proxy.invalid:{port}"))
                        .unwrap()
                        .basic_auth("Aladdin", "open sesame"),
                )
                .dns_resolver(Resolver(lookups.clone()))
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap();
            for _ in 0..2 {
                let request = client.get(format!("http://{target}:8081/resource"));
                #[cfg(target_os = "linux")]
                let request = request
                    .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2)));
                let response = request.send().await.unwrap();
                assert_eq!(response.status(), http::StatusCode::OK);
                assert_eq!(response.bytes().await.unwrap(), "through socks");
            }
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();

            let mut actual = lookups.lock().unwrap().clone();
            actual.sort();
            let expected = if !remote && target == "target.invalid" {
                vec!["proxy.invalid", "target.invalid"]
            } else {
                vec!["proxy.invalid"]
            };
            assert_eq!(actual, expected, "{scheme} with {target}");
        }
    }
}

#[tokio::test]
async fn https_proxy_tunnel_follows_client_hostname_verification() {
    use std::{pin::Pin, time::Duration};

    use btls::{
        pkey::PKey,
        ssl::{Ssl, SslAcceptor, SslMethod},
        x509::X509,
    };
    use http::Version;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wreq::{Proxy, tls::trust::CertStore};

    // Issued by localhost-ca for localhost and 127.0.0.1: valid for the target, not the proxy.
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_der(include_bytes!("support/localhost.cert")).unwrap())
        .unwrap();
    acceptor
        .set_private_key(
            &PKey::private_key_from_der(include_bytes!("support/localhost.key")).unwrap(),
        )
        .unwrap();
    let acceptor = acceptor.build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let mut stream = tokio_btls::SslStream::new(ssl, socket).unwrap();
            // A client verifying the proxy host aborts this handshake.
            if Pin::new(&mut stream).accept().await.is_err() {
                continue;
            }
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            assert!(head.starts_with(b"CONNECT localhost:443 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let stream = server::tls_accept(&acceptor, stream).await;
            server::serve_connection(stream, Version::HTTP_11, |_| async {
                http::Response::builder()
                    .header(http::header::CONNECTION, "close")
                    .body(wreq::Body::from("ok"))
                    .unwrap()
            })
            .await
            .unwrap();
            break;
        }
    });

    let client = |verify_hostname| {
        let ca = include_bytes!("support/localhost-ca.cert").as_slice();
        Client::builder_tokio()
            .resolve("proxy.test", addr)
            .proxy(Proxy::all(format!("https://proxy.test:{}", addr.port())).unwrap())
            .tls_cert_store(CertStore::from_der_certs([ca]).unwrap())
            .tls_verify_hostname(verify_hostname)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    };

    // Only the proxy hop can fail: its certificate does not cover proxy.test.
    let error = client(true)
        .get("https://localhost/")
        .send()
        .await
        .unwrap_err();
    assert!(error.is_proxy_connect(), "{error:?}");
    assert!(
        format!("{error:?}").contains("CERTIFICATE_VERIFY_FAILED"),
        "{error:?}"
    );

    // Disabling hostname verification covers the proxy hop as well as the target.
    let response = client(false)
        .get("https://localhost/")
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "ok");
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}
