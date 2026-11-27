#![cfg(feature = "tokio-rt")]

mod support;
use support::server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wreq::Client;

#[tokio::test]
async fn http_upgrade() {
    let server = server::http(move |req| {
        assert_eq!(req.method(), "GET");
        assert_eq!(req.headers()["connection"], "upgrade");
        assert_eq!(req.headers()["upgrade"], "foobar");

        tokio::spawn(async move {
            let mut upgraded = hyper_util::rt::TokioIo::new(hyper::upgrade::on(req).await.unwrap());

            let mut buf = vec![0; 7];
            upgraded.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, b"foo=bar");

            upgraded.write_all(b"bar=foo").await.unwrap();
        });

        async {
            http::Response::builder()
                .status(http::StatusCode::SWITCHING_PROTOCOLS)
                .header(http::header::CONNECTION, "upgrade")
                .header(http::header::UPGRADE, "foobar")
                .body(wreq::Body::default())
                .unwrap()
        }
    });

    let res = Client::builder_tokio()
        .build()
        .unwrap()
        .get(format!("http://{}", server.addr()))
        .header(http::header::CONNECTION, "upgrade")
        .header(http::header::UPGRADE, "foobar")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), http::StatusCode::SWITCHING_PROTOCOLS);
    let mut upgraded = res.upgrade().await.unwrap();

    upgraded.write_all(b"foo=bar").await.unwrap();

    let mut buf = vec![];
    upgraded.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"bar=foo");
}

#[cfg(feature = "http2")]
#[tokio::test]
async fn adaptive_and_extended_connect_custom_protocol() {
    use std::convert::Infallible;

    use http::{
        HeaderName, Method, StatusCode, Version,
        header::{CONNECTION, UPGRADE},
    };
    use support::server::Event;
    use wreq::upgrade::{Protocol, Upgrade};

    const HANDSHAKE_KEY: HeaderName = HeaderName::from_static("x-handshake-key");
    const PROTO: Protocol = Protocol::from_static("foobar");

    for enabled in [true, false] {
        let mut server = server::http_with_config(
            |req: http::Request<hyper::body::Incoming>| async move {
                let mut res = http::Response::new(wreq::Body::default());
                if req.method() == Method::CONNECT {
                    assert_eq!(
                        req.extensions()
                            .get::<hyper::ext::Protocol>()
                            .map(hyper::ext::Protocol::as_str),
                        Some("foobar")
                    );
                    assert!(
                        [UPGRADE, CONNECTION, HANDSHAKE_KEY]
                            .iter()
                            .all(|h| !req.headers().contains_key(h))
                    );
                } else if req.headers().contains_key(UPGRADE) {
                    assert_eq!(req.headers()[HANDSHAKE_KEY], "abc");
                    *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                    res.headers_mut().insert(UPGRADE, "foobar".parse().unwrap());
                    res.headers_mut()
                        .insert(CONNECTION, "upgrade".parse().unwrap());
                } else {
                    return Ok::<_, Infallible>(res);
                }
                assert_eq!(req.headers()["x-keep"], "1");
                tokio::spawn(async move {
                    let mut io =
                        hyper_util::rt::TokioIo::new(hyper::upgrade::on(req).await.unwrap());
                    let mut buf = [0; 4];
                    io.read_exact(&mut buf).await.unwrap();
                    io.write_all(&buf).await.unwrap();
                });
                Ok::<_, Infallible>(res)
            },
            move |b| {
                if enabled {
                    b.http2().enable_connect_protocol();
                }
            },
        );
        let client = Client::builder_tokio()
            .http2_only()
            .no_proxy()
            .build()
            .unwrap();
        let url = format!("http://{}/tunnel", server.addr());

        client
            .get(&url)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let res = client
            .get(&url)
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "foobar")
            .header(HANDSHAKE_KEY, "abc")
            .header("x-keep", "1")
            .upgrade(Upgrade::adaptive(PROTO).strip_headers([HANDSHAKE_KEY]))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.version(),
            if enabled {
                Version::HTTP_2
            } else {
                Version::HTTP_11
            }
        );
        let accepts = server
            .events()
            .into_iter()
            .filter(|e| matches!(e, Event::ConnectionAccepted))
            .count();
        assert_eq!(accepts, if enabled { 1 } else { 2 });

        let mut io = res.upgrade().await.unwrap();
        io.write_all(b"ping").await.unwrap();
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"ping");

        let explicit = client
            .request(Method::CONNECT, &url)
            .header("x-keep", "1")
            .upgrade(Upgrade::extended_connect(PROTO))
            .send()
            .await;
        if enabled {
            assert_eq!(explicit.unwrap().status(), StatusCode::OK);
        } else {
            assert!(
                format!("{:?}", explicit.unwrap_err())
                    .contains("peer did not enable extended CONNECT")
            );
        }
    }
}

#[cfg(feature = "http2")]
#[tokio::test]
async fn http2_upgrade() {
    let server = server::http_with_config(
        move |req| {
            assert_eq!(req.method(), http::Method::CONNECT);
            assert_eq!(req.version(), http::Version::HTTP_2);

            tokio::spawn(async move {
                let mut upgraded =
                    hyper_util::rt::TokioIo::new(hyper::upgrade::on(req).await.unwrap());

                let mut buf = vec![0; 7];
                upgraded.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, b"foo=bar");

                upgraded.write_all(b"bar=foo").await.unwrap();
            });

            async { Ok::<_, std::convert::Infallible>(http::Response::default()) }
        },
        |builder| {
            let mut http2 = builder.http2();
            http2.enable_connect_protocol();
        },
    );

    let res = Client::builder_tokio()
        .http2_only()
        .build()
        .unwrap()
        .request(http::Method::CONNECT, format!("http://{}", server.addr()))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), http::StatusCode::OK);
    assert_eq!(res.version(), http::Version::HTTP_2);
    let mut upgraded = res.upgrade().await.unwrap();

    upgraded.write_all(b"foo=bar").await.unwrap();

    let mut buf = vec![];
    upgraded.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"bar=foo");
}

#[tokio::test]
async fn connect_target_names_default_port() {
    let server = server::http(|req| async move {
        assert_eq!(req.method(), http::Method::CONNECT);
        http::Response::builder()
            .header("x-target", req.uri().to_string())
            .header("x-host", req.headers()[http::header::HOST].clone())
            .body(wreq::Body::default())
            .unwrap()
    });
    // A forward proxy receives the CONNECT target, which must name the elided port.
    let proxy = wreq::Proxy::http(format!("http://{}", server.addr())).unwrap();
    for (builder, version) in [
        (Client::builder_tokio(), http::Version::HTTP_11),
        #[cfg(feature = "http2")]
        (Client::builder_tokio().http2_only(), http::Version::HTTP_2),
    ] {
        let client = builder.proxy(proxy.clone()).build().unwrap();
        // `Uri` accepts a port a u16 cannot hold, which is not an elided one.
        for (authority, target) in [
            ("connect.test", "connect.test:80"),
            ("connect.test:65536", "connect.test:65536"),
        ] {
            let res = client
                .request(http::Method::CONNECT, format!("http://{authority}/"))
                .header(http::header::HOST, authority)
                .send()
                .await
                .unwrap();
            assert_eq!(res.version(), version);
            assert_eq!(res.headers()["x-target"], target);
            // HTTP/1 keeps the caller's Host; multiplexed versions align it with `:authority`.
            let host = match version {
                http::Version::HTTP_2 => target,
                _ => authority,
            };
            assert_eq!(res.headers()["x-host"], host);
        }
    }

    #[cfg(feature = "http2")]
    {
        let client = Client::builder_tokio().proxy(proxy).build().unwrap();
        let mut request = client
            .request(http::Method::CONNECT, "http://connect.test/")
            .version(http::Version::HTTP_11)
            .build()
            .unwrap();
        request
            .extensions_mut()
            .insert(http2::ext::Protocol::from_static("foobar"));
        let error = client.execute(request).await.unwrap_err();
        assert!(format!("{error:?}").contains("UserUnsupportedVersion"));
    }
}

#[cfg(feature = "ws")]
#[tokio::test]
async fn websocket_uses_dedicated_http1_connection() {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use http::header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
    use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let accepted = accepted.clone();
        async move {
            loop {
                let (io, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        |req: http::Request<hyper::body::Incoming>| async move {
                            let mut res = http::Response::new(wreq::Body::default());
                            if let Some(key) = req.headers().get(SEC_WEBSOCKET_KEY) {
                                *res.status_mut() = http::StatusCode::SWITCHING_PROTOCOLS;
                                let headers = res.headers_mut();
                                headers.insert(UPGRADE, "websocket".parse().unwrap());
                                headers.insert(CONNECTION, "upgrade".parse().unwrap());
                                headers.insert(
                                    SEC_WEBSOCKET_ACCEPT,
                                    derive_accept_key(key.as_bytes()).parse().unwrap(),
                                );
                            }
                            Ok::<_, Infallible>(res)
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(io), service)
                        .with_upgrades()
                        .await;
                });
            }
        }
    });

    let client = Client::builder_tokio().no_proxy().build().unwrap();
    let get = || {
        client
            .get(format!("http://{addr}"))
            .version(http::Version::HTTP_11)
            .send()
    };
    get().await.unwrap().bytes().await.unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 1);

    // The handshake opens its own socket instead of taking the idle keep-alive one.
    let websocket = client
        .websocket(format!("ws://{addr}"))
        .send()
        .await
        .unwrap()
        .into_websocket()
        .await
        .unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    drop(websocket);

    // The idle connection is still pooled, and the WebSocket socket never joined it.
    get().await.unwrap().bytes().await.unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 2);

    let request =
        client
            .get(format!("ws://{addr}"))
            .upgrade(wreq::upgrade::Upgrade::extended_connect(
                wreq::upgrade::Protocol::WEBSOCKET,
            ));
    let websocket = wreq::ws::WebSocketRequestBuilder::new(request)
        .version(http::Version::HTTP_11)
        .send()
        .await
        .unwrap()
        .into_websocket()
        .await
        .unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    drop(websocket);

    // The explicit HTTP/1.1 handshake consumed the idle socket.
    get().await.unwrap().bytes().await.unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
}

#[cfg(all(feature = "ws", feature = "http2"))]
#[tokio::test]
async fn websocket_reuses_established_http2_with_extended_connect() {
    use std::{convert::Infallible, error::Error as _};

    use futures_util::{SinkExt, StreamExt};
    use http::{
        Method,
        header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE},
    };
    use support::server::Event;
    use tokio_tungstenite::{
        WebSocketStream,
        tungstenite::{handshake::derive_accept_key, protocol::Role},
    };
    use wreq::ws::message::Message;

    async fn echo(upgrade: hyper::upgrade::OnUpgrade) {
        let io = hyper_util::rt::TokioIo::new(upgrade.await.unwrap());
        let mut ws = WebSocketStream::from_raw_socket(io, Role::Server, None).await;
        while let Some(Ok(message)) = ws.next().await {
            if message.is_text() && ws.send(message).await.is_err() {
                break;
            }
        }
    }

    for enabled in [true, false] {
        let mut server = server::http_with_config(
            |mut req: http::Request<hyper::body::Incoming>| async move {
                let mut res = http::Response::new(wreq::Body::default());
                if req.method() == Method::CONNECT {
                    // RFC 8441 §5: no RFC 6455 key or connection-specific fields.
                    assert_eq!(req.version(), http::Version::HTTP_2);
                    let protocol = req.extensions().get::<hyper::ext::Protocol>().unwrap();
                    assert_eq!(protocol.as_str(), "websocket");
                    for name in [SEC_WEBSOCKET_KEY, UPGRADE, CONNECTION] {
                        assert!(!req.headers().contains_key(name));
                    }
                    tokio::spawn(echo(hyper::upgrade::on(&mut req)));
                } else if let Some(key) = req.headers().get(SEC_WEBSOCKET_KEY) {
                    assert_eq!(req.version(), http::Version::HTTP_11);
                    *res.status_mut() = http::StatusCode::SWITCHING_PROTOCOLS;
                    let accept = derive_accept_key(key.as_bytes()).parse().unwrap();
                    let headers = res.headers_mut();
                    headers.insert(UPGRADE, "websocket".parse().unwrap());
                    headers.insert(CONNECTION, "upgrade".parse().unwrap());
                    headers.insert(SEC_WEBSOCKET_ACCEPT, accept);
                    tokio::spawn(echo(hyper::upgrade::on(&mut req)));
                }
                Ok::<_, Infallible>(res)
            },
            move |builder| {
                if enabled {
                    builder.http2().enable_connect_protocol();
                }
            },
        );
        let mut accepted = 0;
        let mut accepted = move |server: &mut server::Server| {
            accepted += server
                .events()
                .into_iter()
                .filter(|event| matches!(event, Event::ConnectionAccepted))
                .count();
            accepted
        };
        let client = Client::builder_tokio()
            .http2_only()
            .no_proxy()
            .build()
            .unwrap();
        let ws_url = format!("ws://{}", server.addr());
        let http_url = format!("http://{}", server.addr());

        // The default WebSocket route does not open an HTTP/2 connection.
        let response = client.websocket(&ws_url).send().await.unwrap();
        assert_eq!(response.version(), http::Version::HTTP_11);
        drop(response);
        assert_eq!(accepted(&mut server), 1);

        let response = client.get(&http_url).send().await.unwrap();
        assert_eq!(response.version(), http::Version::HTTP_2);
        response.bytes().await.unwrap();
        assert_eq!(accepted(&mut server), 2);

        // The default route reuses the connection only if its peer enabled extended CONNECT.
        let response = client.websocket(&ws_url).send().await.unwrap();
        let expected = if enabled {
            http::Version::HTTP_2
        } else {
            http::Version::HTTP_11
        };
        assert_eq!(response.version(), expected);
        let mut websocket = response.into_websocket().await.unwrap();
        websocket.send(Message::text("ping")).await.unwrap();
        assert_eq!(
            websocket.recv().await.unwrap().unwrap(),
            Message::text("ping")
        );
        assert_eq!(accepted(&mut server), if enabled { 2 } else { 3 });

        // The shared connection stays reusable while the tunnel is open.
        let response = client.get(&http_url).send().await.unwrap();
        assert_eq!(response.version(), http::Version::HTTP_2);
        response.bytes().await.unwrap();
        let before = if enabled { 2 } else { 3 };
        assert_eq!(accepted(&mut server), before);
        drop(websocket);

        // Explicit HTTP/2 shares this client's group, but has its own on an automatic client:
        // a new connection waits for SETTINGS, and a known refusal fails before sending
        // instead of retrying the same connection.
        let auto = Client::builder_tokio().no_proxy().build().unwrap();
        for client in [&client, &auto, &auto] {
            let result = client
                .websocket(&ws_url)
                .version(http::Version::HTTP_2)
                .send()
                .await;
            if enabled {
                assert_eq!(result.unwrap().version(), http::Version::HTTP_2);
            } else {
                let error = result.unwrap_err();
                let mut source = error.source();
                let mut disabled = false;
                while let Some(error) = source {
                    disabled |= error
                        .to_string()
                        .contains("peer did not enable extended CONNECT");
                    source = error.source();
                }
                assert!(disabled, "{error:?}");
            }
        }
        assert_eq!(accepted(&mut server), before + 1);
    }
}

#[cfg(all(feature = "ws", feature = "http3"))]
#[tokio::test]
async fn websocket_reuses_established_http3_with_extended_connect() {
    use bytes::BytesMut;
    use futures_util::{SinkExt, StreamExt};
    use http::{
        Method, Response, Version,
        header::{CONNECTION, SEC_WEBSOCKET_KEY, UPGRADE},
    };
    use support::h3;
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};
    use wreq::ws::{WebSocketResponse, message::Message};

    /// Echoes text messages on the tunnel of an accepted extended CONNECT. Tungstenite runs on
    /// one end of a pipe whose other end is pumped to and from the request stream.
    async fn echo(stream: h3::RequestStream) {
        let (mut send, mut recv) = stream.split();
        let (io, tunnel) = tokio::io::duplex(4096);
        let (mut reader, mut writer) = tokio::io::split(tunnel);
        let inbound = async move {
            while let Ok(Some(mut data)) = recv.recv_data().await {
                if writer.write_all_buf(&mut data).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        };
        let outbound = async move {
            let mut buf = BytesMut::with_capacity(4096);
            while reader.read_buf(&mut buf).await.is_ok_and(|n| n > 0) {
                if send.send_data(buf.split().freeze()).await.is_err() {
                    break;
                }
            }
            let _ = send.finish().await;
        };
        let websocket = async move {
            let mut ws = WebSocketStream::from_raw_socket(io, Role::Server, None).await;
            while let Some(Ok(message)) = ws.next().await {
                if message.is_text() && ws.send(message).await.is_err() {
                    break;
                }
            }
        };
        tokio::join!(inbound, outbound, websocket);
    }

    async fn ping(response: WebSocketResponse) {
        assert_eq!(response.version(), Version::HTTP_3);
        let mut websocket = response.into_websocket().await.unwrap();
        websocket.send(Message::text("ping")).await.unwrap();
        assert_eq!(
            websocket.recv().await.unwrap().unwrap(),
            Message::text("ping")
        );
    }

    for enabled in [true, false] {
        let certificate = h3::Certificate::new("localhost");
        let endpoint = h3::endpoint(&certificate, None);
        let server = h3::Server::serve(endpoint, enabled, |request, mut stream| async move {
            stream.send_response(Response::new(())).await.unwrap();
            if request.method() == Method::CONNECT {
                // RFC 9220 §3 follows RFC 8441 §5: no RFC 6455 key or connection-specific fields.
                assert_eq!(
                    request.extensions().get::<http3::ext::Protocol>(),
                    Some(&http3::ext::Protocol::WEBSOCKET)
                );
                for name in [SEC_WEBSOCKET_KEY, UPGRADE, CONNECTION] {
                    assert!(!request.headers().contains_key(name));
                }
                echo(stream).await;
            } else {
                stream.finish().await.unwrap();
            }
        });
        // Nothing listens on TCP, so a fallback to a dedicated HTTP/1.1 connection fails.
        let client = Client::builder_tokio()
            .no_proxy()
            .http3_only()
            .resolve("localhost", server.addr())
            .tls_cert_store(certificate.cert_store())
            .build()
            .unwrap();
        let port = server.addr().port();
        let ws_url = format!("wss://localhost:{port}/chat");
        let http_url = format!("https://localhost:{port}/");

        // The default WebSocket route does not open an HTTP/3 connection.
        let error = client.websocket(&ws_url).send().await.unwrap_err();
        assert!(error.is_connect(), "{error:?}");
        assert_eq!(server.connections(), 0);

        let response = client.get(&http_url).send().await.unwrap();
        assert_eq!(response.version(), Version::HTTP_3);
        response.bytes().await.unwrap();
        assert_eq!(server.connections(), 1);

        // The default route reuses the connection only if its peer enabled extended CONNECT.
        let result = client.websocket(&ws_url).send().await;
        if enabled {
            ping(result.unwrap()).await;
        } else {
            let error = result.unwrap_err();
            assert!(error.is_connect(), "{error:?}");
        }
        assert_eq!(server.connections(), 1);

        // Explicit HTTP/3 shares the client's group; a known refusal fails before sending.
        let result = client
            .websocket(&ws_url)
            .version(Version::HTTP_3)
            .send()
            .await;
        if enabled {
            ping(result.unwrap()).await;
        } else {
            let error = format!("{:?}", result.unwrap_err());
            assert!(
                error.contains("peer did not enable extended CONNECT"),
                "{error}"
            );
        }
        assert_eq!(server.connections(), 1);
    }
}
