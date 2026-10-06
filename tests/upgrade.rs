mod support;
use http::Method;
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

    let res = Client::builder()
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

    let res = Client::builder()
        .http2_only()
        .build()
        .unwrap()
        .request(Method::CONNECT, format!("http://{}", server.addr()))
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

    let client = Client::builder().no_proxy().build().unwrap();
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
}

#[cfg(feature = "ws")]
#[tokio::test]
async fn websocket_reuses_established_http2_with_extended_connect() {
    use std::{convert::Infallible, error::Error as _};

    use futures_util::{SinkExt, StreamExt};
    use http::header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
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
        let client = Client::builder().http2_only().no_proxy().build().unwrap();
        let ws_url = format!("ws://{}", server.addr());
        let http_url = format!("http://{}", server.addr());

        // A WebSocket never opens an HTTP/2 connection for itself.
        let response = client.websocket(&ws_url).send().await.unwrap();
        assert_eq!(response.version(), http::Version::HTTP_11);
        drop(response);
        assert_eq!(accepted(&mut server), 1);

        let response = client.get(&http_url).send().await.unwrap();
        assert_eq!(response.version(), http::Version::HTTP_2);
        response.bytes().await.unwrap();
        assert_eq!(accepted(&mut server), 2);

        // The default route rides the established connection only if its peer allows it.
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

        // Explicit HTTP/2 uses its own group: a new connection waits for SETTINGS, and a
        // known refusal fails before sending instead of retrying the same connection.
        for _ in 0..2 {
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
