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
