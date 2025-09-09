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
