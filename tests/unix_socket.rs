#![cfg(all(unix, feature = "tokio-rt"))]

mod support;

use std::{hash::BuildHasher, time::Duration};

use http::{Method, Version};
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use support::server;
use tokio::{net::UnixListener, task};
use wreq::{Client, Proxy};

fn random_sock_path() -> std::path::PathBuf {
    let mut buf = std::env::temp_dir();
    // libstd uses system random to create each one
    let rng = std::collections::hash_map::RandomState::new();
    let n = rng.hash_one("uds-sock");
    buf.push(format!("test-uds-sock-{}", n));
    buf
}

#[tokio::test]
async fn test_unix_socket() {
    let sock_path = random_sock_path();

    let listener = UnixListener::bind(&sock_path).unwrap();
    let server = async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(|_req: Request<Incoming>| async {
                Ok::<_, hyper::Error>(Response::new(Full::new(&b"hello unix"[..])))
            });
            task::spawn(async move {
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    eprintln!("server error: {:?}", e);
                }
            });
        }
    };
    tokio::spawn(server);

    let client = Client::builder_tokio()
        .proxy(Proxy::unix(sock_path).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let resp = client.get("http://localhost/").send().await.unwrap();
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello unix");
}

#[tokio::test]
async fn test_proxy_unix_socket() {
    let sock_path = random_sock_path();

    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}/resource", target.local_addr().unwrap());
    let acceptor = server::tls_acceptor(b"\x08http/1.1");
    let target = tokio::spawn(async move {
        let (socket, _) = target.accept().await.unwrap();
        let stream = server::tls_accept(&acceptor, socket).await;
        server::serve_connection(stream, Version::HTTP_11, |request| async move {
            assert_eq!(request.method(), Method::GET);
            assert_eq!(request.uri(), "/resource");
            Response::builder()
                .header(http::header::CONNECTION, "close")
                .body(Full::new(&b"hello tunnel"[..]))
                .unwrap()
        })
        .await
        .unwrap();
    });

    let listener = UnixListener::bind(&sock_path).unwrap();
    let server = async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(|req: Request<Incoming>| {
                async move {
                    if Method::CONNECT == req.method() {
                        // Received an HTTP request like:
                        // ```
                        // CONNECT www.domain.com:443 HTTP/1.1
                        // Host: www.domain.com:443
                        // Proxy-Connection: Keep-Alive
                        // ```
                        //
                        // When HTTP method is CONNECT we should return an empty body,
                        // then we can eventually upgrade the connection and talk a new protocol.
                        //
                        // Note: only after client received an empty body with STATUS_OK can the
                        // connection be upgraded, so we can't return a response inside
                        // `on_upgrade` future.
                        let authority = req.uri().authority().cloned().unwrap();
                        tokio::task::spawn({
                            let req = req;
                            async move {
                                match hyper::upgrade::on(req).await {
                                    Ok(upgraded) => {
                                        tracing::info!("upgraded connection to: {}", authority);
                                        if let Ok(mut io) =
                                            tokio::net::TcpStream::connect(authority.to_string())
                                                .await
                                        {
                                            let _ = tokio::io::copy_bidirectional(
                                                &mut TokioIo::new(upgraded),
                                                &mut io,
                                            )
                                            .await;
                                        }
                                    }
                                    Err(e) => tracing::warn!("upgrade error: {}", e),
                                }
                            }
                        });

                        Ok::<_, hyper::Error>(Response::new(Full::new(&b""[..])))
                    } else {
                        Ok::<_, hyper::Error>(Response::new(Full::new(
                            &b"unsupported request method"[..],
                        )))
                    }
                }
            });
            task::spawn(async move {
                if let Err(e) = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(io, service)
                    .await
                {
                    eprintln!("server error: {:?}", e);
                }
            });
        }
    };
    tokio::spawn(server);

    let client = Client::builder_tokio()
        .proxy(Proxy::unix(sock_path).unwrap())
        .tls_cert_verification(false)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let resp = client.get(url).send().await.unwrap();
    assert!(resp.status().is_success(), "Expected successful response");
    assert_eq!(resp.text().await.unwrap(), "hello tunnel");
    tokio::time::timeout(Duration::from_secs(5), target)
        .await
        .unwrap()
        .unwrap();
}
