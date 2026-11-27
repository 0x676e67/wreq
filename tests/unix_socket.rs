#![cfg(all(unix, feature = "tokio-rt"))]

#[path = "support/tls_cert.rs"]
mod tls_cert;

use std::{hash::BuildHasher, path::PathBuf, pin::Pin, time::Duration};

use btls::ssl::Ssl;
use http::{Method, StatusCode, header::CONNECTION};
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::{
    net::{TcpListener, TcpStream, UnixListener},
    sync::mpsc,
    task,
    time::timeout,
};
use wreq::{Client, Proxy, tls::trust::CertStore};

struct SocketPath(PathBuf);

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn bind_unix_listener() -> (UnixListener, SocketPath) {
    // libstd uses system random to create each one
    let rng = std::collections::hash_map::RandomState::new();
    let n = rng.hash_one("uds-sock");
    let path = std::env::temp_dir().join(format!("test-uds-sock-{n}"));
    let listener = UnixListener::bind(&path).expect("bind test Unix socket");
    (listener, SocketPath(path))
}

#[tokio::test]
async fn test_unix_socket() {
    let (listener, sock_path) = bind_unix_listener();
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
        .proxy(Proxy::unix(sock_path.0.as_path()).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let resp = client.get("http://localhost/").send().await.unwrap();
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello unix");
}

#[tokio::test]
async fn test_proxy_unix_socket() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (cert, key) = tls_cert::self_signed("localhost", upstream_addr.ip());
    let acceptor = tls_cert::acceptor(&cert, &key);
    let trust = CertStore::builder()
        .add_der_cert(&cert.to_der().unwrap())
        .build()
        .unwrap();
    let upstream = tokio::spawn(async move {
        let (tcp, _) = upstream.accept().await.unwrap();
        let ssl = Ssl::new(acceptor.context()).unwrap();
        let mut stream = tokio_btls::SslStream::new(ssl, tcp).unwrap();
        Pin::new(&mut stream).accept().await.unwrap();
        let service = service_fn(|req: Request<Incoming>| async move {
            assert_eq!(req.method(), Method::GET);
            assert_eq!(req.uri(), "/resource");
            Ok::<_, hyper::Error>(
                Response::builder()
                    .header(CONNECTION, "close")
                    .body(Full::new(&b"hello tunnel"[..]))
                    .unwrap(),
            )
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });

    let (listener, sock_path) = bind_unix_listener();
    let proxy = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let expected_authority = upstream_addr.to_string();
        let (upgrade_tx, mut upgrade_rx) = mpsc::channel(1);
        let service = service_fn(move |req: Request<Incoming>| {
            assert_eq!(req.method(), Method::CONNECT);
            let authority = req.uri().authority().expect("CONNECT authority");
            assert_eq!(authority.as_str(), expected_authority);
            upgrade_tx
                .try_send(hyper::upgrade::on(req))
                .expect("one CONNECT request");
            async {
                Ok::<_, hyper::Error>(
                    Response::builder()
                        .status(StatusCode::CREATED)
                        .body(Full::new(&b""[..]))
                        .unwrap(),
                )
            }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await
            .unwrap();

        // Hyper finishes the CONNECT response before handing over the socket.
        let upgrade = upgrade_rx
            .try_recv()
            .expect("Unix proxy must receive CONNECT");
        let mut tunnel = TokioIo::new(upgrade.await.unwrap());
        let mut upstream = TcpStream::connect(upstream_addr).await.unwrap();
        tokio::io::copy_bidirectional(&mut tunnel, &mut upstream)
            .await
            .unwrap();
    });

    let client = Client::builder_tokio()
        .proxy(Proxy::unix(sock_path.0.as_path()).unwrap())
        .tls_cert_store(trust)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let resp = client
        .get(format!("https://{upstream_addr}/resource"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "hello tunnel");
    drop(client);
    timeout(Duration::from_secs(5), proxy)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(5), upstream)
        .await
        .unwrap()
        .unwrap();
}
