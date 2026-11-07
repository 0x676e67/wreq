#![cfg(feature = "compio-rt")]

mod support;

use std::{
    convert::Infallible,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, TcpListener},
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use bytes::Bytes;
use http::{
    StatusCode, Version,
    header::{CONNECTION, UPGRADE},
};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wreq::{Body, Client};

#[test]
fn compio_client_uses_its_own_dns_io_and_timer() {
    let server = support::server::http(|request| async move {
        let version = request.version();
        let body = request.into_body().collect().await.unwrap().to_bytes();
        http::Response::builder()
            .version(version)
            .body(Body::from(body))
            .unwrap()
    });
    let runtime = compio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        // The server has its own Tokio thread; this client thread has no Tokio runtime.
        // Resolving localhost must therefore use the selected Compio runtime as well.
        let client = Client::builder_compio()
            .no_proxy()
            .local_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("http://localhost:{}/echo", server.addr().port());
        let payload = vec![b'x'; 4096];
        let echo = async |version| {
            let response = client
                .post(&url)
                .version(version)
                .body(payload.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(response.version(), version);
            assert_eq!(response.bytes().await.unwrap(), payload);
        };
        echo(Version::HTTP_11).await;
        #[cfg(feature = "http2")]
        echo(Version::HTTP_2).await;
    });
}

#[test]
fn compio_try_execute_returns_tasks_without_a_runtime() {
    use wreq::rt::{Runtime as _, compio::CompioRuntime};

    let (done, ran) = tokio::sync::oneshot::channel();
    // Outside a Compio runtime the task comes back instead of panicking.
    let task = CompioRuntime
        .try_execute(Box::pin(async move { done.send(()).unwrap() }))
        .unwrap_err();
    compio::runtime::Runtime::new().unwrap().block_on(async {
        assert!(CompioRuntime.try_execute(task).is_ok());
        ran.await.unwrap();
    });
}

#[test]
fn oversized_timeouts_do_not_overflow() {
    let server = support::server::http(|_| async { http::Response::new(Body::from("ok")) });
    let url = format!("http://{}/", server.addr());
    let get = async |builder: wreq::ClientBuilder| {
        let builder = builder
            .no_proxy()
            .timeout(Duration::MAX)
            .read_timeout(Duration::MAX)
            .connect_timeout(Duration::MAX)
            .pool_idle_timeout(Duration::MAX);
        #[cfg(feature = "http2")]
        let builder = builder.http2_options(
            wreq::http2::Http2Options::builder()
                .keep_alive_interval(Duration::MAX)
                .keep_alive_timeout(Duration::MAX)
                .keep_alive_while_idle(true)
                .build(),
        );
        let client = builder.build().unwrap();
        let send = async |version| {
            let response = client.get(&url).version(version).send().await.unwrap();
            assert_eq!(response.version(), version);
            assert_eq!(response.text().await.unwrap(), "ok");
        };
        send(Version::HTTP_11).await;
        #[cfg(feature = "http2")]
        send(Version::HTTP_2).await;
    };

    compio::runtime::Runtime::new()
        .unwrap()
        .block_on(get(Client::builder_compio()));
    #[cfg(feature = "tokio-rt")]
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(get(Client::builder_tokio()));
}

#[test]
fn early_response_is_read_while_upload_is_blocked() {
    // The server answers after the request head and never reads the body, so the upload stalls.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let (done, wait) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (mut head, mut buf) = (Vec::new(), [0; 1024]);
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let n = stream.read(&mut buf).unwrap();
            assert_ne!(n, 0, "client closed before sending the request head");
            head.extend_from_slice(&buf[..n]);
        }
        stream
            .write_all(b"HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\n\r\n")
            .unwrap();
        let _ = wait.recv();
    });

    compio::runtime::Runtime::new().unwrap().block_on(async {
        let client = Client::builder_compio()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        // Larger than the loopback socket buffers, so the upload stays blocked.
        let response = client
            .post(&url)
            .body(vec![0; 16 << 20])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    });
    drop(done);
    server.join().unwrap();
}

#[test]
fn split_upgrade_keeps_reader_and_writer_wakeups() {
    // Larger than the loopback socket buffers, so a flush blocks until the server reads.
    const UPLOAD: usize = 16 << 20;
    let read_upload = Arc::new(tokio::sync::Notify::new());
    let server = support::server::http({
        let read_upload = read_upload.clone();
        move |request| {
            let read_upload = read_upload.clone();
            tokio::spawn(async move {
                let mut io =
                    hyper_util::rt::TokioIo::new(hyper::upgrade::on(request).await.unwrap());
                let mut ping = [0; 4];
                io.read_exact(&mut ping).await.unwrap();
                assert_eq!(&ping, b"ping");
                io.write_all(b"pong").await.unwrap();
                read_upload.notified().await;
                io.read_exact(&mut vec![0; UPLOAD]).await.unwrap();
                io.write_all(b"done").await.unwrap();
            });
            async {
                http::Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header(CONNECTION, "upgrade")
                    .header(UPGRADE, "test")
                    .body(Body::default())
                    .unwrap()
            }
        }
    });
    let url = format!("http://{}/", server.addr());

    compio::runtime::Runtime::new().unwrap().block_on(async {
        let response = Client::builder_compio()
            .no_proxy()
            .build()
            .unwrap()
            .get(&url)
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "test")
            .send()
            .await
            .unwrap();
        let (mut reader, mut writer) = tokio::io::split(response.upgrade().await.unwrap());
        // The reader polls while the writer waits on its flush; each task must still wake.
        let writer = compio::runtime::spawn(async move {
            writer.write_all(b"ping").await.unwrap();
            writer.flush().await.unwrap();
            writer
        });
        let reader = compio::runtime::spawn(async move {
            let mut pong = [0; 4];
            reader.read_exact(&mut pong).await.unwrap();
            (reader, pong)
        });
        let (writer, reader) = compio::time::timeout(
            Duration::from_secs(5),
            futures_util::future::join(writer, reader),
        )
        .await
        .expect("split upgrade stalled");
        let (mut writer, (mut reader, pong)) = (writer.unwrap(), reader.unwrap());
        assert_eq!(&pong, b"pong");

        // A writer that abandons its blocked flush leaves the rest of the upload to the reader.
        compio::runtime::spawn(async move {
            writer.write_all(&vec![0; UPLOAD]).await.unwrap();
            compio::time::timeout(Duration::from_millis(100), writer.flush())
                .await
                .expect_err("upload flushed before the server read it");
        })
        .await
        .unwrap();
        read_upload.notify_one();
        let mut done = [0; 4];
        compio::time::timeout(Duration::from_secs(5), reader.read_exact(&mut done))
            .await
            .expect("abandoned flush stalled")
            .unwrap();
        assert_eq!(&done, b"done");
    });
}

#[test]
fn timed_out_body_can_be_polled_again() {
    let server = support::server::http(|_| async {
        // The head arrives at once; the body never yields a frame.
        let body = StreamBody::new(futures_util::stream::pending::<
            Result<Frame<Bytes>, Infallible>,
        >());
        http::Response::new(Body::wrap(body))
    });
    let url = format!("http://{}/", server.addr());

    compio::runtime::Runtime::new().unwrap().block_on(async {
        let timeout = Duration::from_millis(100);
        for builder in [
            Client::builder_compio().timeout(timeout),
            Client::builder_compio().read_timeout(timeout),
        ] {
            let client = builder.no_proxy().build().unwrap();
            let mut response = client.get(&url).send().await.unwrap();
            // A fired timer keeps reporting the timeout instead of resuming its finished future.
            for _ in 0..2 {
                let error = response.frame().await.unwrap().unwrap_err();
                assert!(error.is_body() && error.is_timeout(), "{error:?}");
            }
        }
    });
}

#[cfg(feature = "http3")]
#[test]
fn compio_http3_fails_without_affecting_tcp() {
    use std::{error::Error as _, io};

    let server = support::server::http(|_| async { http::Response::new(Body::from("ok")) });
    compio::runtime::Runtime::new().unwrap().block_on(async {
        let client = Client::builder_compio()
            .http3_only()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        // Compio keeps the default `Runtime::udp_socket`, so registering the QUIC socket fails.
        // A failed attempt must not leave a broken endpoint behind for the next one.
        for _ in 0..2 {
            let err = client
                .get(format!("https://{}/", server.addr()))
                .send()
                .await
                .unwrap_err();
            assert!(err.is_connect(), "{err:?}");
            let unsupported = std::iter::successors(err.source(), |&source| source.source())
                .filter_map(|source| source.downcast_ref::<io::Error>())
                .any(|error| error.kind() == io::ErrorKind::Unsupported);
            assert!(unsupported, "{err:?}");
        }

        // Explicit TCP versions override `http3_only` and still work on the same client.
        let send = async |version| {
            let response = client
                .get(format!("http://{}/", server.addr()))
                .version(version)
                .send()
                .await
                .unwrap();
            assert_eq!(response.version(), version);
            assert_eq!(response.text().await.unwrap(), "ok");
        };
        send(Version::HTTP_11).await;
        #[cfg(feature = "http2")]
        send(Version::HTTP_2).await;
    });
}
