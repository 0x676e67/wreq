#![cfg(all(feature = "http3", feature = "tokio-rt"))]

mod support;

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::{Method, Response, StatusCode, Version, header::LOCATION};
use http3::error::Code;
use support::h3;
use wreq::{Body, Client, redirect, retry::Policy, tls::trust::CertStore};

/// Binds an HTTP/3 endpoint for `localhost` and returns the client trust store for it.
fn endpoint() -> (quic::Endpoint, CertStore) {
    let certificate = h3::Certificate::new("localhost");
    (h3::endpoint(&certificate, None), certificate.cert_store())
}

/// Rejects the first `rejections` POSTs with `code`, then answers. Returns whether the request
/// succeeded and how many attempts reached the server.
async fn post(code: Code, rejections: usize, body: Body, retry: Option<Policy>) -> (bool, usize) {
    let (endpoint, cert_store) = endpoint();
    let addr = endpoint.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let received = count.clone();
    let (release, mut released) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (_, mut server) = h3::accept(&endpoint).await;
        loop {
            let next = tokio::select! {
                _ = &mut released => break,
                next = server.accept() => next.unwrap().unwrap(),
            };
            let (head, mut stream) = next.resolve_request().await.unwrap();
            assert_eq!(head.method(), Method::POST);
            assert_eq!(head.version(), Version::HTTP_3);
            let mut body = Vec::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            assert_eq!(body, b"replay me");
            if received.fetch_add(1, Ordering::SeqCst) < rejections {
                // Inspecting the bytes here has no application side effect.
                stream.stop_stream(code);
            } else {
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
            }
        }
    });

    let mut builder = Client::builder_tokio()
        .no_proxy()
        .http3_only()
        .resolve("localhost", addr)
        .tls_cert_store(cert_store);
    if let Some(retry) = retry {
        builder = builder.retry(retry);
    }
    let client = builder.build().unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        client
            .post(format!("https://localhost:{}/", addr.port()))
            .body(body)
            .send(),
    )
    .await
    .expect("retry must finish within its request limit");
    let succeeded = result.is_ok();
    if let Ok(response) = result {
        assert_eq!(response.version(), Version::HTTP_3);
        assert!(response.bytes().await.unwrap().is_empty());
    }
    let _ = release.send(());
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap();
    (succeeded, count.load(Ordering::SeqCst))
}

#[tokio::test]
async fn http3_replays_only_rejected_requests() {
    // Only rejection guarantees the server did not process the request.
    for (code, expected) in [
        (Code::H3_REQUEST_REJECTED, (true, 2)),
        (Code::H3_REQUEST_CANCELLED, (false, 1)),
    ] {
        assert_eq!(
            post(code, 1, Body::from("replay me"), None).await,
            expected,
            "{code:?}"
        );
    }
}

#[tokio::test]
async fn http3_does_not_replay_a_streamed_body() {
    let body = Body::wrap(http_body_util::Full::new(Bytes::from_static(b"replay me")));
    assert_eq!(
        post(Code::H3_REQUEST_REJECTED, 1, body, None).await,
        (false, 1)
    );
}

#[tokio::test]
async fn http3_respects_disabled_retries_and_the_retry_limit() {
    for (rejections, retry, expected) in [
        (1, Some(Policy::never()), (false, 1)),
        (3, None, (false, 3)),
    ] {
        assert_eq!(
            post(
                Code::H3_REQUEST_REJECTED,
                rejections,
                Body::from("replay me"),
                retry
            )
            .await,
            expected
        );
    }
}

#[tokio::test]
async fn http3_goaway_replays_only_the_redirected_hop() {
    let (endpoint, cert_store) = endpoint();
    let addr = endpoint.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (first, mut server) = h3::accept(&endpoint).await;
        let (head, mut stream) = server
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        record
            .lock()
            .unwrap()
            .push(format!("{} {}", head.method(), head.uri().path()));
        while stream.recv_data().await.unwrap().is_some() {}
        let see_other = Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(LOCATION, "/next")
            .body(())
            .unwrap();
        stream.send_response(see_other).await.unwrap();
        stream.finish().await.unwrap();

        // Take the follow-up before HTTP/3 accepts it, so the GOAWAY below excludes it.
        let (mut send, mut recv) = first.accept_bi().await.unwrap();
        server.shutdown(0).await.unwrap();
        // Requests at or above the GOAWAY identifier were not processed and may be retried:
        // https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2
        let rejected = quic::VarInt::from_u64(Code::H3_REQUEST_REJECTED.value()).unwrap();
        send.reset(rejected).unwrap();
        recv.stop(rejected).unwrap();
        // A graceful shutdown keeps rejecting streams the client opens before it sees the GOAWAY.
        let drain = async {
            while let Ok(Some(_)) = server.accept().await {}
            std::future::pending::<()>().await
        };

        let retried = async {
            let (_, mut server) = h3::accept(&endpoint).await;
            let (head, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            record
                .lock()
                .unwrap()
                .push(format!("{} {}", head.method(), head.uri().path()));
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            let _ = released.await;
        };
        tokio::select! {
            () = drain => {}
            () = retried => {}
        }
    });

    let client = Client::builder_tokio()
        .no_proxy()
        .http3_only()
        .redirect(redirect::Policy::default())
        .resolve("localhost", addr)
        .tls_cert_store(cert_store)
        .build()
        .unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        client
            .post(format!("https://localhost:{}/form", addr.port()))
            .body("form")
            .send(),
    )
    .await
    .expect("the retried hop must finish within its request limit")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.uri().path(), "/next");
    // The rejected GET is replayed on a new connection; the form is submitted once.
    assert_eq!(*seen.lock().unwrap(), ["POST /form", "GET /next"]);

    let _ = release.send(());
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap();
}
