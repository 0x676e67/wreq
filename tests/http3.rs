#![cfg(all(feature = "http3", feature = "tokio-rt"))]

mod support;

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use futures_util::future::join_all;
use http::{Response, StatusCode, Version};
use support::h3;
use tokio::{
    sync::{Notify, mpsc},
    task::JoinSet,
};
use wreq::{
    Client, ClientBuilder, Emulation,
    http3::{Http3Options, PseudoId, PseudoOrder, SettingId, SettingsOrder},
    tls::TlsInfo,
};

const TIMEOUT: Duration = Duration::from_secs(10);

/// What one client connection sent: its SETTINGS and its first request's pseudo-header order.
struct Fingerprint {
    settings: Vec<(u64, u64)>,
    pseudo_order: Vec<String>,
}

/// Answers every request with `ok`.
fn ok_server(certificate: &h3::Certificate) -> h3::Server {
    h3::Server::serve(
        h3::endpoint(certificate, None),
        false,
        |_, mut stream| async move {
            stream.send_response(Response::new(())).await.unwrap();
            stream.send_data(Bytes::from_static(b"ok")).await.unwrap();
            stream.finish().await.unwrap();
        },
    )
}

/// An HTTP/3-only client trusting `certificate` that resolves `localhost` to `server`.
fn client(server: &h3::Server, certificate: &h3::Certificate) -> ClientBuilder {
    Client::builder_tokio()
        .no_proxy()
        .http3_only()
        .resolve("localhost", server.addr())
        .tls_cert_store(certificate.cert_store())
        .timeout(TIMEOUT)
}

fn url(server: &h3::Server) -> String {
    format!("https://localhost:{}/", server.addr().port())
}

fn varint(bytes: &mut &[u8]) -> u64 {
    let len = 1 << (bytes[0] >> 6);
    let (encoded, rest) = bytes.split_at(len);
    *bytes = rest;
    encoded[1..]
        .iter()
        .fold(u64::from(encoded[0] & 0x3f), |value, &byte| {
            (value << 8) | u64::from(byte)
        })
}

async fn read_varint(stream: &mut quic::RecvStream) -> u64 {
    let mut bytes = [0; 8];
    stream.read_exact(&mut bytes[..1]).await.unwrap();
    let len = 1 << (bytes[0] >> 6);
    stream.read_exact(&mut bytes[1..len]).await.unwrap();
    varint(&mut &bytes[..len])
}

/// Reads one frame ([RFC 9114 Section 7.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1)).
async fn read_frame(stream: &mut quic::RecvStream) -> (u64, Vec<u8>) {
    let kind = read_varint(stream).await;
    let mut payload = vec![0; usize::try_from(read_varint(stream).await).unwrap()];
    stream.read_exact(&mut payload).await.unwrap();
    (kind, payload)
}

/// Records the SETTINGS and the request pseudo-header order each client connection sends, then
/// answers its first request with an empty `200` response.
fn observer(certificate: &h3::Certificate) -> (h3::Server, mpsc::UnboundedReceiver<Fingerprint>) {
    let endpoint = h3::endpoint(certificate, None);
    let incoming = endpoint.clone();
    let (sender, observed) = mpsc::unbounded_channel();
    let server = h3::Server::spawn(endpoint, async move {
        let mut connections = JoinSet::new();
        while let Some(connecting) = incoming.accept().await {
            let sender = sender.clone();
            connections.spawn(async move {
                let connection = connecting.await.unwrap();
                // A control stream opens with SETTINGS, here empty
                // (https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1).
                let mut control = connection.open_uni().await.unwrap();
                control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();

                // Closing the client's control or QPACK streams would fail the connection.
                let mut qpack = Vec::new();
                let mut client_control = loop {
                    let mut stream = connection.accept_uni().await.unwrap();
                    if read_varint(&mut stream).await == 0x00 {
                        break stream;
                    }
                    qpack.push(stream);
                };
                let (frame, payload) = read_frame(&mut client_control).await;
                assert_eq!(frame, 0x04, "SETTINGS must come first");
                let mut payload = payload.as_slice();
                let mut settings = Vec::new();
                while !payload.is_empty() {
                    settings.push((varint(&mut payload), varint(&mut payload)));
                }

                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let (frame, payload) = read_frame(&mut recv).await;
                assert_eq!(frame, 0x01, "HEADERS must come first");
                let pseudo_order =
                    http3::qpack::decode_stateless(&mut payload.as_slice(), u64::MAX)
                        .unwrap()
                        .fields
                        .into_iter()
                        .map(|field| String::from_utf8(field.name.into_owned()).unwrap())
                        .filter(|name| name.starts_with(':'))
                        .collect();
                sender
                    .send(Fingerprint {
                        settings,
                        pseudo_order,
                    })
                    .unwrap();
                // HEADERS with a field section of Required Insert Count 0, Base 0 and static
                // entry 25, `:status: 200`
                // (https://www.rfc-editor.org/rfc/rfc9204.html#appendix-A).
                send.write_all(&[0x01, 0x03, 0x00, 0x00, 0xd9])
                    .await
                    .unwrap();
                send.finish().unwrap();
                connection.closed().await;
            });
        }
    });
    (server, observed)
}

#[tokio::test]
async fn http3_requests_share_one_connection() {
    let certificate = h3::Certificate::new("localhost");
    let server = ok_server(&certificate);
    let client = client(&server, &certificate)
        .tls_info(true)
        .build()
        .unwrap();
    let url = url(&server);
    let check = async |response: wreq::Response| {
        assert_eq!(response.version(), Version::HTTP_3);
        // Reused connections report TLS details too.
        let info = response.extensions().get::<TlsInfo>().unwrap();
        assert_eq!(info.peer_certificate(), Some(certificate.der()));
        assert_eq!(response.text().await.unwrap(), "ok");
    };

    // Concurrent checkouts join the connection still being made.
    for response in join_all((0..10).map(|_| client.get(&url).send())).await {
        check(response.unwrap()).await;
    }
    for _ in 0..3 {
        check(client.get(&url).send().await.unwrap()).await;
    }
    assert_eq!(server.connections(), 1);

    // A poisoned connection is not reused; the next request dials a new one.
    let response = client.get(&url).send().await.unwrap();
    response.forbid_recycle();
    check(response).await;
    check(client.get(&url).send().await.unwrap()).await;
    assert_eq!(server.connections(), 2);
}

#[tokio::test]
async fn http3_redials_after_the_idle_timeout() {
    let certificate = h3::Certificate::new("localhost");
    let server = ok_server(&certificate);
    let client = client(&server, &certificate)
        .pool_idle_timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    let url = url(&server);
    for (pause, expected) in [
        (Duration::ZERO, 1),
        (Duration::ZERO, 1),
        (Duration::from_millis(500), 2),
    ] {
        tokio::time::sleep(pause).await;
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.text().await.unwrap(), "ok");
        assert_eq!(server.connections(), expected);
    }
}

#[tokio::test]
async fn http3_keeps_a_connection_with_a_live_body_past_the_idle_timeout() {
    let certificate = h3::Certificate::new("localhost");
    let release = Arc::new(Notify::new());
    let server = h3::Server::serve(h3::endpoint(&certificate, None), false, {
        let release = release.clone();
        move |request, mut stream| {
            let release = release.clone();
            async move {
                stream.send_response(Response::new(())).await.unwrap();
                if request.uri().path() == "/slow" {
                    release.notified().await;
                }
                stream.send_data(Bytes::from_static(b"ok")).await.unwrap();
                stream.finish().await.unwrap();
            }
        }
    });
    let client = client(&server, &certificate)
        .pool_idle_timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    let url = url(&server);
    let get = async || client.get(&url).send().await.unwrap().text().await.unwrap();

    // A body outliving the idle timeout and a sweep keeps its connection reusable.
    let slow = client.get(format!("{url}slow")).send().await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(get().await, "ok");
    assert_eq!(server.connections(), 1);

    // Once the body ends, the connection idles out again.
    release.notify_one();
    assert_eq!(slow.text().await.unwrap(), "ok");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(get().await, "ok");
    assert_eq!(server.connections(), 2);
}

#[tokio::test]
async fn http3_completes_concurrent_requests_whose_bodies_are_read_later() {
    // More requests than the default admission limit of 128: a response whose head arrived must
    // not hold a slot while its body waits, and the limit must not open more connections
    // (https://www.rfc-editor.org/rfc/rfc9114.html#section-3.3).
    let certificate = h3::Certificate::new("localhost");
    let server = ok_server(&certificate);
    let client = client(&server, &certificate).build().unwrap();
    let url = url(&server);
    let responses =
        tokio::time::timeout(TIMEOUT, join_all((0..200).map(|_| client.get(&url).send())))
            .await
            .expect("every response head must arrive while earlier bodies are unread");
    for response in responses {
        assert_eq!(response.unwrap().text().await.unwrap(), "ok");
    }
    assert_eq!(server.connections(), 1);
}

#[tokio::test]
async fn http3_options_reach_the_server_from_every_source() {
    let options = Http3Options::builder()
        .send_grease(false)
        .max_field_section_size(32100)
        .qpack_blocked_streams(Some(0))
        .headers_pseudo_order(
            PseudoOrder::builder()
                .extend([
                    PseudoId::Path,
                    PseudoId::Authority,
                    PseudoId::Method,
                    PseudoId::Scheme,
                ])
                .build(),
        )
        .settings_order(
            SettingsOrder::builder()
                .extend([
                    SettingId::QPACK_MAX_BLOCKED_STREAMS,
                    SettingId::MAX_HEADER_LIST_SIZE,
                    SettingId::QPACK_MAX_TABLE_CAPACITY,
                ])
                .build(),
        )
        .build();
    let certificate = h3::Certificate::new("localhost");
    let (server, mut observed) = observer(&certificate);
    let url = url(&server);
    let emulation = Emulation::builder().config(options.clone()).build();

    for source in ["client", "emulation", "request"] {
        let builder = client(&server, &certificate);
        let builder = match source {
            "client" => builder.http3_options(options.clone()),
            "emulation" => builder.emulation(emulation.clone()),
            _ => builder,
        };
        let mut request = builder.build().unwrap().get(&url);
        if source == "request" {
            request = request.emulation(options.clone());
        }
        assert_eq!(request.send().await.unwrap().status(), StatusCode::OK);
        let fingerprint = tokio::time::timeout(TIMEOUT, observed.recv())
            .await
            .unwrap()
            .unwrap();
        // The unconfigured table capacity is left out.
        assert_eq!(fingerprint.settings, [(0x07, 0), (0x06, 32100)], "{source}");
        assert_eq!(
            fingerprint.pseudo_order,
            [":path", ":authority", ":method", ":scheme"],
            "{source}"
        );
    }
}
