#![cfg(all(feature = "http3", feature = "tokio-rt"))]

mod support;

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes, BytesMut};
use http::{
    HeaderMap, Method, Request, Response, StatusCode, Version, header::PROXY_AUTHORIZATION,
};
use support::h3;
use tokio::{io::AsyncReadExt, net::UdpSocket, sync::mpsc};
use wreq::{Client, ClientBuilder, Proxy, dns, tls::trust::CertStore};

const TIMEOUT: Duration = Duration::from_secs(5);
/// Has no port: CONNECT-UDP must name 443, and the relay ignores the requested target.
const ORIGIN_URL: &str = "https://origin.test/";

struct Server {
    server: h3::Server,
    certificate: h3::Certificate,
    requests: mpsc::UnboundedReceiver<Request<()>>,
}

enum Mode {
    Relay(SocketAddr, bool),
    Reject,
    Unsupported,
    Stall,
}

struct ProxyResolver(SocketAddr);

async fn next<T>(receiver: &mut mpsc::UnboundedReceiver<T>) -> T {
    tokio::time::timeout(TIMEOUT, receiver.recv())
        .await
        .expect("server observation timed out")
        .expect("server stopped before sending its observation")
}

fn varint(bytes: &mut &[u8]) -> Option<u64> {
    let first = *bytes.first()?;
    let encoded = bytes.get(..1 << (first >> 6))?;
    let mut value = u64::from(first & 0x3f);
    for byte in &encoded[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *bytes = &bytes[encoded.len()..];
    Some(value)
}

fn encode_varint(value: u64, output: &mut BytesMut) {
    let (len, tag) = match value {
        0..64 => (1, 0),
        64..16384 => (2, 1 << 14),
        16384..1073741824 => (4, 2 << 30),
        _ => (8, 3 << 62),
    };
    output.extend_from_slice(&(value | tag).to_be_bytes()[8 - len..]);
}

fn capsule(buffer: &mut BytesMut) -> Option<(u64, Bytes)> {
    let mut remaining = &buffer[..];
    let kind = varint(&mut remaining)?;
    let len = usize::try_from(varint(&mut remaining)?).unwrap();
    if remaining.len() < len {
        return None;
    }
    let header = buffer.len() - remaining.len();
    buffer.advance(header);
    Some((kind, buffer.split_to(len).freeze()))
}

// ===== impl Server =====

impl Server {
    fn origin() -> Self {
        let certificate = h3::Certificate::new("origin.test");
        let (sender, requests) = mpsc::unbounded_channel();
        let endpoint = h3::endpoint(&certificate, None);
        let server = h3::Server::serve(endpoint, false, move |request, mut stream| {
            let sender = sender.clone();
            async move {
                let stall = request.uri().path() == "/stall";
                sender.send(request).unwrap();
                if stall {
                    std::future::pending::<()>().await;
                }
                stream.send_response(Response::new(())).await.unwrap();
                stream
                    .send_data(Bytes::from_static(b"origin"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            }
        });
        Self {
            server,
            certificate,
            requests,
        }
    }

    fn proxy(mode: Mode) -> (Self, mpsc::UnboundedReceiver<()>) {
        let certificate = h3::Certificate::new("proxy.test");
        let endpoint = h3::endpoint(&certificate, None);
        let incoming = endpoint.clone();
        let (sender, requests) = mpsc::unbounded_channel();
        let (closed, receiver) = mpsc::unbounded_channel();
        let server = h3::Server::spawn(endpoint, async move {
            let connection = incoming.accept().await.unwrap().await.unwrap();
            let mut server = http3::server::builder()
                .enable_extended_connect(!matches!(mode, Mode::Unsupported))
                .enable_datagram(!matches!(mode, Mode::Relay(_, false)))
                .build::<_, Bytes>(http3_quic::Connection::new(connection.clone()))
                .await
                .unwrap();

            let mut request = tokio::select! {
                request = server.accept() => match request {
                    Ok(Some(request)) => Some(request.resolve_request().await.unwrap()),
                    _ => None,
                },
                _ = connection.closed() => None,
            };

            if let Some((request, mut stream)) = request.take() {
                assert!(!matches!(mode, Mode::Unsupported));
                let quarter_stream_id = stream.id().index();
                sender.send(request).unwrap();
                match mode {
                    Mode::Relay(origin, datagrams) => {
                        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                        udp.connect(origin).await.unwrap();
                        stream
                            .send_response(
                                Response::builder()
                                    .header("capsule-protocol", "?1")
                                    .body(())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        let mut buffer = vec![0u8; 65535];
                        let mut prefix = Bytes::new();
                        let mut capsules = BytesMut::new();
                        let mut injected_empty = false;
                        loop {
                            tokio::select! {
                                datagram = connection.read_datagram() => {
                                    let Ok(datagram) = datagram else { break };
                                    assert!(datagrams);
                                    let mut payload = &datagram[..];
                                    assert_eq!(varint(&mut payload), Some(quarter_stream_id));
                                    assert_eq!(varint(&mut payload), Some(0));
                                    prefix = datagram.slice(..datagram.len() - payload.len());
                                    if !injected_empty {
                                        connection.send_datagram(prefix.clone()).unwrap();
                                        injected_empty = true;
                                    }
                                    udp.send(payload).await.unwrap();
                                }
                                received = udp.recv(&mut buffer) => {
                                    let len = received.unwrap();
                                    let mut datagram = BytesMut::with_capacity(prefix.len() + len);
                                    if datagrams {
                                        datagram.extend_from_slice(&prefix);
                                    } else {
                                        encode_varint(0, &mut datagram);
                                        encode_varint((len + 1) as u64, &mut datagram);
                                        encode_varint(0, &mut datagram);
                                    }
                                    datagram.extend_from_slice(&buffer[..len]);
                                    if datagrams {
                                        // Drop oversized target packets, including MTU probes.
                                        // https://www.rfc-editor.org/rfc/rfc9298.html#section-6.1
                                        match connection.send_datagram(datagram.freeze()) {
                                            Ok(()) | Err(quic::SendDatagramError::TooLarge) => {}
                                            Err(_) => break,
                                        }
                                    } else if stream.send_data(datagram.freeze()).await.is_err() {
                                        break;
                                    }
                                }
                                data = stream.recv_data() => {
                                    let Ok(Some(mut data)) = data else { break };
                                    capsules.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                                    while let Some((kind, payload)) = capsule(&mut capsules) {
                                        if kind == 0 {
                                            assert!(!datagrams);
                                            let mut payload = &payload[..];
                                            assert_eq!(varint(&mut payload), Some(0));
                                            if !injected_empty {
                                                stream.send_data(Bytes::from_static(&[0, 1, 0])).await.unwrap();
                                                injected_empty = true;
                                            }
                                            udp.send(payload).await.unwrap();
                                        }
                                    }
                                }
                                request = server.accept() => {
                                    assert!(!matches!(request, Ok(Some(_))), "unexpected second tunnel");
                                    break;
                                }
                            }
                        }
                    }
                    Mode::Reject => {
                        stream
                            .send_response(
                                Response::builder()
                                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                                    .body(())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        stream.finish().await.unwrap();
                    }
                    Mode::Stall => {
                        tokio::select! {
                            _ = stream.recv_data() => {}
                            _ = server.accept() => {}
                            _ = connection.closed() => {}
                        }
                    }
                    Mode::Unsupported => unreachable!(),
                }
            }
            connection.closed().await;
            let _ = closed.send(());
        });
        (
            Self {
                server,
                certificate,
                requests,
            },
            receiver,
        )
    }

    fn addr(&self) -> SocketAddr {
        self.server.addr()
    }

    fn client(&self, origin: &Self, password: &str) -> ClientBuilder {
        let mut headers = HeaderMap::new();
        headers.insert("x-proxy-only", "secret".parse().unwrap());
        Client::builder_tokio()
            .no_proxy()
            .http3_only()
            .retry(wreq::retry::Policy::never())
            .dns_resolver(ProxyResolver(self.addr()))
            .tls_cert_store(
                CertStore::from_der_certs([self.certificate.der(), origin.certificate.der()])
                    .unwrap(),
            )
            .proxy(
                Proxy::all(format!("QuIc://proxy.test:{}", self.addr().port()))
                    .unwrap()
                    .basic_auth("user", password)
                    .custom_http_headers(headers),
            )
            .timeout(TIMEOUT)
    }
}

// ===== impl ProxyResolver =====

impl dns::Resolve for ProxyResolver {
    fn resolve(&self, name: dns::Name) -> dns::Resolving {
        let addr = self.0;
        Box::pin(async move {
            if name.as_str() != "proxy.test" {
                return Err(io::Error::other(format!("unexpected local lookup: {name}")).into());
            }
            Ok(Box::new(std::iter::once(addr)) as dns::Addrs)
        })
    }
}

#[tokio::test]
async fn masque_authentication_remote_dns_and_pool_reuse() {
    // A proxy ending the tunnel is routine and must not be logged as an I/O error. The test
    // runtime drives every task on this thread.
    let errors = Arc::new(AtomicUsize::new(0));
    let counter = errors.clone();
    let _logs = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(move || {
                counter.fetch_add(1, Ordering::Relaxed);
                io::sink()
            })
            .finish(),
    );
    for datagrams in [true, false] {
        let mut origin = Server::origin();
        let (mut proxy, mut closed) = Server::proxy(Mode::Relay(origin.addr(), datagrams));
        let client = proxy.client(&origin, "pass").build().unwrap();
        for _ in 0..2 {
            let response = client.get(ORIGIN_URL).send().await.unwrap();
            assert_eq!(response.version(), Version::HTTP_3);
            assert_eq!(response.text().await.unwrap(), "origin");
            let request = next(&mut origin.requests).await;
            assert_eq!(request.uri().host(), Some("origin.test"));
            assert!(!request.headers().contains_key(PROXY_AUTHORIZATION));
            assert!(!request.headers().contains_key("x-proxy-only"));
        }
        assert_eq!(origin.server.connections(), 1);
        let request = next(&mut proxy.requests).await;
        assert_eq!(request.method(), "CONNECT");
        assert_eq!(
            request.extensions().get::<http3::ext::Protocol>(),
            Some(&http3::ext::Protocol::CONNECT_UDP)
        );
        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(request.uri().host(), Some("proxy.test"));
        assert_eq!(
            request.uri().path(),
            "/.well-known/masque/udp/origin.test/443/"
        );
        assert_eq!(request.headers()[PROXY_AUTHORIZATION], "Basic dXNlcjpwYXNz");
        assert_eq!(request.headers()["x-proxy-only"], "secret");
        assert!(proxy.requests.try_recv().is_err());

        let mut request = tokio::spawn(client.post(format!("{ORIGIN_URL}stall")).send());
        let received = tokio::select! {
            received = next(&mut origin.requests) => received,
            result = &mut request => panic!("stalled request completed early (datagrams={datagrams}): {result:?}"),
        };
        assert_eq!(received.uri().path(), "/stall");
        proxy
            .server
            .endpoint()
            .close(0u32.into(), b"proxy shutdown");
        next(&mut closed).await;
        let error = request.await.unwrap().unwrap_err();
        assert!(!error.is_timeout(), "{error:?}");
    }
    assert_eq!(errors.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn masque_rejects_authentication_and_missing_extended_connect() {
    let origin = Server::origin();
    for mode in [Mode::Reject, Mode::Unsupported] {
        let unsupported = matches!(mode, Mode::Unsupported);
        let (mut proxy, mut closed) = Server::proxy(mode);
        let error = proxy
            .client(&origin, "wrong")
            .build()
            .unwrap()
            .get(ORIGIN_URL)
            .send()
            .await
            .unwrap_err();
        assert!(error.is_proxy_connect() && !error.is_timeout(), "{error:?}");
        if unsupported {
            assert!(proxy.requests.try_recv().is_err());
        } else {
            let request = next(&mut proxy.requests).await;
            assert_eq!(
                request.headers()[PROXY_AUTHORIZATION],
                "Basic dXNlcjp3cm9uZw=="
            );
        }
        next(&mut closed).await;
    }
}

#[tokio::test]
async fn masque_connect_timeout_and_cancellation_close_the_proxy_connection() {
    let origin = Server::origin();
    for timeout in [true, false] {
        let (mut proxy, mut closed) = Server::proxy(Mode::Stall);
        let mut builder = proxy.client(&origin, "pass");
        if timeout {
            builder = builder.connect_timeout(Duration::from_secs(1));
        }
        let client = builder.build().unwrap();
        let request = tokio::spawn(client.get(ORIGIN_URL).send());
        next(&mut proxy.requests).await;
        if timeout {
            let error = request.await.unwrap().unwrap_err();
            assert!(error.is_connect() && error.is_timeout(), "{error:?}");
        } else {
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
        }
        next(&mut closed).await;
    }
}

#[tokio::test]
async fn connect_sends_only_the_marker_of_the_connection_protocol() {
    for extended in [true, false] {
        let certificate = h3::Certificate::new("localhost");
        let (sender, mut requests) = mpsc::unbounded_channel();
        let endpoint = h3::endpoint(&certificate, None);
        let server = h3::Server::serve(endpoint, extended, move |request, mut stream| {
            let sender = sender.clone();
            async move {
                sender.send(request).unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                let _ = stream.finish().await;
            }
        });
        let port = server.addr().port();
        let client = Client::builder_tokio()
            .no_proxy()
            .http3_only()
            .tls_cert_store(certificate.cert_store())
            .timeout(TIMEOUT)
            .build()
            .unwrap();
        let connect = |path: &str| {
            client
                .request(Method::CONNECT, format!("https://localhost:{port}{path}"))
                .build()
                .unwrap()
        };

        // HTTP/3 ignores the HTTP/2 marker, which would leave an ordinary CONNECT.
        #[cfg(feature = "http2")]
        {
            let mut request = connect("/h2");
            request
                .extensions_mut()
                .insert(http2::ext::Protocol::from_static("websocket"));
            let error = client.execute(request).await.unwrap_err();
            assert!(
                format!("{error:?}").contains("does not match the connection's HTTP version"),
                "{error:?}"
            );
        }

        // Without a marker, HTTP/3 sends an ordinary CONNECT naming only the authority.
        assert_eq!(
            client.execute(connect("/")).await.unwrap().status(),
            StatusCode::OK
        );
        let request = next(&mut requests).await;
        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(
            request.uri().authority().unwrap().as_str(),
            format!("localhost:{port}")
        );
        assert!(request.extensions().get::<http3::ext::Protocol>().is_none());

        let mut request = connect("/chat");
        request
            .extensions_mut()
            .insert(wreq::http3::Protocol::WEBSOCKET);
        let result = client.execute(request).await;
        if extended {
            assert_eq!(result.unwrap().status(), StatusCode::OK);
            let request = next(&mut requests).await;
            assert_eq!(request.uri().path(), "/chat");
            assert_eq!(
                request.extensions().get::<http3::ext::Protocol>(),
                Some(&http3::ext::Protocol::WEBSOCKET)
            );
        } else {
            let error = result.unwrap_err();
            assert!(
                format!("{error:?}").contains("peer did not enable extended CONNECT"),
                "{error:?}"
            );
        }
        drop(client);
        drop(server);
    }

    // HTTP/1 has no extended CONNECT, so the HTTP/3 marker fails before any byte is sent.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.read(&mut [0; 1]).await.unwrap_or_default()
    });
    let client = Client::builder_tokio()
        .no_proxy()
        .timeout(TIMEOUT)
        .build()
        .unwrap();
    let mut request = client
        .request(Method::CONNECT, format!("http://{addr}/chat"))
        .build()
        .unwrap();
    request
        .extensions_mut()
        .insert(wreq::http3::Protocol::WEBSOCKET);
    let error = client.execute(request).await.unwrap_err();
    assert!(
        format!("{error:?}").contains("does not match the connection's HTTP version"),
        "{error:?}"
    );
    drop(client);
    assert_eq!(
        tokio::time::timeout(TIMEOUT, accepted)
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
