#![cfg(all(feature = "http3", feature = "tokio-rt"))]

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, Request, Response, StatusCode, Version, header::PROXY_AUTHORIZATION};
use quic::crypto::rustls::QuicServerConfig;
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle};
use wreq::{Client, ClientBuilder, Proxy, dns, tls::trust::CertStore};

const TIMEOUT: Duration = Duration::from_secs(5);

struct Server {
    endpoint: quic::Endpoint,
    certificate: Vec<u8>,
    task: JoinHandle<()>,
    requests: mpsc::UnboundedReceiver<Request<()>>,
}

enum Mode {
    Relay(SocketAddr, bool),
    Reject,
    Unsupported,
    Stall,
}

struct ProxyResolver(SocketAddr);

fn endpoint(host: &str) -> (quic::Endpoint, Vec<u8>) {
    let mut params = rcgen::CertificateParams::new(vec![host.into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host);
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config =
        quic::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    (
        quic::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap(),
        certificate.der().to_vec(),
    )
}

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
        let (endpoint, certificate) = endpoint("origin.test");
        let incoming = endpoint.clone();
        let (sender, requests) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let connection = incoming.accept().await.unwrap().await.unwrap();
            let mut server = http3::server::builder()
                .build::<_, Bytes>(http3_quic::Connection::new(connection))
                .await
                .unwrap();
            while let Ok(Some(request)) = server.accept().await {
                let (request, mut stream) = request.resolve_request().await.unwrap();
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
            endpoint,
            certificate,
            task,
            requests,
        }
    }

    fn proxy(mode: Mode) -> (Self, mpsc::UnboundedReceiver<()>) {
        let (endpoint, certificate) = endpoint("proxy.test");
        let incoming = endpoint.clone();
        let (sender, requests) = mpsc::unbounded_channel();
        let (closed, receiver) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
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
                endpoint,
                certificate,
                task,
                requests,
            },
            receiver,
        )
    }

    fn addr(&self) -> SocketAddr {
        self.endpoint.local_addr().unwrap()
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
                CertStore::from_der_certs([&self.certificate, &origin.certificate]).unwrap(),
            )
            .proxy(
                Proxy::all(format!("QuIc://proxy.test:{}", self.addr().port()))
                    .unwrap()
                    .basic_auth("user", password)
                    .custom_http_headers(headers),
            )
            .timeout(TIMEOUT)
    }

    fn url(&self) -> String {
        format!("https://origin.test:{}/", self.addr().port())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"done");
        self.task.abort();
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
    for datagrams in [true, false] {
        let mut origin = Server::origin();
        let (mut proxy, mut closed) = Server::proxy(Mode::Relay(origin.addr(), datagrams));
        let client = proxy.client(&origin, "pass").build().unwrap();
        for _ in 0..2 {
            let response = client.get(origin.url()).send().await.unwrap();
            assert_eq!(response.version(), Version::HTTP_3);
            assert_eq!(response.text().await.unwrap(), "origin");
            let request = next(&mut origin.requests).await;
            assert_eq!(request.uri().host(), Some("origin.test"));
            assert!(!request.headers().contains_key(PROXY_AUTHORIZATION));
            assert!(!request.headers().contains_key("x-proxy-only"));
        }
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
            format!(
                "/.well-known/masque/udp/origin.test/{}/",
                origin.addr().port()
            )
        );
        assert_eq!(request.headers()[PROXY_AUTHORIZATION], "Basic dXNlcjpwYXNz");
        assert_eq!(request.headers()["x-proxy-only"], "secret");
        assert!(proxy.requests.try_recv().is_err());

        let mut request = tokio::spawn(client.post(format!("{}stall", origin.url())).send());
        let received = tokio::select! {
            received = next(&mut origin.requests) => received,
            result = &mut request => panic!("stalled request completed early (datagrams={datagrams}): {result:?}"),
        };
        assert_eq!(received.uri().path(), "/stall");
        proxy.endpoint.close(0u32.into(), b"proxy shutdown");
        next(&mut closed).await;
        let error = request.await.unwrap().unwrap_err();
        assert!(!error.is_timeout(), "{error:?}");
    }
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
            .get(origin.url())
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
        let request = tokio::spawn(client.get(origin.url()).send());
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
