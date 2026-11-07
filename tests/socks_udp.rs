#![cfg(all(feature = "http3", feature = "socks", feature = "tokio-rt"))]

use std::{
    error::Error as StdError,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Request, Response, Version, header::PROXY_AUTHORIZATION};
use quic::crypto::rustls::QuicServerConfig;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use wreq::{
    Client, ClientBuilder, Proxy, dns,
    tls::{TlsVersion, trust::CertStore},
};

const TIMEOUT: Duration = Duration::from_secs(5);

struct Origin {
    endpoint: quic::Endpoint,
    certificate: Vec<u8>,
    requests: mpsc::UnboundedReceiver<Request<()>>,
    task: JoinHandle<()>,
}

struct SocksProxy {
    addr: SocketAddr,
    associated: mpsc::UnboundedReceiver<()>,
    closed: mpsc::UnboundedReceiver<()>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

enum Mode {
    Relay {
        origin: SocketAddr,
        remote: bool,
        address: RelayAddress,
    },
    Reject,
    Stall,
}

#[derive(Clone, Copy)]
enum RelayAddress {
    Mapped,
    Wildcard,
    Domain,
}

enum RelayLookup {
    Resolve,
    Fail,
    Pending(mpsc::UnboundedSender<oneshot::Receiver<()>>),
}

struct Resolver {
    lookups: Arc<Mutex<Vec<String>>>,
    remote: bool,
    relay: RelayLookup,
}

async fn next<T>(receiver: &mut mpsc::UnboundedReceiver<T>) -> T {
    tokio::time::timeout(TIMEOUT, receiver.recv())
        .await
        .expect("server observation timed out")
        .expect("server stopped before sending its observation")
}

fn address(bytes: &[u8]) -> (String, u16, usize) {
    let (host, end) = match bytes[0] {
        1 => (
            Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]).to_string(),
            5,
        ),
        3 => {
            let end = 2 + usize::from(bytes[1]);
            (String::from_utf8(bytes[2..end].to_vec()).unwrap(), end)
        }
        4 => (
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[1..17]).unwrap()).to_string(),
            17,
        ),
        kind => panic!("unexpected SOCKS address type: {kind}"),
    };
    (
        host,
        u16::from_be_bytes([bytes[end], bytes[end + 1]]),
        end + 2,
    )
}

/// Display messages of `error` and its sources.
fn messages(error: &(dyn StdError + 'static)) -> Vec<String> {
    std::iter::successors(Some(error), |&error| error.source())
        .map(ToString::to_string)
        .collect()
}

/// Counts ERROR events on this thread, which a current-thread test runtime drives.
fn count_errors() -> (Arc<AtomicUsize>, tracing::subscriber::DefaultGuard) {
    let errors = Arc::new(AtomicUsize::new(0));
    let counter = errors.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .with_writer(move || {
            counter.fetch_add(1, Ordering::Relaxed);
            io::sink()
        })
        .finish();
    (errors, tracing::subscriber::set_default(subscriber))
}

async fn read_address(stream: &mut TcpStream) {
    let kind = stream.read_u8().await.unwrap();
    let len = match kind {
        1 => 4,
        4 => 16,
        3 => usize::from(stream.read_u8().await.unwrap()),
        kind => panic!("unexpected ASSOCIATE address type: {kind}"),
    };
    let mut bytes = vec![0; len + 2];
    stream.read_exact(&mut bytes).await.unwrap();
}

// ===== impl Origin =====

impl Origin {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(vec!["origin.test".into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "origin.test");
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
        let endpoint = quic::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
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
                    .send_data(Bytes::from_static(b"through socks udp"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            }
        });
        Self {
            endpoint,
            certificate: certificate.der().to_vec(),
            requests,
            task,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.endpoint.local_addr().unwrap()
    }

    fn url(&self) -> String {
        format!("https://origin.test:{}/", self.addr().port())
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"done");
        self.task.abort();
    }
}

// ===== impl SocksProxy =====

impl SocksProxy {
    async fn new(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (associated_sender, associated) = mpsc::unbounded_channel();
        let (closed_sender, closed) = mpsc::unbounded_channel();
        let (shutdown, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            assert_eq!(control.read_u8().await.unwrap(), 5);
            let mut methods = vec![0; usize::from(control.read_u8().await.unwrap())];
            control.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&2));
            control.write_all(&[5, 2]).await.unwrap();
            assert_eq!(control.read_u8().await.unwrap(), 1);
            for expected in [b"user".as_slice(), b"pass".as_slice()] {
                let mut value = vec![0; usize::from(control.read_u8().await.unwrap())];
                control.read_exact(&mut value).await.unwrap();
                assert_eq!(value, expected);
            }
            if matches!(mode, Mode::Reject) {
                control.write_all(&[1, 1]).await.unwrap();
            } else {
                control.write_all(&[1, 0]).await.unwrap();
                let mut head = [0; 3];
                control.read_exact(&mut head).await.unwrap();
                assert_eq!(head, [5, 3, 0]);
                read_address(&mut control).await;
                associated_sender.send(()).unwrap();
            }

            let mut control_byte = [0];
            if let Mode::Relay {
                origin,
                remote,
                address: relay_address,
            } = mode
            {
                let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                upstream.connect(origin).await.unwrap();
                let mut reply = match relay_address {
                    RelayAddress::Mapped => {
                        // An IPv4-mapped relay still requires an IPv4 socket.
                        let mut reply = vec![5, 0, 0, 4];
                        reply.extend_from_slice(&Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets());
                        reply
                    }
                    // A wildcard BND.ADDR refers to the control connection's peer.
                    RelayAddress::Wildcard => vec![5, 0, 0, 1, 0, 0, 0, 0],
                    RelayAddress::Domain => b"\x05\x00\x00\x03\x0arelay.test".to_vec(),
                };
                reply.extend_from_slice(&relay.local_addr().unwrap().port().to_be_bytes());
                control.write_all(&reply).await.unwrap();
                let mut outbound = vec![0; 65535];
                let mut inbound = vec![0; 65535];
                let mut client = None;
                loop {
                    tokio::select! {
                        received = relay.recv_from(&mut outbound) => {
                            let (len, sender) = received.unwrap();
                            if let Some(client) = client {
                                assert_eq!(sender, client, "one association must use one UDP socket");
                            } else {
                                client = Some(sender);
                            }
                            let packet = &outbound[..len];
                            assert_eq!(&packet[..3], &[0, 0, 0]);
                            assert_eq!(packet[3], if remote { 3 } else { 1 });
                            let (host, port, len) = address(&packet[3..]);
                            assert_eq!(host, if remote { "origin.test" } else { "127.0.0.1" });
                            assert_eq!(port, origin.port());
                            upstream.send(&packet[3 + len..]).await.unwrap();
                        }
                        received = upstream.recv(&mut inbound) => {
                            let len = received.unwrap();
                            let mut packet = if matches!(relay_address, RelayAddress::Domain) {
                                b"\x00\x00\x00\x03\x0bORIGIN.TEST".to_vec()
                            } else {
                                vec![0, 0, 0, 1, 127, 0, 0, 1]
                            };
                            packet.extend_from_slice(&origin.port().to_be_bytes());
                            packet.extend_from_slice(&inbound[..len]);
                            relay.send_to(&packet, client.unwrap()).await.unwrap();
                        }
                        received = control.read(&mut control_byte) => {
                            assert_eq!(received.unwrap(), 0);
                            break;
                        }
                        _ = &mut stopped => break,
                        accepted = listener.accept() => panic!("unexpected second association: {accepted:?}"),
                    }
                }
            } else {
                assert_eq!(control.read(&mut control_byte).await.unwrap(), 0);
            }
            drop(control);
            closed_sender.send(()).unwrap();
        });
        Self {
            addr,
            associated,
            closed,
            shutdown: Some(shutdown),
            task,
        }
    }

    fn client(
        &self,
        origin: &Origin,
        remote: bool,
        lookups: Arc<Mutex<Vec<String>>>,
    ) -> ClientBuilder {
        let scheme = if remote { "socks5h" } else { "socks5" };
        Client::builder_tokio()
            .no_proxy()
            .http3_only()
            .retry(wreq::retry::Policy::never())
            .dns_resolver(Resolver {
                lookups,
                remote,
                relay: RelayLookup::Resolve,
            })
            .tls_cert_store(CertStore::from_der_certs([&origin.certificate]).unwrap())
            .proxy(
                Proxy::all(format!("{scheme}://proxy.test:{}", self.addr.port()))
                    .unwrap()
                    .basic_auth("user", "pass"),
            )
            .timeout(TIMEOUT)
    }
}

impl Drop for SocksProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ===== impl Resolver =====

impl dns::Resolve for Resolver {
    fn resolve(&self, name: dns::Name) -> dns::Resolving {
        self.lookups.lock().unwrap().push(name.as_str().to_owned());
        if name.as_str() == "relay.test" {
            return match &self.relay {
                RelayLookup::Resolve => Box::pin(async {
                    // Prefer the control peer's address family and the port from BND.PORT.
                    let addresses = ["[::1]:1".parse().unwrap(), "127.0.0.1:1".parse().unwrap()];
                    Ok(Box::new(addresses.into_iter()) as dns::Addrs)
                }),
                RelayLookup::Fail => {
                    Box::pin(async { Err(io::Error::other("relay resolution failed").into()) })
                }
                RelayLookup::Pending(sender) => {
                    let sender = sender.clone();
                    Box::pin(async move {
                        let (dropped, receiver) = oneshot::channel();
                        sender.send(receiver).unwrap();
                        let result = std::future::pending().await;
                        drop(dropped);
                        result
                    })
                }
            };
        }
        let allowed =
            name.as_str() == "proxy.test" || (!self.remote && name.as_str() == "origin.test");
        Box::pin(async move {
            if !allowed {
                return Err(io::Error::other(format!("unexpected local lookup: {name}")).into());
            }
            Ok(Box::new(std::iter::once("127.0.0.1:0".parse().unwrap())) as dns::Addrs)
        })
    }
}

#[tokio::test]
async fn socks_udp_authentication_dns_and_pool_reuse() {
    // A proxy closing the association is routine and must not be logged as an I/O error.
    let (errors, _logs) = count_errors();
    for (remote, address) in [
        (false, RelayAddress::Mapped),
        (true, RelayAddress::Wildcard),
        (true, RelayAddress::Domain),
    ] {
        let mut origin = Origin::new();
        let mut proxy = SocksProxy::new(Mode::Relay {
            origin: origin.addr(),
            remote,
            address,
        })
        .await;
        let lookups = Arc::new(Mutex::new(Vec::new()));
        let client = proxy
            .client(&origin, remote, lookups.clone())
            .build()
            .unwrap();
        for _ in 0..2 {
            let response = client.get(origin.url()).send().await.unwrap();
            assert_eq!(response.version(), Version::HTTP_3);
            assert_eq!(response.text().await.unwrap(), "through socks udp");
            let request = next(&mut origin.requests).await;
            assert_eq!(request.uri().host(), Some("origin.test"));
            assert!(!request.headers().contains_key(PROXY_AUTHORIZATION));
        }
        next(&mut proxy.associated).await;
        assert!(proxy.associated.try_recv().is_err());
        let mut actual = lookups.lock().unwrap().clone();
        actual.sort();
        assert_eq!(
            actual,
            if matches!(address, RelayAddress::Domain) {
                vec!["proxy.test", "relay.test"]
            } else if remote {
                vec!["proxy.test"]
            } else {
                vec!["origin.test", "proxy.test"]
            }
        );

        let mut request = tokio::spawn(client.post(format!("{}stall", origin.url())).send());
        let received = tokio::select! {
            received = next(&mut origin.requests) => received,
            result = &mut request => panic!("stalled request completed early: {result:?}"),
        };
        assert_eq!(received.uri().path(), "/stall");
        proxy.shutdown.take().unwrap().send(()).unwrap();
        next(&mut proxy.closed).await;
        (&mut proxy.task).await.unwrap();
        let error = request.await.unwrap().unwrap_err();
        assert!(!error.is_timeout(), "{error:?}");
    }
    assert_eq!(errors.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn socks_udp_authentication_rejection_closes_the_control_connection() {
    let origin = Origin::new();
    let mut proxy = SocksProxy::new(Mode::Reject).await;
    let error = proxy
        .client(&origin, true, Arc::default())
        .build()
        .unwrap()
        .get(origin.url())
        .send()
        .await
        .unwrap_err();
    assert!(error.is_proxy_connect() && !error.is_timeout(), "{error:?}");
    assert!(messages(&error).contains(&"SOCKS5 authentication error".into()));
    next(&mut proxy.closed).await;
    (&mut proxy.task).await.unwrap();
    assert!(proxy.associated.try_recv().is_err());
}

#[tokio::test]
async fn proxied_http3_errors_name_the_failed_stage() {
    // Nothing listens on this port, so the proxy refuses connections.
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    for scheme in ["socks5", "socks5h", "quic"] {
        let lookups = Arc::new(Mutex::new(Vec::new()));
        let client = |builder: ClientBuilder| {
            builder
                .no_proxy()
                .http3_only()
                .retry(wreq::retry::Policy::never())
                .dns_resolver(Resolver {
                    lookups: lookups.clone(),
                    remote: scheme != "socks5",
                    relay: RelayLookup::Resolve,
                })
                .proxy(Proxy::all(format!("{scheme}://proxy.test:{port}")).unwrap())
                .timeout(TIMEOUT)
                .build()
                .unwrap()
        };

        // A local configuration error the connector finds costs no proxy setup and is not a
        // proxy error. HTTP/3 requires TLS 1.3, which only the connector checks.
        let error = client(Client::builder_tokio().tls_max_version(TlsVersion::TLS_1_2))
            .get("https://origin.test/")
            .send()
            .await
            .unwrap_err();
        assert!(
            error.is_connect() && !error.is_proxy_connect(),
            "{scheme}: {error:?}"
        );
        assert!(lookups.lock().unwrap().is_empty(), "{scheme}");

        // A refused proxy is not reported as a failed target handshake.
        if scheme != "quic" {
            let error = client(Client::builder_tokio())
                .get("https://origin.test/")
                .send()
                .await
                .unwrap_err();
            let messages = messages(&error);
            assert!(error.is_proxy_connect(), "{scheme}: {error:?}");
            assert!(
                messages.contains(&"SOCKS5 proxy connect error".into()),
                "{scheme}: {messages:?}"
            );
            assert!(
                !messages.iter().any(|message| message.contains("handshake")),
                "{scheme}: {messages:?}"
            );
        }
    }
}

#[tokio::test]
async fn socks_udp_timeout_and_cancellation_close_the_control_connection() {
    let origin = Origin::new();
    for timeout in [true, false] {
        let mut proxy = SocksProxy::new(Mode::Stall).await;
        let mut builder = proxy.client(&origin, true, Arc::default());
        if timeout {
            builder = builder.connect_timeout(Duration::from_secs(1));
        }
        let client = builder.build().unwrap();
        let request = tokio::spawn(client.get(origin.url()).send());
        next(&mut proxy.associated).await;
        if timeout {
            let error = request.await.unwrap().unwrap_err();
            assert!(error.is_connect() && error.is_timeout(), "{error:?}");
        } else {
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
        }
        next(&mut proxy.closed).await;
        (&mut proxy.task).await.unwrap();
    }
}

#[tokio::test]
async fn socks_udp_relay_dns_and_control_connection_share_the_attempt_lifetime() {
    enum End {
        DnsFailure,
        Cancel,
        ControlClosed,
    }

    let origin = Origin::new();
    for end in [End::DnsFailure, End::Cancel, End::ControlClosed] {
        let mut proxy = SocksProxy::new(Mode::Relay {
            origin: origin.addr(),
            remote: true,
            address: RelayAddress::Domain,
        })
        .await;
        let lookups = Arc::new(Mutex::new(Vec::new()));
        let (sender, mut resolving) = mpsc::unbounded_channel();
        let client = proxy
            .client(&origin, true, lookups.clone())
            .dns_resolver(Resolver {
                lookups: lookups.clone(),
                remote: true,
                relay: if matches!(end, End::DnsFailure) {
                    RelayLookup::Fail
                } else {
                    RelayLookup::Pending(sender)
                },
            })
            .build()
            .unwrap();
        let request = tokio::spawn(client.get(origin.url()).send());
        if matches!(end, End::DnsFailure) {
            let error = request.await.unwrap().unwrap_err();
            assert!(error.is_proxy_connect() && !error.is_timeout(), "{error:?}");
        } else {
            let dropped = next(&mut resolving).await;
            if matches!(end, End::ControlClosed) {
                proxy.shutdown.take().unwrap().send(()).unwrap();
                let error = tokio::time::timeout(Duration::from_secs(2), request)
                    .await
                    .expect("control EOF must interrupt DNS before the request timeout")
                    .unwrap()
                    .unwrap_err();
                assert!(error.is_proxy_connect() && !error.is_timeout(), "{error:?}");
            } else {
                request.abort();
                assert!(request.await.unwrap_err().is_cancelled());
            }
            assert!(
                tokio::time::timeout(TIMEOUT, dropped)
                    .await
                    .expect("the pending DNS future was retained after the attempt ended")
                    .is_err()
            );
        }
        next(&mut proxy.closed).await;
        (&mut proxy.task).await.unwrap();
        assert_eq!(*lookups.lock().unwrap(), ["proxy.test", "relay.test"]);
    }
}
