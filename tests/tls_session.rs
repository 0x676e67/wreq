#![cfg(feature = "tokio-rt")]

use std::{
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use btls::{
    pkey::PKey,
    ssl::{ExtensionType, Ssl, SslAcceptor, SslAcceptorBuilder, SslMethod, SslVersion},
    x509::X509,
};
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_btls::SslStream;
#[cfg(target_os = "linux")]
use wreq::dns::{Addrs, Name, Resolve, Resolving};
use wreq::{
    Client, ClientBuilder, RequestBuilder,
    tls::{
        AlpnProtocol, AlpsProtocol, Tls13Cipher, TlsOptions, TlsVersion,
        session::{Key, LruTlsSessionStore, TlsSession, TlsSessionStore},
        trust::CertStore,
    },
};

/// Deliberately ignores lookup keys to exercise the outer session validation.
/// Stores one ticket across clients so a foreign ticket can be returned.
/// The test consumes that ticket rather than keeping additional clones.
#[derive(Default)]
struct UnscopedSessionStore(Mutex<Option<TlsSession>>);

impl TlsSessionStore for UnscopedSessionStore {
    fn put(&self, _key: Key, session: TlsSession) {
        *self.0.lock().unwrap() = Some(session);
    }

    fn pop(&self, _key: &Key) -> Option<TlsSession> {
        self.0.lock().unwrap().take()
    }
}

/// Fails while receiving a new session from the native handshake callback.
/// Exercises the boundary that prevents Rust unwind from entering BoringSSL.
/// Stores no ticket, so requests must complete without resumption.
struct PanickingSessionStore;

impl TlsSessionStore for PanickingSessionStore {
    fn put(&self, _key: Key, _session: TlsSession) {
        panic!("session callback panic");
    }

    fn pop(&self, _key: &Key) -> Option<TlsSession> {
        None
    }
}

const TEST_IDENTITY: (&[u8], &[u8]) = (
    include_bytes!("support/server.cert"),
    include_bytes!("support/server.key"),
);
// Issued by LOCALHOST_CA for localhost and 127.0.0.1, and usable for RSA key exchange.
const LOCALHOST_IDENTITY: (&[u8], &[u8]) = (
    include_bytes!("support/localhost.cert"),
    include_bytes!("support/localhost.key"),
);
const LOCALHOST_CA: &[u8] = include_bytes!("support/localhost-ca.cert");

/// Builds an acceptor for a DER certificate and key that negotiates at most `max_version`.
fn acceptor(
    (certificate, private_key): (&[u8], &[u8]),
    max_version: SslVersion,
) -> SslAcceptorBuilder {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    let certificate = X509::from_der(certificate).unwrap();
    let private_key = PKey::private_key_from_der(private_key).unwrap();
    acceptor.set_certificate(&certificate).unwrap();
    acceptor.set_private_key(&private_key).unwrap();
    acceptor.set_max_proto_version(Some(max_version)).unwrap();
    acceptor
}

/// Serves one HTTP/1.1 request over TLS and reports whether the handshake resumed.
async fn serve_once(acceptor: &SslAcceptor, listener: &TcpListener) -> bool {
    let (socket, _) = listener.accept().await.unwrap();
    let ssl = Ssl::new(acceptor.context()).unwrap();
    let mut stream = SslStream::new(ssl, socket).unwrap();
    Pin::new(&mut stream).accept().await.unwrap();
    let resumed = stream.ssl().session_reused();

    let service = service_fn(|_| async {
        Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from_static(b"ok"))))
    });
    hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .serve_connection(TokioIo::new(stream), service)
        .await
        .unwrap();
    resumed
}

/// Serves `connections` requests on one listener and reports, for each, whether it resumed.
async fn serve(acceptor: SslAcceptor, connections: usize) -> (SocketAddr, JoinHandle<Vec<bool>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut resumed = Vec::with_capacity(connections);
        for _ in 0..connections {
            resumed.push(serve_once(&acceptor, &listener).await);
        }
        resumed
    });
    (addr, server)
}

/// Serves `connections` TLS 1.3 requests and returns their URL.
async fn serve_resumed(connections: usize) -> (String, JoinHandle<Vec<bool>>) {
    let (addr, server) = serve(
        acceptor(TEST_IDENTITY, SslVersion::TLS1_3).build(),
        connections,
    )
    .await;
    (format!("https://{addr}/"), server)
}

/// Like [`serve_resumed`], also reporting whether each ClientHello carried `session_ticket`.
async fn serve_tickets(
    identity: (&[u8], &[u8]),
    max_version: SslVersion,
    connections: usize,
) -> (String, JoinHandle<Vec<(bool, bool)>>) {
    let tickets = Arc::new(Mutex::new(Vec::new()));
    let mut acceptor = acceptor(identity, max_version);
    let offered = tickets.clone();
    acceptor.set_select_certificate_callback(move |hello| {
        let ticket = hello.get_extension(ExtensionType::SESSION_TICKET).is_some();
        offered.lock().unwrap().push(ticket);
        Ok(())
    });
    let (addr, server) = serve(acceptor.build(), connections).await;
    let server = tokio::spawn(async move {
        let resumed = server.await.unwrap();
        let tickets = std::mem::take(&mut *tickets.lock().unwrap());
        resumed.into_iter().zip(tickets).collect()
    });
    (format!("https://{addr}/"), server)
}

/// A client opening one connection per request, without verifying the test certificate.
fn client_builder() -> ClientBuilder {
    Client::builder_tokio()
        .no_proxy()
        .http1_only()
        .pool_max_idle_per_host(0)
        .tls_cert_verification(false)
        .timeout(Duration::from_secs(5))
}

fn psk() -> TlsOptions {
    TlsOptions::builder().pre_shared_key(true).build()
}

fn tls13() -> wreq::tls::TlsOptionsBuilder {
    TlsOptions::builder()
        .min_tls_version(TlsVersion::TLS_1_3)
        .max_tls_version(TlsVersion::TLS_1_3)
        .pre_shared_key(true)
}

async fn get(request: RequestBuilder) {
    let response = request.send().await.unwrap();
    assert_eq!(response.bytes().await.unwrap(), "ok");
}

async fn finish<T>(server: JoinHandle<T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn tls13_tickets_stay_in_their_client_with_a_shared_store() {
    // Both stores are shared by two clients; the second store even ignores lookup keys.
    let lru: Arc<dyn TlsSessionStore> = Arc::new(LruTlsSessionStore::new(2));
    let unscoped: Arc<dyn TlsSessionStore> = Arc::new(UnscopedSessionStore::default());
    for store in [lru, unscoped] {
        let (url, server) = serve_resumed(4).await;
        for _ in 0..2 {
            let client = client_builder()
                .tls_session_store(store.clone())
                .build()
                .unwrap();
            // Without client TLS options, each fresh connection rebuilds the request context.
            // Tickets must still resume within this client and remain isolated from the next.
            for _ in 0..2 {
                get(client.get(&url).emulation(tls13().build())).await;
            }
        }
        assert_eq!(finish(server).await, [false, true, false, true]);
    }
}

#[tokio::test]
async fn tls13_tickets_survive_a_panicking_store() {
    let (url, server) = serve_resumed(2).await;
    let client = client_builder()
        .tls_session_store(Arc::new(PanickingSessionStore))
        .build()
        .unwrap();
    for _ in 0..2 {
        get(client.get(&url).emulation(tls13().build())).await;
    }
    assert_eq!(finish(server).await, [false, false]);
}

#[tokio::test]
async fn tls13_tickets_resume_across_alpn_and_alps_offers() {
    // An automatic client offers [h2, http/1.1]; a forced HTTP/1.1 request offers only
    // http/1.1 and must still resume the earlier ticket, as WebSocket handshakes do.
    let (url, server) = serve_resumed(3).await;
    let client = Client::builder_tokio()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .tls_cert_verification(false)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let negotiation = tls13()
        .alpn_protocols([AlpnProtocol::HTTP1])
        .alps_protocols([AlpsProtocol::HTTP1])
        .alps_use_new_codepoint(false)
        .build();
    get(client.get(&url).emulation(tls13().build())).await;
    let http1 = client.get(&url).emulation(tls13().build());
    get(http1.version(http::Version::HTTP_11)).await;
    get(client.get(&url).emulation(negotiation)).await;
    assert_eq!(finish(server).await, [false, true, true]);
}

#[tokio::test]
async fn handshake_options_follow_client_and_request_settings() {
    let hellos = Arc::new(Mutex::new(Vec::new()));
    let observed = hellos.clone();
    let mut acceptor = acceptor(TEST_IDENTITY, SslVersion::TLS1_3);
    acceptor.set_select_certificate_callback(move |hello| {
        let ciphers: Vec<_> = hello
            .ciphers()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|bytes| u16::from_be_bytes(*bytes))
            .filter(|cipher| (0x1301..=0x1303).contains(cipher))
            .collect();
        let padding = hello
            .get_extension(ExtensionType::SERVER_PADDING)
            .map(<[u8]>::to_vec);
        observed.lock().unwrap().push((ciphers, padding));
        Ok(())
    });
    let (addr, server) = serve(acceptor.build(), 3).await;
    let url = format!("https://{addr}/");
    let client = client_builder()
        .tls_options(
            TlsOptions::builder()
                .tls13_cipher_list(&[
                    Tls13Cipher::AES_256_GCM_SHA384,
                    Tls13Cipher::CHACHA20_POLY1305_SHA256,
                    Tls13Cipher::AES_128_GCM_SHA256,
                ])
                .server_padding(0)
                .build(),
        )
        .build()
        .unwrap();

    get(client.get(&url)).await;
    get(client.get(&url).emulation(
        TlsOptions::builder()
            .tls13_cipher_list(&[Tls13Cipher::AES_128_GCM_SHA256])
            .server_padding(32)
            .build(),
    ))
    .await;
    get(client
        .get(&url)
        .emulation(TlsOptions::builder().tls13_cipher_list(Vec::new()).build()))
    .await;
    finish(server).await;
    {
        let mut offered = hellos.lock().unwrap();
        offered[2].0.sort_unstable();
        assert_eq!(
            *offered,
            [
                (vec![0x1302, 0x1303, 0x1301], Some(vec![0, 0])),
                (vec![0x1301], Some(vec![0, 32])),
                (vec![0x1301, 0x1302, 0x1303], None),
            ]
        );
    }

    let duplicate = TlsOptions::builder()
        .tls13_cipher_list(&[Tls13Cipher::AES_128_GCM_SHA256; 2])
        .build();
    assert!(
        client_builder()
            .tls_options(duplicate.clone())
            .build()
            .is_err()
    );
    let error = client
        .get(&url)
        .emulation(duplicate)
        .send()
        .await
        .unwrap_err();
    assert!(error.is_connect());
    assert!(
        std::iter::successors(
            Some(&error as &(dyn std::error::Error + 'static)),
            |error| { error.source() }
        )
        .any(|error| error.is::<btls::error::ErrorStack>())
    );
}

#[tokio::test]
async fn psk_skip_session_ticket_omits_ticket_only_on_tls13_resumption() {
    let options = TlsOptions::builder()
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .pre_shared_key(true)
        .psk_skip_session_ticket(true)
        .build();
    let client = client_builder().build().unwrap();

    // Full handshakes and TLS 1.2 resumption send session_ticket; TLS 1.3 resumption does not.
    for (max_version, expected) in [
        (SslVersion::TLS1_3, [(false, true), (true, false)]),
        (SslVersion::TLS1_2, [(false, true), (true, true)]),
    ] {
        let (url, server) = serve_tickets(TEST_IDENTITY, max_version, 2).await;
        for _ in 0..2 {
            get(client.get(&url).emulation(options.clone())).await;
        }
        assert_eq!(finish(server).await, expected);
    }
}

#[tokio::test]
async fn tls13_tickets_resume_with_certificate_verification() {
    let (url, server) = serve_tickets(LOCALHOST_IDENTITY, SslVersion::TLS1_3, 2).await;
    let client = client_builder()
        .tls_cert_verification(true)
        .tls_cert_store(CertStore::from_der_certs([LOCALHOST_CA]).unwrap())
        .build()
        .unwrap();

    // The certificate is verified on the full handshake and again on resumption.
    for _ in 0..2 {
        get(client.get(&url).emulation(psk())).await;
    }
    let resumed: Vec<_> = finish(server)
        .await
        .into_iter()
        .map(|(resumed, _)| resumed)
        .collect();
    assert_eq!(resumed, [false, true]);
}

/// Resolves every name to the address the test selects next.
#[cfg(target_os = "linux")]
struct SwitchingResolver(Mutex<SocketAddr>);

#[cfg(target_os = "linux")]
impl Resolve for SwitchingResolver {
    fn resolve(&self, _: Name) -> Resolving {
        let addr = *self.0.lock().unwrap();
        Box::pin(async move { Ok(Box::new(std::iter::once(addr)) as Addrs) })
    }
}

// 127.0.0.2 reaches the loopback interface without configuration only on Linux.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn tls12_rsa_key_exchange_sessions_resume_only_at_their_address() {
    for (cipher_list, resumes_elsewhere) in [
        ("ECDHE-RSA-AES128-GCM-SHA256", true),
        ("AES128-GCM-SHA256", false),
    ] {
        let mut acceptor = acceptor(LOCALHOST_IDENTITY, SslVersion::TLS1_2);
        acceptor.set_cipher_list(cipher_list).unwrap();
        let acceptor = acceptor.build();
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.2:0").await.unwrap();
        let addrs = [
            first.local_addr().unwrap(),
            first.local_addr().unwrap(),
            second.local_addr().unwrap(),
        ];
        let server = tokio::spawn(async move {
            [
                serve_once(&acceptor, &first).await,
                serve_once(&acceptor, &first).await,
                serve_once(&acceptor, &second).await,
            ]
        });

        let resolver = Arc::new(SwitchingResolver(Mutex::new(addrs[0])));
        let client = client_builder()
            .dns_resolver(resolver.clone())
            .build()
            .unwrap();
        for addr in addrs {
            *resolver.0.lock().unwrap() = addr;
            get(client.get("https://session.test/").emulation(psk())).await;
        }
        assert_eq!(
            finish(server).await,
            [false, true, resumes_elsewhere],
            "{cipher_list}"
        );
    }
}

#[tokio::test]
async fn lru_session_store_evicts_least_recently_used_key() {
    let (addr, server) = serve(acceptor(TEST_IDENTITY, SslVersion::TLS1_3).build(), 4).await;

    // A per-key capacity beyond any allocation shows that storage grows with use. The last
    // key capacity wins, even after a zero one disabled storage.
    let store = LruTlsSessionStore::new(usize::MAX)
        .with_key_capacity(0)
        .with_key_capacity(1);
    let client = client_builder()
        .resolve("a.test", addr)
        .resolve("b.test", addr)
        .tls_session_store(Arc::new(store))
        .build()
        .unwrap();
    for host in ["a.test", "a.test", "b.test", "a.test"] {
        get(client.get(format!("https://{host}/")).emulation(psk())).await;
    }
    assert_eq!(finish(server).await, [false, true, false, false]);
}
