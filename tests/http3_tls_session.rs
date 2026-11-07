#![cfg(all(feature = "http3", feature = "tokio-rt"))]

mod support;

use std::{
    net::{Ipv4Addr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use support::h3;
use wreq::{
    Client, Group,
    quic::QuicOptions,
    tls::{
        session::{Key, TlsSession, TlsSessionStore},
        trust::CertStore,
    },
};

/// Returns a foreign key's ticket deliberately, so wreq must validate its scope.
#[derive(Default)]
struct Tickets {
    ticket: Mutex<Option<TlsSession>>,
    received: tokio::sync::Notify,
}

/// Serves `first` until rotated, then `second`.
#[derive(Debug)]
struct Certificates {
    rotated: AtomicBool,
    first: Arc<CertifiedKey>,
    second: Arc<CertifiedKey>,
}

// ===== impl Tickets =====

impl TlsSessionStore for Tickets {
    fn put(&self, _key: Key, session: TlsSession) {
        assert!(session.should_be_single_use());
        *self.ticket.lock().unwrap() = Some(session);
        self.received.notify_one();
    }

    fn pop(&self, _key: &Key) -> Option<TlsSession> {
        self.ticket.lock().unwrap().take()
    }
}

// ===== impl Certificates =====

impl ResolvesServerCert for Certificates {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(if self.rotated.load(Ordering::Acquire) {
            self.second.clone()
        } else {
            self.first.clone()
        })
    }
}

fn certified(cert: &rcgen::Certificate, key: &rcgen::KeyPair) -> Arc<CertifiedKey> {
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    Arc::new(CertifiedKey::from_der(vec![cert.der().clone()], key, &provider).unwrap())
}

/// An HTTP/3 server issuing `tickets` TLS 1.3 tickets per connection.
fn server(certificates: Arc<Certificates>, tickets: usize) -> quic::Endpoint {
    let mut tls = h3::tls(certificates);
    tls.send_tls13_tickets = tickets;
    h3::endpoint(tls, None)
}

/// Answers one request on `connection` with `ok`.
async fn respond(connection: quic::Connection) -> h3::Connection {
    let mut server = http3::server::builder()
        .build::<_, Bytes>(http3_quic::Connection::new(connection))
        .await
        .unwrap();
    let (_, mut stream) = server
        .accept()
        .await
        .unwrap()
        .unwrap()
        .resolve_request()
        .await
        .unwrap();
    stream.send_response(http::Response::new(())).await.unwrap();
    stream.send_data(Bytes::from_static(b"ok")).await.unwrap();
    stream.finish().await.unwrap();
    server
}

#[tokio::test]
async fn http3_tickets_resume_across_contexts_and_preserve_client_scope() {
    // Cover both the shared client context and request contexts rebuilt for each connection.
    for request_options in [false, true] {
        // After rotation, a full handshake fails trust validation; only resumption works.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificates = Arc::new(Certificates {
            rotated: AtomicBool::new(false),
            first: certified(&cert.cert, &cert.signing_key),
            second: certified(&other.cert, &other.signing_key),
        });
        let endpoint = server(certificates.clone(), 1);
        let address = endpoint.local_addr().unwrap();
        let url = format!("https://localhost:{}/", address.port());
        let (release, mut released) = tokio::sync::mpsc::channel(1);
        let server = tokio::spawn(async move {
            for success in [true, true, false, false, false] {
                let connection = endpoint.accept().await.unwrap().await;
                if !success {
                    assert!(
                        connection.is_err(),
                        "a full handshake must reject the new certificate"
                    );
                    continue;
                }
                let _server = respond(connection.unwrap()).await;
                released.recv().await.unwrap();
            }
        });
        let tickets = Arc::new(Tickets::default());
        let options = QuicOptions::builder().pre_shared_key(true).build();
        let builder = || {
            let mut builder = Client::builder_tokio()
                .no_proxy()
                .http3_only()
                .resolve("localhost", address)
                .pool_max_idle_per_host(0)
                .tls_info(true)
                .timeout(Duration::from_secs(5))
                .tls_cert_store(CertStore::from_der_certs([cert.cert.der().as_ref()]).unwrap())
                .tls_session_store(tickets.clone());
            if !request_options {
                builder = builder.quic_options(options.clone());
            }
            builder
        };
        let client = builder().build().unwrap();
        for _ in 0..2 {
            let mut request = client.get(&url);
            if request_options {
                request = request.emulation(options.clone());
            }
            let response = request.send().await.unwrap();
            let info = response.extensions().get::<wreq::tls::TlsInfo>().unwrap();
            assert_eq!(info.peer_certificate(), Some(cert.cert.der().as_ref()));
            assert_eq!(
                info.peer_certificate_chain().unwrap().collect::<Vec<_>>(),
                [cert.cert.der().as_ref()]
            );
            tokio::time::timeout(Duration::from_secs(5), tickets.received.notified())
                .await
                .unwrap();
            assert_eq!(response.bytes().await.unwrap(), "ok");
            release.send(()).await.unwrap();
            certificates.rotated.store(true, Ordering::Release);
        }
        // Explicitly opting out cannot use the saved ticket and must fail trust.
        let response = client
            .get(&url)
            .emulation(QuicOptions::default())
            .send()
            .await;
        assert!(response.is_err());
        // A caller store returning the wrong request identity cannot resume it.
        let saved = tickets.ticket.lock().unwrap().clone().unwrap();
        let changed = QuicOptions::builder()
            .pre_shared_key(true)
            .grease_enabled(true)
            .build();
        assert!(client.get(&url).emulation(changed).send().await.is_err());
        // Restore the rejected ticket deliberately to exercise client scope too.
        *tickets.ticket.lock().unwrap() = Some(saved);
        // An incorrectly implemented caller store must not bypass client scope.
        let other_client = builder().build().unwrap();
        let mut request = other_client.get(&url);
        if request_options {
            request = request.emulation(options.clone());
        }
        assert!(request.send().await.is_err());
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn http3_skips_tickets_whose_certificate_chain_expired() {
    // Resumption re-verifies the stored chain, so a ticket outliving its certificate must give way
    // to a full handshake instead of failing it.
    let expires = SystemTime::now() + Duration::from_secs(3);
    // Distinct names keep the trust store from confusing the two self-signed roots.
    let issue = |name: &str, not_after: Option<SystemTime>| {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        if let Some(not_after) = not_after {
            params.not_after = not_after.into();
        }
        let key = rcgen::KeyPair::generate().unwrap();
        (params.self_signed(&key).unwrap(), key)
    };
    let (expiring, expiring_key) = issue("expiring", Some(expires));
    let (renewed, renewed_key) = issue("renewed", None);
    let certificates = Arc::new(Certificates {
        rotated: AtomicBool::new(false),
        first: certified(&expiring, &expiring_key),
        second: certified(&renewed, &renewed_key),
    });
    let endpoint = server(certificates.clone(), 1);
    let address = endpoint.local_addr().unwrap();
    let (release, mut released) = tokio::sync::mpsc::channel(1);
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let _server = respond(connection).await;
            released.recv().await.unwrap();
        }
    });

    let tickets = Arc::new(Tickets::default());
    let client = Client::builder_tokio()
        .no_proxy()
        .http3_only()
        .resolve("localhost", address)
        .tls_info(true)
        .timeout(Duration::from_secs(5))
        .tls_cert_store(
            CertStore::from_der_certs([expiring.der().as_ref(), renewed.der().as_ref()]).unwrap(),
        )
        .tls_session_store(tickets.clone())
        .quic_options(QuicOptions::builder().pre_shared_key(true).build())
        .build()
        .unwrap();
    let url = format!("https://localhost:{}/", address.port());
    let peer_certificate = |response: &wreq::Response| {
        let info = response.extensions().get::<wreq::tls::TlsInfo>().unwrap();
        info.peer_certificate().unwrap().to_vec()
    };

    let response = client.get(&url).send().await.unwrap();
    assert_eq!(peer_certificate(&response), expiring.der().as_ref());
    tokio::time::timeout(Duration::from_secs(5), tickets.received.notified())
        .await
        .unwrap();
    assert_eq!(response.bytes().await.unwrap(), "ok");
    release.send(()).await.unwrap();

    certificates.rotated.store(true, Ordering::Release);
    let remaining = expires
        .duration_since(SystemTime::now())
        .unwrap_or_default();
    tokio::time::sleep(remaining + Duration::from_secs(1)).await;
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(peer_certificate(&response), renewed.der().as_ref());
    assert_eq!(response.bytes().await.unwrap(), "ok");
    release.send(()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn http3_race_attempts_resume_with_their_own_tickets() {
    /// Keeps every ticket and counts the ones it hands out.
    #[derive(Default)]
    struct Stack {
        tickets: Mutex<Vec<TlsSession>>,
        taken: AtomicUsize,
    }

    impl TlsSessionStore for Stack {
        fn put(&self, _key: Key, session: TlsSession) {
            self.tickets.lock().unwrap().push(session);
        }

        fn pop(&self, _key: &Key) -> Option<TlsSession> {
            let ticket = self.tickets.lock().unwrap().pop();
            self.taken
                .fetch_add(usize::from(ticket.is_some()), Ordering::SeqCst);
            ticket
        }
    }

    let issue = |name: &str, validity: Option<(SystemTime, SystemTime)>| {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        if let Some((not_before, not_after)) = validity {
            params.not_before = not_before.into();
            params.not_after = not_after.into();
        }
        let key = rcgen::KeyPair::generate().unwrap();
        (params.self_signed(&key).unwrap(), key)
    };
    let day = Duration::from_secs(24 * 60 * 60);
    let now = SystemTime::now();
    let (trusted, trusted_key) = issue("trusted", None);
    // Sent after the trusted leaf but off the verified path, like a stale cross-sign.
    let (stale, _) = issue("stale", Some((now - 2 * day, now - day)));
    let (other, other_key) = issue("other", None);
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(trusted_key.serialize_der()).into();
    let chain = vec![trusted.der().clone(), stale.der().clone()];
    let certificates = Arc::new(Certificates {
        rotated: AtomicBool::new(false),
        first: Arc::new(CertifiedKey::from_der(chain, key, &provider).unwrap()),
        second: certified(&other, &other_key),
    });
    let endpoint = server(certificates.clone(), 2);
    let address = endpoint.local_addr().unwrap();
    let (done, finished) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let mut connections = Vec::new();
        for _ in 0..2 {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            connections.push(respond(connection).await);
        }
        finished.await.unwrap();
    });

    // The first address never answers, so each connection races two attempts.
    let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let tickets = Arc::new(Stack::default());
    let client = Client::builder_tokio()
        .no_proxy()
        .http3_only()
        .resolve_to_addrs("localhost", [blackhole.local_addr().unwrap(), address])
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .tls_cert_store(CertStore::from_der_certs([trusted.der().as_ref()]).unwrap())
        .tls_session_store(tickets.clone())
        .quic_options(QuicOptions::builder().pre_shared_key(true).build())
        .build()
        .unwrap();

    let response = client.get("https://localhost/").send().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while tickets.tickets.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(response.bytes().await.unwrap(), "ok");

    // Only resumption passes trust now. It needs a ticket the expired certificate does not
    // spoil, and each attempt must consume a ticket of its own.
    certificates.rotated.store(true, Ordering::Release);
    let response = client.get("https://localhost/").send().await.unwrap();
    assert_eq!(response.bytes().await.unwrap(), "ok");
    assert_eq!(tickets.taken.load(Ordering::SeqCst), 2);
    done.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn http3_survives_a_panicking_session_store() {
    // A panic in the caller's store must count as a miss instead of failing the connection or
    // the shared endpoint that later connections use.
    struct Panicking;

    impl TlsSessionStore for Panicking {
        fn put(&self, _key: Key, _session: TlsSession) {}

        fn pop(&self, _key: &Key) -> Option<TlsSession> {
            panic!("session store failure")
        }
    }

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = certified(&cert.cert, &cert.signing_key);
    let endpoint = server(
        Arc::new(Certificates {
            rotated: AtomicBool::new(false),
            first: key.clone(),
            second: key,
        }),
        1,
    );
    let address = endpoint.local_addr().unwrap();
    let (done, finished) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let mut connections = Vec::new();
        for _ in 0..2 {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            connections.push(respond(connection).await);
        }
        finished.await.unwrap();
    });

    let client = Client::builder_tokio()
        .no_proxy()
        .http3_only()
        .resolve("localhost", address)
        .timeout(Duration::from_secs(5))
        .tls_cert_store(CertStore::from_der_certs([cert.cert.der().as_ref()]).unwrap())
        .tls_session_store(Arc::new(Panicking))
        .quic_options(QuicOptions::builder().pre_shared_key(true).build())
        .build()
        .unwrap();
    let url = format!("https://localhost:{}/", address.port());
    // A second group opens a second connection on the same endpoint.
    for group in ["first", "second"] {
        let response = client.get(&url).group(Group::new(group)).send().await;
        assert_eq!(response.unwrap().bytes().await.unwrap(), "ok");
    }
    done.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}
