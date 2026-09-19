use std::{
    convert::Infallible,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use btls::{
    pkey::PKey,
    ssl::{Ssl, SslAcceptor, SslMethod, SslVersion},
    x509::X509,
};
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_btls::SslStream;
use wreq::{
    Client, Emulation,
    tls::{
        TlsOptions, TlsVersion,
        session::{Key, LruTlsSessionStore, TlsSession, TlsSessionStore},
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

#[tokio::test]
async fn tls13_tickets_resume_with_fresh_contexts_and_client_scope() {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    let certificate = X509::from_der(include_bytes!("support/server.cert")).unwrap();
    let private_key = PKey::private_key_from_der(include_bytes!("support/server.key")).unwrap();
    acceptor.set_certificate(&certificate).unwrap();
    acceptor.set_private_key(&private_key).unwrap();
    acceptor.check_private_key().unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    acceptor
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let acceptor = Arc::new(acceptor.build());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut reused = [false; 12];
        for session_reused in &mut reused {
            let (socket, _) = listener.accept().await.unwrap();
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let mut stream = SslStream::new(ssl, socket).unwrap();
            Pin::new(&mut stream).accept().await.unwrap();
            *session_reused = stream.ssl().session_reused();

            let service = service_fn(|_| async {
                Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from_static(b"ok"))))
            });
            hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        }
        reused
    });

    let tls_options = TlsOptions::builder()
        .min_tls_version(TlsVersion::TLS_1_3)
        .max_tls_version(TlsVersion::TLS_1_3)
        .pre_shared_key(true)
        .build();
    let builder = || {
        Client::builder()
            .no_proxy()
            .http1_only()
            .pool_max_idle_per_host(0)
            .tls_cert_verification(false)
            .timeout(Duration::from_secs(5))
    };
    let default_client = builder().build().unwrap();
    let tls_session_store = Arc::new(LruTlsSessionStore::new(2));
    let client = || {
        builder()
            .tls_session_store(tls_session_store.clone())
            .build()
            .unwrap()
    };
    let first_client = client();
    let second_client = client();
    let unscoped_store = Arc::new(UnscopedSessionStore::default());
    let unscoped_client = || {
        builder()
            .tls_session_store(unscoped_store.clone())
            .build()
            .unwrap()
    };
    let third_client = unscoped_client();
    let fourth_client = unscoped_client();
    let panicking_client = builder()
        .tls_session_store(Arc::new(PanickingSessionStore))
        .build()
        .unwrap();
    let emulation = Emulation::builder().tls_options(tls_options).build();
    let url = format!("https://{address}/");

    for client in [
        &default_client,
        &default_client,
        &first_client,
        &first_client,
        &second_client,
        &second_client,
        &third_client,
        &third_client,
        &fourth_client,
        &fourth_client,
        &panicking_client,
        &panicking_client,
    ] {
        let response = client
            .get(&url)
            .emulation(emulation.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.bytes().await.unwrap(), "ok");
    }

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap(),
        [
            false, true, false, true, false, true, false, true, false, true, false, false
        ]
    );
}
