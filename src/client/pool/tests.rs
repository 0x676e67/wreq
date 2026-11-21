use std::{
    io,
    sync::atomic::Ordering,
    task::{self, Poll},
};

use futures_util::future::BoxFuture;
use http::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "http2")]
use {
    super::entry::CheckoutFuture, bytes::Bytes, http::Response, http_body_util::Empty,
    tower::util::Oneshot,
};
#[cfg(feature = "http3")]
use {
    crate::conn::{Connected, Transport},
    ::quic::crypto::rustls::{QuicClientConfig, QuicServerConfig},
    std::net::{Ipv4Addr, SocketAddr},
};

use super::*;
use crate::{
    conn,
    reuse::{self, Group},
};

/// Mock connector covering failure, stall, keep-alive, HTTP/2, and HTTP/3 scenarios.
#[derive(Clone)]
enum TestConnector {
    /// Fails the connection attempt immediately.
    Fails,
    /// Keeps the connection attempt pending until cancellation.
    Pending,
    /// Completes one request and then closes the transport.
    ClosesAfterResponse,
    /// Keeps the transport reusable until the client drops its sender.
    KeepsAlive,
    /// Accepts a request without producing response headers.
    StallsAfterRequest(Arc<tokio::sync::Notify>),
    /// Counts HTTP/2 connection attempts and gates transport creation.
    /// Reports `h2` as ALPN would, so Auto also selects HTTP/2 without TLS.
    #[cfg(feature = "http2")]
    Http2(Arc<AtomicUsize>, Arc<tokio::sync::Semaphore>),
    /// Opens a fresh QUIC connection to the local server at this address.
    #[cfg(feature = "http3")]
    Http3(SocketAddr, ::quic::ClientConfig),
}

impl Service<Unnameable> for TestConnector {
    type Response = Conn;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Unnameable) -> Self::Future {
        match self {
            Self::Fails => Box::pin(std::future::ready(Err(io::Error::from(
                io::ErrorKind::ConnectionRefused,
            )
            .into()))),
            Self::Pending => Box::pin(std::future::pending()),
            #[cfg(feature = "http3")]
            Self::Http3(server, config) => {
                let (server, config) = (*server, config.clone());
                Box::pin(async move {
                    let endpoint = ::quic::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
                    let connection = endpoint.connect_with(config, server, "localhost")?.await?;
                    Ok(Conn {
                        transport: Transport::Quic {
                            connection,
                            endpoint,
                        },
                        connected: Connected::new(),
                    })
                })
            }
            #[cfg(feature = "http2")]
            Self::Http2(calls, gate) => {
                calls.fetch_add(1, Ordering::Relaxed);
                let gate = gate.clone();
                Box::pin(async move {
                    gate.acquire().await.unwrap().forget();
                    let (client, server) = tokio::io::duplex(4096);
                    tokio::spawn(async move {
                        let service = hyper::service::service_fn(|_| async {
                            Ok::<_, io::Error>(Response::new(Empty::<Bytes>::new()))
                        });
                        let _ = hyper::server::conn::http2::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .enable_connect_protocol()
                        .serve_connection(hyper_util::rt::TokioIo::new(server), service)
                        .await;
                    });
                    let mut conn = Conn::test(client);
                    conn.connected = conn.connected.negotiated_h2();
                    Ok(conn)
                })
            }
            Self::ClosesAfterResponse => Box::pin(async {
                let (client, mut server) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    let mut request = [0; 1024];
                    let read = server.read(&mut request).await.expect("read request");
                    assert!(read > 0);
                    server
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await
                        .expect("write response");
                });
                Ok(Conn::test(client))
            }),
            Self::KeepsAlive => Box::pin(async {
                let (client, mut server) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    let mut request = [0; 1024];
                    let read = server.read(&mut request).await.expect("read request");
                    if read == 0 {
                        return;
                    }
                    server
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .expect("write response");
                    while server.read(&mut request).await.unwrap_or_default() != 0 {}
                });
                Ok(Conn::test(client))
            }),
            Self::StallsAfterRequest(request_read) => {
                let request_read = request_read.clone();
                Box::pin(async move {
                    let (client, mut server) = tokio::io::duplex(1024);
                    tokio::spawn(async move {
                        let mut request = [0; 1024];
                        let read = server.read(&mut request).await.expect("read request");
                        assert!(read > 0);
                        request_read.notify_one();
                        std::future::pending::<()>().await;
                    });
                    Ok(Conn::test(client))
                })
            }
        }
    }
}

/// Prepares a connection request for a local test origin.
fn request(protocol: Protocol, connect_config: ConnectConfig) -> conn::Request<ConnectConfig> {
    conn::Request::new(
        http::Uri::from_static("http://localhost/"),
        protocol,
        connect_config,
    )
}

fn connect_request(protocol: Protocol) -> conn::Request<ConnectConfig> {
    grouped_request(Group::new("test"), protocol)
}

fn grouped_request(group: Group, protocol: Protocol) -> conn::Request<ConnectConfig> {
    let mut connect_config = ConnectConfig::default();
    connect_config.insert(group);
    request(protocol, connect_config)
}

/// Creates a pool without periodic cleanup so empty-entry removal is explicit.
fn test_pool(connector: TestConnector) -> Pool<reuse::Key, TestConnector> {
    Pool::new(
        connector,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        Config {
            idle_timeout: None,
            ..Config::default()
        },
        &ConnectConfig::default(),
        true,
    )
}

impl Pool<reuse::Key, TestConnector> {
    async fn test_checkout(
        &self,
        request: conn::Request<ConnectConfig>,
    ) -> Result<Pooled, BoxError> {
        let key = request.reuse_key(request.protocol());
        self.checkout(Some(&key), &request).await
    }
}

/// Starts a local QUIC server and returns a connector trusting its certificate.
/// The server keeps every accepted connection open until the test runtime ends.
#[cfg(feature = "http3")]
fn http3_connector() -> TestConnector {
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "::1".into(),
    ])
    .unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let config = ::quic::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_tls).unwrap(),
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let server = ::quic::Endpoint::server(config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let address = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut peers = Vec::new();
        while let Some(incoming) = server.accept().await {
            peers.extend(incoming.await);
        }
    });
    TestConnector::Http3(
        address,
        ::quic::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap())),
    )
}

#[test]
fn protocol_modes_clone_connector_once() {
    /// Counts connector clones made during protocol entry construction.
    struct CloneCounter(Arc<AtomicUsize>);

    impl Clone for CloneCounter {
        fn clone(&self) -> Self {
            self.0.fetch_add(1, Ordering::Relaxed);
            Self(self.0.clone())
        }
    }

    let clones = Arc::new(AtomicUsize::new(0));
    let counter = CloneCounter(clones.clone());
    let connector = tower::service_fn(move |_: Unnameable| {
        let _counter = &counter;
        std::future::pending::<Result<Conn, BoxError>>()
    });
    let pool = Pool::new(
        connector,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        Config::default(),
        &ConnectConfig::default(),
        true,
    );
    assert_eq!(clones.load(Ordering::Relaxed), 0);

    for (index, protocol) in [
        Protocol::Http1,
        #[cfg(feature = "http2")]
        Protocol::Http2,
        #[cfg(feature = "http3")]
        Protocol::Http3,
        Protocol::Auto,
    ]
    .into_iter()
    .enumerate()
    {
        let request = connect_request(protocol);
        let key = request.reuse_key(protocol);
        let _entry = pool.inner.new_entry(Some(&key), &request);
        assert_eq!(clones.load(Ordering::Relaxed), index + 1);
    }
}

#[tokio::test]
#[cfg(feature = "http2")]
async fn http2_checkouts_preserve_generation_and_cancellation() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DialOption {
        Driver,
        Waiter,
    }

    // Equivalent HTTP/1 options leave the key unchanged in both modes.
    let http1 = Http1Options::builder().max_headers(96).build();
    let mut connect_config = ConnectConfig::default();
    connect_config.insert(http1.clone());

    for protocol in [Protocol::Http2, Protocol::Auto] {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let connector = ServiceBuilder::new()
            .map_request({
                let observed = observed.clone();
                move |request: Unnameable| {
                    observed
                        .lock()
                        .push(request.0.body().get_ref::<DialOption>().copied());
                    request
                }
            })
            .service(TestConnector::Http2(calls.clone(), gate.clone()));
        let pool = Pool::new(
            connector,
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
            Config {
                idle_timeout: None,
                ..Config::default()
            },
            &connect_config,
            true,
        );
        let mut driver_connect_config = ConnectConfig::default().with_base(&connect_config);
        driver_connect_config
            .insert(Group::new("test"))
            .insert(DialOption::Driver);
        let mut waiter_connect_config = driver_connect_config.clone();
        waiter_connect_config
            .insert(http1.clone())
            .insert(DialOption::Waiter);
        let mut different = waiter_connect_config.clone();
        different.insert(Http1Options::builder().max_headers(97).build());
        let driver_request = request(protocol, driver_connect_config);
        let waiter_request = request(protocol, waiter_connect_config);
        let key = driver_request.reuse_key(protocol);
        let equivalent_key = waiter_request.reuse_key(protocol);
        assert_eq!(equivalent_key, key);
        assert_eq!(
            request(protocol, different).reuse_key(protocol) == key,
            protocol == Protocol::Http2
        );
        let checkout_with = |key: &reuse::Key, request: &conn::Request<ConnectConfig>| {
            let mut entries = pool.inner.entries.lock();
            let entry =
                entries.get_or_insert_with(key, || pool.inner.new_entry(Some(key), request));
            entry.checkout(request, true)
        };
        let checkout = || checkout_with(&equivalent_key, &waiter_request);

        let mut driver = tokio_test::task::spawn(checkout_with(&key, &driver_request));
        assert!(driver.poll().is_pending());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let held = if protocol == Protocol::Http2 {
            let waiter = checkout();
            assert!(matches!(waiter, CheckoutFuture::Mux { .. }));
            let mut waiter = tokio_test::task::spawn(waiter);
            assert!(waiter.poll().is_pending());
            drop(driver);
            assert!(waiter.is_woken());
            gate.add_permits(1);
            let held = tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap();
            assert!(held.is_reused());
            held
        } else {
            // Auto has no singleton generation until transport negotiation.
            gate.add_permits(1);
            tokio::time::timeout(Duration::from_secs(1), driver)
                .await
                .unwrap()
                .unwrap()
        };

        let mut checkouts = Vec::new();
        for i in 0..100 {
            let future = checkout();
            assert!(matches!(future, CheckoutFuture::Mux { .. }));
            if i % 2 == 0 {
                checkouts.push(future);
            }
        }
        for pooled in futures_util::future::join_all(checkouts).await {
            assert!(pooled.unwrap().is_reused());
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(*observed.lock(), [Some(DialOption::Driver)]);

        let pending = checkout();
        let completed = checkout().await.unwrap();
        let connected = completed.connected().clone();
        drop(completed);
        // Response::forbid_recycle poisons after dispatch releases its checkout.
        // Another unpolled checkout must not suppress this health check.
        connected.poison();
        let discarded = pool
            .inner
            .entries
            .lock()
            .get_mut(&key)
            .unwrap()
            .prune(pool.inner.now(), None);
        assert!(
            discarded.is_some(),
            "{protocol:?}: poisoned sender was retained"
        );
        drop(discarded);
        gate.add_permits(1);
        let mut replacement = tokio::time::timeout(Duration::from_secs(1), checkout())
            .await
            .unwrap()
            .unwrap();
        assert!(!replacement.is_reused());
        drop(pending);
        drop(held);
        let reuse = checkout();
        assert!(matches!(reuse, CheckoutFuture::Mux { .. }));
        let reused = reuse.await.unwrap();
        assert!(reused.is_reused());
        drop(reused);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            *observed.lock(),
            [Some(DialOption::Driver), Some(DialOption::Waiter)]
        );
        assert_eq!(pool.inner.entries.lock().iter_mut().count(), 1);

        let response = Oneshot::new(
            &mut replacement,
            Request::builder()
                .uri("http://localhost/")
                .body(crate::Body::default())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.version(), http::Version::HTTP_2);
        replacement.connected().poison();
        drop(replacement);
        assert!(pool.inner.entries.lock().is_empty());

        let mut driver = tokio_test::task::spawn(checkout());
        assert!(driver.poll().is_pending());
        let waiter = checkout();
        drop(driver);
        drop(waiter);
        assert!(pool.inner.entries.lock().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn idle_task_tracks_reusable_state() {
    for (protocol, connector) in [
        (Protocol::Http1, TestConnector::KeepsAlive),
        #[cfg(feature = "http2")]
        (
            Protocol::Http2,
            TestConnector::Http2(
                Arc::new(AtomicUsize::new(0)),
                Arc::new(tokio::sync::Semaphore::new(1)),
            ),
        ),
    ] {
        let pool = Pool::new(
            connector,
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
            Config {
                idle_timeout: Some(Duration::from_millis(10)),
                ..Config::default()
            },
            &ConnectConfig::default(),
            true,
        );
        let request = connect_request(protocol);
        let pooled = pool.test_checkout(request.clone()).await.unwrap();
        if protocol == Protocol::Http1 {
            assert!(!pool.inner.expire.is_running());
        }
        drop(pooled);
        tokio::task::yield_now().await;
        assert!(pool.inner.expire.is_running());

        let reused = pool.test_checkout(request).await.unwrap();
        assert!(reused.is_reused());
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        assert!(!pool.inner.entries.lock().is_empty());

        drop(reused);
        tokio::task::yield_now().await;
        assert!(pool.inner.expire.is_running());
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;

        assert!(pool.inner.entries.lock().is_empty());
        assert!(!pool.inner.expire.is_running());
    }

    let pool = Pool::new(
        TestConnector::KeepsAlive,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        Config {
            idle_timeout: Some(Duration::ZERO),
            ..Config::default()
        },
        &ConnectConfig::default(),
        true,
    );
    let pooled = pool
        .test_checkout(connect_request(Protocol::Http1))
        .await
        .expect("successful checkout");

    drop(pooled);
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;

    assert!(!pool.inner.entries.lock().is_empty());
    assert!(!pool.inner.expire.is_running());
}

#[tokio::test]
#[cfg(all(feature = "ws", feature = "http2"))]
async fn extended_connect_checkout_only_clones_established_senders() {
    for protocol in [Protocol::Http2, Protocol::Auto] {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let pool = test_pool(TestConnector::Http2(calls.clone(), gate.clone()));
        let request = connect_request(protocol);
        let key = request.reuse_key(protocol);

        // A miss neither connects nor leaves an entry behind.
        assert!(pool.checkout_extended_connect(&key).is_none());
        assert!(pool.inner.entries.lock().get_mut(&key).is_none());

        // A generation still being made is not joined.
        let mut making = tokio_test::task::spawn(pool.checkout(Some(&key), &request));
        assert!(making.poll().is_pending());
        assert!(pool.checkout_extended_connect(&key).is_none());
        gate.add_permits(1);
        let mut pooled = making.await.unwrap();
        // Support is unknown until the peer's SETTINGS; the probe must not guess.
        assert_eq!(pooled.extended_connect(), None);
        assert!(pool.checkout_extended_connect(&key).is_none());

        // A response proves the peer's SETTINGS were applied.
        let request = Request::get("http://localhost/")
            .body(crate::Body::default())
            .unwrap();
        pooled.call(request).await.unwrap();
        drop(pooled);
        let probed = pool.checkout_extended_connect(&key).unwrap();
        assert!(probed.version() == http::Version::HTTP_2 && probed.is_reused());
        assert_eq!(probed.extended_connect(), Some(true));
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        // Unusable senders are skipped without the probe evicting them.
        probed.connected().poison();
        assert!(pool.checkout_extended_connect(&key).is_none());
        assert!(pool.inner.entries.lock().get_mut(&key).is_some());
        // A probed checkout discards its sender like any other.
        drop(probed);
        assert!(pool.inner.entries.lock().get_mut(&key).is_none());
    }
}

#[tokio::test]
async fn checkouts_remove_empty_map_entries() {
    for protocol in [
        Protocol::Http1,
        #[cfg(feature = "http2")]
        Protocol::Http2,
        #[cfg(feature = "http3")]
        Protocol::Http3,
        Protocol::Auto,
    ] {
        let pool = test_pool(TestConnector::Fails);
        let result = pool.test_checkout(connect_request(protocol)).await;
        std::assert_matches!(&result, Err(_));
        assert!(pool.inner.entries.lock().is_empty());
        assert!(!pool.inner.expire.is_running());

        let pool = test_pool(TestConnector::Pending);
        let mut first = tokio_test::task::spawn(pool.test_checkout(connect_request(protocol)));
        let mut second = tokio_test::task::spawn(pool.test_checkout(connect_request(protocol)));
        assert!(first.poll().is_pending());
        assert!(second.poll().is_pending());
        drop(first);
        assert!(!pool.inner.entries.lock().is_empty());
        drop(second);
        assert!(pool.inner.entries.lock().is_empty());
        assert!(!pool.inner.expire.is_running());
    }

    let pool = test_pool(TestConnector::ClosesAfterResponse);
    let mut pooled = pool
        .test_checkout(connect_request(Protocol::Http1))
        .await
        .expect("successful checkout");
    std::future::poll_fn(|cx| pooled.poll_ready(cx))
        .await
        .expect("ready sender");
    let response = pooled
        .call(
            Request::builder()
                .uri("http://localhost/")
                .body(crate::Body::default())
                .unwrap(),
        )
        .await
        .expect("successful request");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(
        std::future::poll_fn(|cx| pooled.poll_ready(cx))
            .await
            .is_err()
    );
    drop(pooled);

    assert!(pool.inner.entries.lock().is_empty());
    assert!(!pool.inner.expire.is_running());

    let request_read = Arc::new(tokio::sync::Notify::new());
    let pool = test_pool(TestConnector::StallsAfterRequest(request_read.clone()));
    let mut pooled = pool
        .test_checkout(connect_request(Protocol::Http1))
        .await
        .expect("successful checkout");
    std::future::poll_fn(|cx| pooled.poll_ready(cx))
        .await
        .expect("ready sender");
    let mut response = tokio_test::task::spawn(
        pooled.call(
            Request::builder()
                .uri("http://localhost/")
                .body(crate::Body::default())
                .unwrap(),
        ),
    );
    assert!(response.poll().is_pending());
    tokio::time::timeout(Duration::from_secs(1), request_read.notified())
        .await
        .expect("request should reach server");
    drop(response);
    drop(pooled);

    assert!(pool.inner.entries.lock().is_empty());
    assert!(!pool.inner.expire.is_running());

    let pool = test_pool(TestConnector::KeepsAlive);
    let request = grouped_request(Group::new("active"), Protocol::Http1);
    let key = request.reuse_key(request.protocol());
    let mut first = pool
        .checkout(Some(&key), &request)
        .await
        .expect("first checkout");
    std::future::poll_fn(|cx| first.poll_ready(cx))
        .await
        .expect("ready sender");
    first
        .call(
            Request::builder()
                .uri("http://localhost/")
                .body(crate::Body::default())
                .unwrap(),
        )
        .await
        .expect("successful request");

    // An in-flight HTTP/1 sender can disappear from its idle cache while
    // still needing that cache for its return. This regression was found in:
    // https://github.com/smithy-lang/smithy-rs/commit/998e5fb9254bf972aa9c6f6e82e521afd627613e
    let (removed, discarded) = {
        let mut entries = pool.inner.entries.lock();
        let mut discarded = Vec::new();
        let removed = entries.retain(|_, entry| {
            discarded.extend(entry.prune(pool.inner.now(), Some(Duration::ZERO)));
            !entry.is_empty()
        });
        (removed, discarded)
    };
    assert!(removed.is_empty());
    assert!(discarded.is_empty());
    assert_eq!(pool.inner.entries.lock().iter_mut().count(), 1);

    std::future::poll_fn(|cx| first.poll_ready(cx))
        .await
        .expect("reusable sender");
    drop(first);

    let second = pool
        .checkout(Some(&key), &request)
        .await
        .expect("second checkout");

    assert!(second.is_reused());
    assert_eq!(pool.inner.entries.lock().iter_mut().count(), 1);
    drop(second);
}

#[tokio::test]
async fn pool_max_size_evicts_only_idle_groups() {
    async fn send(client: &mut Pooled) {
        std::future::poll_fn(|cx| client.poll_ready(cx))
            .await
            .expect("ready sender");
        client
            .call(
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            )
            .await
            .expect("successful request");
    }

    let pool = Pool::new(
        TestConnector::KeepsAlive,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        Config {
            max_size: NonZeroUsize::new(1),
            ..Config::default()
        },
        &ConnectConfig::default(),
        true,
    );
    let first_request = grouped_request(Group::new("first"), Protocol::Http1);
    let second_request = grouped_request(Group::new("second"), Protocol::Http1);
    let first_key = first_request.reuse_key(first_request.protocol());
    let second_key = second_request.reuse_key(second_request.protocol());

    let mut first = pool
        .checkout(Some(&first_key), &first_request)
        .await
        .expect("first checkout");
    send(&mut first).await;

    let mut second = pool
        .checkout(Some(&second_key), &second_request)
        .await
        .expect("second checkout");
    send(&mut second).await;
    drop(second);

    assert_eq!(pool.inner.entries.lock().iter_mut().count(), 2);

    drop(first);

    let mut entries = pool.inner.entries.lock();
    assert!(entries.get_mut(&first_key).is_some());
    assert!(entries.get_mut(&second_key).is_none());
}

#[tokio::test]
#[cfg(any(feature = "http2", feature = "http3"))]
async fn pool_max_size_skips_dead_and_busy_mux_groups() {
    #[cfg(feature = "http2")]
    let http2_connector = || {
        use tokio::sync::Semaphore;
        TestConnector::Http2(
            Arc::default(),
            Arc::new(Semaphore::new(Semaphore::MAX_PERMITS)),
        )
    };
    for (protocol, connector) in [
        #[cfg(feature = "http2")]
        (Protocol::Http2, http2_connector()),
        #[cfg(feature = "http2")]
        (Protocol::Auto, http2_connector()),
        #[cfg(feature = "http3")]
        (Protocol::Http3, http3_connector()),
    ] {
        let make_pool = |max_size| {
            Pool::new(
                connector.clone(),
                DynRuntime::new(crate::rt::tokio::TokioRuntime),
                Config {
                    idle_timeout: None,
                    max_size: NonZeroUsize::new(max_size),
                    ..Config::default()
                },
                &ConnectConfig::default(),
                true,
            )
        };
        let pool = make_pool(2);
        let group = |name| {
            let request = grouped_request(Group::new(name), protocol);
            (request.reuse_key(protocol), request)
        };
        let [(live_key, live), (dead_key, dead), (next_key, next)] =
            ["live", "dead", "next"].map(group);
        let checkout = |key, request| pool.checkout(Some(key), request);
        let retained = |key| {
            pool.inner
                .entries
                .lock()
                .get_mut(key)
                .is_some_and(|entry| entry.has_retained())
        };

        // Established senders stay retained after their checkouts end.
        drop(checkout(&live_key, &live).await.expect("live checkout"));
        let pooled = checkout(&dead_key, &dead).await.expect("dead checkout");
        let connected = pooled.connected().clone();
        drop(pooled);
        assert!(retained(&dead_key));
        // Kill the idle MRU sender without a checkout, as Response::forbid_recycle
        // or a QUIC idle close would.
        connected.poison();
        assert!(!retained(&dead_key), "{protocol:?}");

        // The full LRU removes the dead group instead of evicting the live one,
        // even though idle sweeps are disabled.
        drop(checkout(&next_key, &next).await.expect("next checkout"));
        assert!(retained(&live_key) && retained(&next_key), "{protocol:?}");
        assert!(pool.inner.entries.lock().get_mut(&dead_key).is_none());
        assert_eq!(pool.inner.entries.lock().iter_mut().count(), 2);

        // A group in use is pruned, not evicted, even once it is the least recent group:
        // the full LRU displaces the idle `next` instead.
        let busy = checkout(&live_key, &live).await.expect("busy checkout");
        for name in ["first", "second"] {
            let (key, request) = group(name);
            drop(
                pool.checkout(Some(&key), &request)
                    .await
                    .expect("idle checkout"),
            );
        }
        assert!(retained(&live_key) && !retained(&next_key), "{protocol:?}");
        drop(busy);
        drop(pool);

        // An untracked group counts toward capacity again when its last checkout ends.
        let pool = make_pool(1);
        let checkout = |key, request| pool.checkout(Some(key), request);
        let first = checkout(&live_key, &live).await.expect("first checkout");
        let last = checkout(&live_key, &live).await.expect("last checkout");
        drop(checkout(&next_key, &next).await.expect("next checkout"));

        drop(first);
        assert_eq!(
            pool.inner.entries.lock().iter_mut().count(),
            2,
            "{protocol:?}"
        );
        drop(last);
        let mut entries = pool.inner.entries.lock();
        assert!(
            entries
                .get_mut(&live_key)
                .is_some_and(|entry| entry.has_retained()),
            "{protocol:?}: the returning sender must remain reusable"
        );
        assert!(
            entries.get_mut(&next_key).is_none(),
            "{protocol:?}: retained two idle groups"
        );
    }
}

/// A connector returning the other transport fails the stream handshake and the
/// HTTP/3 connect alike.
#[tokio::test]
#[cfg(feature = "http3")]
async fn mismatched_transport_fails_checkout() {
    for (protocol, connector, message) in [
        (
            Protocol::Http1,
            http3_connector(),
            "stream connection returned QUIC",
        ),
        (
            Protocol::Http3,
            TestConnector::KeepsAlive,
            "QUIC connection returned a stream",
        ),
    ] {
        let Err(error) = test_pool(connector)
            .test_checkout(connect_request(protocol))
            .await
        else {
            panic!("{protocol:?}: checkout accepted a mismatched transport");
        };
        let source: &(dyn std::error::Error + 'static) = &*error;
        assert!(
            std::iter::successors(Some(source), |error| error.source())
                .any(|error| error.to_string() == message),
            "{protocol:?}: {error}"
        );
    }
}
