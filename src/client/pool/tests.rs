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
use crate::{conn::Conn, group::Group};

/// Connector behavior used to exercise unsuccessful checkout cleanup.
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

impl Service<Request<ConnectConfig>> for TestConnector {
    type Response = Conn;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<ConnectConfig>) -> Self::Future {
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

/// Creates a pool key for a local test origin.
fn pool_key(
    protocol: Protocol,
    request_config: &ConnectConfig,
    client_config: &ConnectConfig,
) -> PoolKey<PoolTarget> {
    PoolKey::new(PoolTarget {
        origin: http::Uri::from_static("http://localhost/"),
        protocol,
        options: Options::new(protocol, request_config, client_config),
    })
}

fn connect_key(protocol: Protocol) -> PoolKey<PoolTarget> {
    grouped_key(Group::new("test"), protocol)
}

fn grouped_key(group: Group, protocol: Protocol) -> PoolKey<PoolTarget> {
    let mut config = ConnectConfig::default();
    config.insert(group);
    pool_key(protocol, &config, &ConnectConfig::default())
}

/// Creates a pool without periodic cleanup so empty-entry removal is explicit.
fn test_pool(connector: TestConnector) -> Pool<TestConnector> {
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

impl Pool<TestConnector> {
    async fn test_checkout(&self, key: PoolKey<PoolTarget>) -> Result<Pooled, BoxError> {
        self.checkout(&key, false).await
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
    /// Counts connector copies made while composing protocol entries.
    /// Shares the counter between clones without creating a transport.
    /// Captured by the connector closure to observe service graph construction.
    struct CloneCounter(Arc<AtomicUsize>);

    impl Clone for CloneCounter {
        fn clone(&self) -> Self {
            self.0.fetch_add(1, Ordering::Relaxed);
            Self(self.0.clone())
        }
    }

    let clones = Arc::new(AtomicUsize::new(0));
    let counter = CloneCounter(clones.clone());
    let connector = tower::service_fn(move |_: Request<ConnectConfig>| {
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
        let key = connect_key(protocol);
        let _entry = pool.inner.new_entry(&key);
        assert_eq!(clones.load(Ordering::Relaxed), index + 1);
    }
}

#[tokio::test]
#[cfg(feature = "http2")]
async fn http2_checkouts_preserve_generation_and_cancellation() {
    // Equivalent HTTP/1 options leave the key unchanged in both modes.
    let http1 = Http1Options::builder().max_headers(96).build();
    let mut client_config = ConnectConfig::default();
    client_config.insert(http1.clone());

    for protocol in [Protocol::Http2, Protocol::Auto] {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let pool = Pool::new(
            TestConnector::Http2(calls.clone(), gate.clone()),
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
            Config {
                idle_timeout: None,
                ..Config::default()
            },
            &client_config,
            true,
        );
        let mut request_config = ConnectConfig::default();
        request_config.insert(Group::new("test"));
        let key = pool_key(protocol, &request_config, &client_config);
        request_config.insert(http1.clone());
        let equivalent_key = pool_key(protocol, &request_config, &client_config);
        assert_eq!(equivalent_key, key);
        let checkout = || {
            let mut entries = pool.inner.entries.lock();
            let entry = entries
                .get_or_insert_with(&equivalent_key, || pool.inner.new_entry(&equivalent_key));
            entry.checkout(equivalent_key.as_ref(), true)
        };

        let mut driver = tokio_test::task::spawn(checkout());
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
        assert!(checkout().await.unwrap().is_reused());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
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
    let pool = Pool::new(
        TestConnector::KeepsAlive,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        Config {
            idle_timeout: Some(Duration::from_millis(10)),
            ..Config::default()
        },
        &ConnectConfig::default(),
        true,
    );
    let pooled = pool
        .test_checkout(connect_key(Protocol::Http1))
        .await
        .expect("successful checkout");

    assert!(!pool.inner.expire.is_running());
    drop(pooled);
    tokio::task::yield_now().await;
    assert!(pool.inner.expire.is_running());

    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;

    assert!(pool.inner.entries.lock().is_empty());
    assert!(!pool.inner.expire.is_running());

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
        .test_checkout(connect_key(Protocol::Http1))
        .await
        .expect("successful checkout");

    drop(pooled);
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;

    assert!(!pool.inner.entries.lock().is_empty());
    assert!(!pool.inner.expire.is_running());
}

#[tokio::test]
async fn idle_task_waits_for_a_runtime_after_off_runtime_drop() {
    let pool = Pool::new(
        TestConnector::KeepsAlive,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        Config {
            idle_timeout: Some(Duration::from_mins(1)),
            ..Config::default()
        },
        &ConnectConfig::default(),
        true,
    );
    let checkout = || pool.test_checkout(connect_key(Protocol::Http1));

    // Returning a connection on a thread without a runtime keeps it pooled but
    // cannot start the watcher.
    let pooled = checkout().await.expect("successful checkout");
    std::thread::spawn(move || drop(pooled))
        .join()
        .expect("drop without a runtime");
    tokio::task::yield_now().await;
    assert!(!pool.inner.expire.is_running());

    // The next return on the runtime starts it.
    let pooled = checkout().await.expect("reused checkout");
    assert!(pooled.is_reused());
    drop(pooled);
    tokio::task::yield_now().await;
    assert!(pool.inner.expire.is_running());
}

#[tokio::test]
#[cfg(all(feature = "ws", feature = "http2"))]
async fn extended_connect_checkout_only_clones_established_senders() {
    for protocol in [Protocol::Http2, Protocol::Auto] {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let pool = test_pool(TestConnector::Http2(calls.clone(), gate.clone()));
        let key = connect_key(protocol);

        // A miss neither connects nor leaves an entry behind.
        assert!(pool.checkout_extended_connect(&key).is_none());
        assert!(pool.inner.entries.lock().get_mut(&key).is_none());

        // A generation still being made is not joined.
        let mut making = tokio_test::task::spawn(pool.checkout(&key, false));
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
        let result = pool.test_checkout(connect_key(protocol)).await;
        std::assert_matches!(&result, Err(_));
        assert!(pool.inner.entries.lock().is_empty());
        assert!(!pool.inner.expire.is_running());

        let pool = test_pool(TestConnector::Pending);
        let mut first = tokio_test::task::spawn(pool.test_checkout(connect_key(protocol)));
        let mut second = tokio_test::task::spawn(pool.test_checkout(connect_key(protocol)));
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
        .test_checkout(connect_key(Protocol::Http1))
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
        .test_checkout(connect_key(Protocol::Http1))
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
    let key = grouped_key(Group::new("active"), Protocol::Http1);
    let mut first = pool.checkout(&key, false).await.expect("first checkout");
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

    let second = pool.checkout(&key, false).await.expect("second checkout");

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
    let first_key = grouped_key(Group::new("first"), Protocol::Http1);
    let second_key = grouped_key(Group::new("second"), Protocol::Http1);

    let mut first = pool
        .checkout(&first_key, false)
        .await
        .expect("first checkout");
    send(&mut first).await;

    let mut second = pool
        .checkout(&second_key, false)
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
        let key = |name| grouped_key(Group::new(name), protocol);
        let [live_key, dead_key, next_key] = ["live", "dead", "next"].map(key);
        let checkout = |key| pool.checkout(key, false);
        let retained = |key| {
            pool.inner
                .entries
                .lock()
                .get_mut(key)
                .is_some_and(|entry| entry.has_retained())
        };

        // Established senders stay retained after their checkouts end.
        drop(checkout(&live_key).await.expect("live checkout"));
        let pooled = checkout(&dead_key).await.expect("dead checkout");
        let connected = pooled.connected().clone();
        drop(pooled);
        assert!(retained(&dead_key));
        // Kill the idle MRU sender without a checkout, as Response::forbid_recycle
        // or a QUIC idle close would.
        connected.poison();
        assert!(!retained(&dead_key), "{protocol:?}");

        // The full LRU removes the dead group instead of evicting the live one,
        // even though idle sweeps are disabled.
        drop(checkout(&next_key).await.expect("next checkout"));
        assert!(retained(&live_key) && retained(&next_key), "{protocol:?}");
        assert!(pool.inner.entries.lock().get_mut(&dead_key).is_none());
        assert_eq!(pool.inner.entries.lock().iter_mut().count(), 2);

        // A group in use is pruned, not evicted, even once it is the least recent group:
        // the full LRU displaces the idle `next` instead.
        let busy = checkout(&live_key).await.expect("busy checkout");
        for name in ["first", "second"] {
            drop(
                pool.checkout(&key(name), false)
                    .await
                    .expect("idle checkout"),
            );
        }
        assert!(retained(&live_key) && !retained(&next_key), "{protocol:?}");
        drop(busy);
        drop(pool);

        // An untracked group counts toward capacity again when its last checkout ends.
        let pool = make_pool(1);
        let checkout = |key| pool.checkout(key, false);
        let first = checkout(&live_key).await.expect("first checkout");
        let last = checkout(&live_key).await.expect("last checkout");
        drop(checkout(&next_key).await.expect("next checkout"));

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
            .test_checkout(connect_key(protocol))
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
