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
    super::entry::Checkout,
    crate::conn::config::ConfigScope,
    bytes::Bytes,
    http::Response,
    http_body_util::Empty,
    std::{
        hash::{Hash, Hasher},
        sync::atomic::AtomicBool,
    },
    tower::util::Oneshot,
};
#[cfg(feature = "http3")]
use {
    crate::conn::{Connected, Transport, TransportMismatch, test_server_config},
    ::quic::crypto::rustls::QuicClientConfig,
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

impl Service<ConnectRequest> for TestConnector {
    type Response = Conn;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ConnectRequest) -> Self::Future {
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

/// Creates connection inputs for a local test origin that select `protocol`.
fn connect_request(protocol: Protocol) -> ConnectRequest {
    grouped_request(Group::new("test"), protocol)
}

/// Creates connection inputs with an explicit compatibility group.
fn grouped_request(group: Group, protocol: Protocol) -> ConnectRequest {
    let mut config_set = ConfigSet::default();
    config_set.insert(group);
    ConnectRequest::test(
        http::Uri::from_static("http://localhost/"),
        Some(protocol),
        config_set,
    )
}

/// Creates a pool without periodic cleanup so empty-entry removal is explicit.
fn test_pool(connector: TestConnector) -> Pool<TestConnector> {
    Pool::new(
        Config {
            idle_timeout: None,
            ..Config::default()
        },
        connector,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        &ConfigSet::default(),
        true,
    )
}

/// Starts a local QUIC server and returns a connector trusting its certificate.
/// The server keeps every accepted connection open until the test runtime ends.
#[cfg(feature = "http3")]
fn http3_connector() -> TestConnector {
    let (config, cert) = test_server_config();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.into()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
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
fn protocol_modes_build_specialized_entries() {
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
    let connector = tower::service_fn(move |_: ConnectRequest| {
        let _counter = &counter;
        std::future::pending::<Result<Conn, BoxError>>()
    });
    let pool = Pool::new(
        Config::default(),
        connector,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        &ConfigSet::default(),
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
        let target = PoolTarget {
            req: connect_request(protocol),
            wait_for_reuse: false,
        };
        let entry = pool.inner.targeter.service(&target);

        let expected = match protocol {
            #[cfg(not(feature = "http2"))]
            Protocol::Auto => Protocol::Http1,
            protocol => protocol,
        };
        assert_eq!(entry.protocol(), expected);
        assert_eq!(clones.load(Ordering::Relaxed), index + 1);
    }
}

#[tokio::test]
#[cfg(feature = "http2")]
async fn http2_checkouts_preserve_generation_and_cancellation() {
    /// Records when one checkout's configuration is finally released.
    /// Its QUIC scope keeps it out of the HTTP/2 and Auto pool identities.
    #[derive(Clone)]
    struct Released(Arc<AtomicBool>);

    impl PartialEq for Released {
        fn eq(&self, _other: &Self) -> bool {
            true
        }
    }

    impl Eq for Released {}

    impl Hash for Released {
        fn hash<H: Hasher>(&self, state: &mut H) {
            state.write_u8(0);
        }
    }

    impl ConnectConfig for Released {
        const SCOPE: ConfigScope = ConfigScope::QUIC;
    }

    impl Drop for Released {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    for protocol in [Protocol::Http2, Protocol::Auto] {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let pool = test_pool(TestConnector::Http2(calls.clone(), gate.clone()));
        let checkout = || {
            let released = Arc::new(AtomicBool::new(false));
            let req = connect_request(protocol);
            let mut config_set = req.config_set().clone();
            config_set.insert(Released(released.clone()));
            let target = PoolTarget {
                req: ConnectRequest::test(req.uri().clone(), Some(protocol), config_set),
                wait_for_reuse: false,
            };
            let (future, unused) = pool.inner.services.lock().with_service(
                &pool.inner.targeter,
                target,
                |entry, target| {
                    assert_eq!(entry.protocol(), protocol);
                    let checkout = entry.checkout(target, true);
                    assert!(!released.load(Ordering::Relaxed));
                    checkout
                },
            );
            let reused = unused.is_some();
            drop(unused);
            assert_eq!(released.load(Ordering::Relaxed), reused);
            future
        };

        let mut driver = tokio_test::task::spawn(checkout());
        assert!(driver.poll().is_pending());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let held = if protocol == Protocol::Http2 {
            let waiter = checkout();
            assert!(matches!(waiter, Checkout::Mux { .. }));
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
            assert!(matches!(future, Checkout::Mux { .. }));
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
            .services
            .lock()
            .get_mut(&connect_request(protocol).key())
            .unwrap()
            .retain(pool.inner.now(), None);
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
        assert_eq!(pool.inner.services.lock().iter_mut().count(), 1);

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
        assert!(pool.inner.services.lock().is_empty());

        let mut driver = tokio_test::task::spawn(checkout());
        assert!(driver.poll().is_pending());
        let waiter = checkout();
        drop(driver);
        drop(waiter);
        assert!(pool.inner.services.lock().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn idle_task_tracks_reusable_state() {
    let pool = Pool::new(
        Config {
            idle_timeout: Some(Duration::from_millis(10)),
            ..Config::default()
        },
        TestConnector::KeepsAlive,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        &ConfigSet::default(),
        true,
    );
    let pooled = pool
        .checkout(connect_request(Protocol::Http1), false)
        .await
        .expect("successful checkout");

    assert!(!pool.inner.expire.is_running());
    drop(pooled);
    tokio::task::yield_now().await;
    assert!(pool.inner.expire.is_running());

    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;

    assert!(pool.inner.services.lock().is_empty());
    assert!(!pool.inner.expire.is_running());

    let pool = Pool::new(
        Config {
            idle_timeout: Some(Duration::ZERO),
            ..Config::default()
        },
        TestConnector::KeepsAlive,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        &ConfigSet::default(),
        true,
    );
    let pooled = pool
        .checkout(connect_request(Protocol::Http1), false)
        .await
        .expect("successful checkout");

    drop(pooled);
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;

    assert!(!pool.inner.services.lock().is_empty());
    assert!(!pool.inner.expire.is_running());
}

#[tokio::test]
async fn idle_task_waits_for_a_runtime_after_off_runtime_drop() {
    let pool = Pool::new(
        Config {
            idle_timeout: Some(Duration::from_secs(60)),
            ..Config::default()
        },
        TestConnector::KeepsAlive,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        &ConfigSet::default(),
        true,
    );
    let checkout = || pool.checkout(connect_request(Protocol::Http1), false);

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
#[cfg(feature = "http2")]
async fn extended_connect_checkout_only_clones_established_senders() {
    for protocol in [Protocol::Http2, Protocol::Auto] {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let pool = test_pool(TestConnector::Http2(calls.clone(), gate.clone()));
        let key = connect_request(protocol).key();
        let checkout = || {
            let target = PoolTarget {
                req: connect_request(protocol),
                wait_for_reuse: false,
            };
            let (future, _) = pool.inner.services.lock().with_service(
                &pool.inner.targeter,
                target,
                |entry, target| entry.checkout(target, true),
            );
            future
        };

        // A miss neither connects nor leaves an entry behind.
        assert!(pool.checkout_extended_connect(&key).is_none());
        assert!(pool.inner.services.lock().get_mut(&key).is_none());

        // A generation still being made is not joined.
        let mut making = tokio_test::task::spawn(checkout());
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
        assert!(pool.inner.services.lock().get_mut(&key).is_some());
        // A probed checkout discards its sender like any other.
        drop(probed);
        assert!(pool.inner.services.lock().get_mut(&key).is_none());
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
        let result = pool.checkout(connect_request(protocol), false).await;
        assert!(result.is_err());
        assert!(pool.inner.services.lock().is_empty());
        assert!(!pool.inner.expire.is_running());

        let pool = test_pool(TestConnector::Pending);
        let mut first = tokio_test::task::spawn(pool.checkout(connect_request(protocol), false));
        let mut second = tokio_test::task::spawn(pool.checkout(connect_request(protocol), false));
        assert!(first.poll().is_pending());
        assert!(second.poll().is_pending());
        drop(first);
        assert!(!pool.inner.services.lock().is_empty());
        drop(second);
        assert!(pool.inner.services.lock().is_empty());
        assert!(!pool.inner.expire.is_running());
    }

    let pool = test_pool(TestConnector::ClosesAfterResponse);
    let mut pooled = pool
        .checkout(connect_request(Protocol::Http1), false)
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

    assert!(pool.inner.services.lock().is_empty());
    assert!(!pool.inner.expire.is_running());

    let request_read = Arc::new(tokio::sync::Notify::new());
    let pool = test_pool(TestConnector::StallsAfterRequest(request_read.clone()));
    let mut pooled = pool
        .checkout(connect_request(Protocol::Http1), false)
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

    assert!(pool.inner.services.lock().is_empty());
    assert!(!pool.inner.expire.is_running());

    let pool = test_pool(TestConnector::KeepsAlive);
    let req = grouped_request(Group::new("active"), Protocol::Http1);
    let mut first = pool
        .checkout(req.clone(), false)
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
        let mut services = pool.inner.services.lock();
        let mut discarded = Vec::new();
        let removed = services.retain(|_, entry| {
            discarded.extend(entry.retain(pool.inner.now(), Some(Duration::ZERO)));
            !entry.is_empty()
        });
        (removed, discarded)
    };
    assert!(removed.is_empty());
    assert!(discarded.is_empty());
    assert_eq!(pool.inner.services.lock().iter_mut().count(), 1);

    std::future::poll_fn(|cx| first.poll_ready(cx))
        .await
        .expect("reusable sender");
    drop(first);

    let second = pool.checkout(req, false).await.expect("second checkout");

    assert!(second.is_reused());
    assert_eq!(pool.inner.services.lock().iter_mut().count(), 1);
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
        Config {
            max_size: NonZeroUsize::new(1),
            ..Config::default()
        },
        TestConnector::KeepsAlive,
        DynRuntime::new(crate::rt::tokio::TokioRuntime),
        &ConfigSet::default(),
        true,
    );
    let first_req = grouped_request(Group::new("first"), Protocol::Http1);
    let second_req = grouped_request(Group::new("second"), Protocol::Http1);
    let first_key = first_req.key();
    let second_key = second_req.key();

    let mut first = pool
        .checkout(first_req, false)
        .await
        .expect("first checkout");
    send(&mut first).await;

    let mut second = pool
        .checkout(second_req, false)
        .await
        .expect("second checkout");
    send(&mut second).await;
    drop(second);

    assert_eq!(pool.inner.services.lock().iter_mut().count(), 2);

    drop(first);

    let mut services = pool.inner.services.lock();
    assert!(services.get_mut(&first_key).is_some());
    assert!(services.get_mut(&second_key).is_none());
}

#[tokio::test]
#[cfg(any(feature = "http2", feature = "http3"))]
async fn pool_max_size_skips_dead_and_busy_mux_groups() {
    for (protocol, connector) in [
        #[cfg(feature = "http2")]
        (
            Protocol::Http2,
            TestConnector::Http2(Arc::default(), Arc::new(tokio::sync::Semaphore::new(5))),
        ),
        #[cfg(feature = "http3")]
        (Protocol::Http3, http3_connector()),
    ] {
        let pool = Pool::new(
            Config {
                idle_timeout: None,
                max_size: NonZeroUsize::new(2),
                ..Config::default()
            },
            connector,
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
            &ConfigSet::default(),
            true,
        );
        let request = |name| grouped_request(Group::new(name), protocol);
        let [live, dead, next] = ["live", "dead", "next"].map(request);
        let (live_key, dead_key, next_key) = (live.key(), dead.key(), next.key());
        let checkout = |req| pool.checkout(req, false);
        let retained = |key| {
            pool.inner
                .services
                .lock()
                .get_mut(key)
                .is_some_and(|entry| entry.is_retained())
        };

        // Established senders stay retained after their checkouts end.
        drop(checkout(live).await.expect("live checkout"));
        let pooled = checkout(dead).await.expect("dead checkout");
        let connected = pooled.connected().clone();
        drop(pooled);
        assert!(retained(&dead_key));
        // Kill the idle MRU sender without a checkout, as Response::forbid_recycle
        // or a QUIC idle close would.
        connected.poison();
        assert!(!retained(&dead_key), "{protocol:?}");

        // The full LRU removes the dead group instead of evicting the live one,
        // even though idle sweeps are disabled.
        drop(checkout(next).await.expect("next checkout"));
        assert!(retained(&live_key) && retained(&next_key), "{protocol:?}");
        assert!(pool.inner.services.lock().get_mut(&dead_key).is_none());
        assert_eq!(pool.inner.services.lock().iter_mut().count(), 2);

        // A group in use is pruned, not evicted, even once it is the least recent group:
        // the full LRU displaces the idle `next` instead.
        let busy = checkout(request("live")).await.expect("busy checkout");
        for name in ["first", "second"] {
            drop(checkout(request(name)).await.expect("idle checkout"));
        }
        assert!(retained(&live_key) && !retained(&next_key), "{protocol:?}");
        drop(busy);
    }
}

/// A connector returning the other transport fails the stream handshake and the
/// HTTP/3 connect alike.
#[tokio::test]
#[cfg(feature = "http3")]
async fn mismatched_transport_fails_checkout() {
    for (protocol, connector) in [
        (Protocol::Http1, http3_connector()),
        (Protocol::Http3, TestConnector::KeepsAlive),
    ] {
        let Err(error) = test_pool(connector)
            .checkout(connect_request(protocol), false)
            .await
        else {
            panic!("{protocol:?}: checkout accepted a mismatched transport");
        };
        let source: &(dyn std::error::Error + 'static) = &*error;
        assert!(
            std::iter::successors(Some(source), |error| error.source())
                .any(|error| error.is::<TransportMismatch>()),
            "{protocol:?}: {error}"
        );
    }
}
