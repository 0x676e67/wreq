use std::{
    io,
    sync::atomic::Ordering,
    task::{self, Poll},
};

use futures_util::future::BoxFuture;
use http::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "http3")]
use {
    crate::conn::{Connected, Transport},
    ::quic::crypto::rustls::{QuicClientConfig, QuicServerConfig},
    std::net::{Ipv4Addr, SocketAddr},
};
#[cfg(feature = "http2")]
use {bytes::Bytes, http::Response, http_body_util::Empty, netty::http1::Http1Options};

use super::*;
use crate::{
    conn,
    reuse::{self, Group},
    rt::{DynRuntime, tokio::TokioRuntime},
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

fn new_pool<C>(
    connector: C,
    config: Config,
    connect_config: &ConnectConfig,
) -> Pool<reuse::Key, C, TokioRuntime>
where
    C: Service<Unnameable, Response = Conn, Error = BoxError, Future: Send + 'static>
        + Clone
        + Send
        + Sync
        + 'static,
{
    Pool::new(
        connector,
        TokioRuntime,
        config,
        proto::Builder::new(DynRuntime::new(TokioRuntime), connect_config),
    )
}

/// Creates a pool without periodic cleanup so empty-entry removal is explicit.
fn test_pool(connector: TestConnector) -> Pool<reuse::Key, TestConnector, TokioRuntime> {
    new_pool(
        connector,
        Config {
            idle_timeout: None,
            ..Config::default()
        },
        &ConnectConfig::default(),
    )
}

impl Pool<reuse::Key, TestConnector, TokioRuntime> {
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

/// Counts connector clones.
struct CloneCounter(Arc<AtomicUsize>);

impl Clone for CloneCounter {
    fn clone(&self) -> Self {
        self.0.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}

#[test]
fn protocol_modes_clone_connector_once() {
    let clones = Arc::new(AtomicUsize::new(0));
    let counter = CloneCounter(clones.clone());
    let connector = tower::service_fn(move |_: Unnameable| {
        let _counter = &counter;
        std::future::pending::<Result<Conn, BoxError>>()
    });
    let pool = new_pool(connector, Config::default(), &ConnectConfig::default());
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
        let pool = new_pool(
            connector,
            Config {
                idle_timeout: None,
                ..Config::default()
            },
            &connect_config,
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
            let (future, discarded) = entry.checkout(request, true);
            drop(entries);
            drop(discarded);
            future
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

        let hot = pool
            .checkout(Some(&equivalent_key), &waiter_request)
            .await
            .unwrap();
        assert!(hot.is_reused());
        let pending = checkout();

        let completed = checkout().await.unwrap();
        let connected = completed.connected().clone();
        drop(completed);
        // Response::forbid_recycle poisons after dispatch releases its checkout.
        // Another unpolled checkout must not suppress this health check.
        connected.poison();
        let discarded = pool.inner.entries.lock().get_mut(&key).unwrap().prune(None);
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
        drop(hot);
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

        std::future::poll_fn(|cx| replacement.poll_ready(cx))
            .await
            .unwrap();
        let response = replacement
            .send_request(
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            )
            .unwrap()
            .await
            .unwrap();
        assert_eq!(response.version(), http::Version::HTTP_2);
        let hot = pool
            .checkout(Some(&equivalent_key), &waiter_request)
            .await
            .unwrap();
        assert!(hot.is_reused());
        drop(replacement);
        hot.connected().poison();
        drop(hot);

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
        let pool = new_pool(
            connector,
            Config {
                idle_timeout: Some(Duration::from_millis(10)),
                ..Config::default()
            },
            &ConnectConfig::default(),
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
        if protocol == Protocol::Http1 {
            assert!(!pool.inner.expire.is_running());
        }

        drop(reused);
        tokio::task::yield_now().await;
        assert!(pool.inner.expire.is_running());
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;

        assert!(pool.inner.entries.lock().is_empty());
        assert!(!pool.inner.expire.is_running());
    }

    let pool = new_pool(
        TestConnector::KeepsAlive,
        Config {
            idle_timeout: Some(Duration::ZERO),
            ..Config::default()
        },
        &ConnectConfig::default(),
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
#[cfg(feature = "http2")]
async fn extended_connect_checkout_only_leases_established_senders() {
    for protocol in [Protocol::Http2, Protocol::Auto] {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let idle_timeout = Duration::from_secs(60);
        let pool = new_pool(
            TestConnector::Http2(calls.clone(), gate.clone()),
            Config {
                idle_timeout: Some(idle_timeout),
                max_size: NonZeroUsize::new(1),
                ..Config::default()
            },
            &ConnectConfig::default(),
        );
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
        pooled.send_request(request).unwrap().await.unwrap();
        drop(pooled);
        let probed = pool.checkout_extended_connect(&key).unwrap();
        assert!(probed.version() == http::Version::HTTP_2 && probed.is_reused());
        assert_eq!(probed.extended_connect(), Some(true));
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        // An active probe lease protects the sender even past its idle deadline.
        let _ = pool.inner.retain(pool.inner.now() + idle_timeout * 2);
        assert!(pool.inner.entries.lock().get_mut(&key).is_some());

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
        .send_request(
            Request::builder()
                .uri("http://localhost/")
                .body(crate::Body::default())
                .unwrap(),
        )
        .unwrap()
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
        pooled
            .send_request(
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            )
            .unwrap(),
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
        .send_request(
            Request::builder()
                .uri("http://localhost/")
                .body(crate::Body::default())
                .unwrap(),
        )
        .unwrap()
        .await
        .expect("successful request");

    // An in-flight HTTP/1 sender can disappear from its idle cache while
    // still needing that cache for its return. This regression was found in:
    // https://github.com/smithy-lang/smithy-rs/commit/998e5fb9254bf972aa9c6f6e82e521afd627613e
    let (removed, discarded) = {
        let mut entries = pool.inner.entries.lock();
        let mut discarded = Vec::new();
        let removed = entries.retain(|_, entry| {
            discarded.extend(entry.prune(Some((pool.inner.now(), Duration::ZERO))));
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
            .send_request(
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            )
            .unwrap()
            .await
            .expect("successful request");
    }

    let pool = new_pool(
        TestConnector::KeepsAlive,
        Config {
            max_size: NonZeroUsize::new(1),
            ..Config::default()
        },
        &ConnectConfig::default(),
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

    {
        let mut entries = pool.inner.entries.lock();
        assert!(entries.get_mut(&first_key).is_some());
        assert!(entries.get_mut(&second_key).is_none());
    }

    // Bounded hits without idle_timeout must resolve on the first poll without reading the clock.
    #[derive(Clone, Default)]
    struct CountingRuntime {
        now_calls: Arc<AtomicUsize>,
    }

    impl Executor for CountingRuntime {
        fn execute(&self, future: BoxFuture<'static, ()>) {
            TokioRuntime.execute(future);
        }
    }

    impl Timer for CountingRuntime {
        fn now(&self) -> Instant {
            self.now_calls.fetch_add(1, Ordering::SeqCst);
            TokioRuntime.now()
        }

        fn sleep(&self, duration: Duration) -> crate::rt::BoxSleep {
            TokioRuntime.sleep(duration)
        }

        fn sleep_until(&self, deadline: Instant) -> crate::rt::BoxSleep {
            TokioRuntime.sleep_until(deadline)
        }
    }

    let runtime = CountingRuntime::default();
    let config = ConnectConfig::default();
    let clones = Arc::new(AtomicUsize::new(0));
    let counter = CloneCounter(clones.clone());
    let connector = ServiceBuilder::new()
        .map_request(move |request: Unnameable| {
            let _counter = &counter;
            request
        })
        .service(TestConnector::KeepsAlive);
    let pool = Pool::new(
        connector,
        runtime.clone(),
        Config {
            idle_timeout: None,
            max_size: NonZeroUsize::new(2),
            ..Config::default()
        },
        proto::Builder::new(DynRuntime::new(TokioRuntime), &config),
    );
    let protocol = cfg_select! {
        feature = "http2" => Protocol::Auto,
        _ => Protocol::Http1,
    };
    let [a, b, c] = ["a", "b", "c"].map(|name| grouped_request(Group::new(name), protocol));
    let [key_a, key_b, key_c] = [&a, &b, &c].map(|request| request.reuse_key(protocol));
    drop(pool.checkout(Some(&key_b), &b).await.unwrap());

    let older = pool.checkout(Some(&key_a), &a).await.unwrap();
    let newer = pool.checkout(Some(&key_a), &a).await.unwrap();
    let connected = older.connected().clone();
    drop(older);
    drop(newer);
    connected.poison();

    let before = runtime.now_calls.load(Ordering::SeqCst);
    #[cfg(feature = "http2")]
    let clones_before = clones.load(Ordering::Relaxed);
    let mut hit = tokio_test::task::spawn(Box::pin(pool.checkout(Some(&key_a), &a)));
    let Poll::Ready(Ok(reused)) = hit.poll() else {
        panic!("bounded warm hit must resolve synchronously on the first poll");
    };
    assert_eq!(runtime.now_calls.load(Ordering::SeqCst), before);
    #[cfg(feature = "http2")]
    assert_eq!(clones.load(Ordering::Relaxed), clones_before);
    assert!(reused.is_reused());

    // A's dead sender below the healthy one must not count against capacity.
    drop(pool.checkout(Some(&key_c), &c).await.unwrap());
    assert!(pool.checkout(Some(&key_b), &b).await.unwrap().is_reused());
    drop(reused);
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
            new_pool(
                connector.clone(),
                Config {
                    idle_timeout: None,
                    max_size: NonZeroUsize::new(max_size),
                    ..Config::default()
                },
                &ConnectConfig::default(),
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
        {
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

        // A deferred final release must not promote a group already re-registered in the LRU.
        drop(pool);
        let pool = make_pool(2);
        let [(a_key, a), (b_key, b), (c_key, c), (d_key, d)] = ["a", "b", "c", "d"].map(group);
        let checkout = |key, request| pool.checkout(Some(key), request);
        let busy_a = checkout(&a_key, &a).await.expect("a checkout");
        drop(checkout(&b_key, &b).await.expect("b checkout"));
        drop(checkout(&c_key, &c).await.expect("c checkout"));
        // Re-register `a`, then touch `c` so LRU order is [a, c].
        drop(checkout(&a_key, &a).await.expect("a re-register"));
        drop(checkout(&c_key, &c).await.expect("c touch"));
        // Final release of `a` clears DEFERRED but must keep `a` behind `c`.
        drop(busy_a);
        drop(checkout(&d_key, &d).await.expect("d checkout"));
        let mut entries = pool.inner.entries.lock();
        assert!(
            entries.get_mut(&a_key).is_none(),
            "{protocol:?}: deferred release must not promote already-tracked group"
        );
        assert!(
            entries.get_mut(&c_key).is_some() && entries.get_mut(&d_key).is_some(),
            "{protocol:?}: more recently used groups must survive eviction"
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

/// Verifies `Singleton` batch cancellation still pairs `poll_ready` with `call` on
/// stateful connectors, and `Auto + ReuseFirst` joins an H2 upgrade published during
/// the reuse delay without dialing a second connection.
#[tokio::test]
#[cfg(any(feature = "http2", feature = "http3"))]
async fn mux_readiness_after_cancel_and_auto_reuse_first_upgrade() {
    struct StrictConnector<C> {
        inner: C,
        ready: bool,
    }

    impl<C: Clone> Clone for StrictConnector<C> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
                ready: false,
            }
        }
    }

    impl<C> Service<Unnameable> for StrictConnector<C>
    where
        C: Service<Unnameable, Response = Conn, Error = BoxError, Future: Send + 'static>,
    {
        type Response = Conn;
        type Error = BoxError;
        type Future = C::Future;

        fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            let ready = self.inner.poll_ready(cx);
            if matches!(ready, Poll::Ready(Ok(()))) {
                self.ready = true;
            }
            ready
        }

        fn call(&mut self, req: Unnameable) -> Self::Future {
            assert!(self.ready, "connector called without readiness");
            self.ready = false;
            self.inner.call(req)
        }
    }

    // Finding 1: Singleton::poll_ready skips inner readiness while a batch is active;
    // canceling that batch before the next call must still pair readiness with call.
    #[cfg(feature = "http2")]
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let runtime = DynRuntime::new(TokioRuntime);
        let config = ConnectConfig::default();
        let proto = proto::Builder::new(runtime.clone(), &config);
        let shared = Arc::new(Mutex::new(EntryState::default()));
        let maker = StreamMaker {
            connector: StrictConnector {
                inner: TestConnector::Http2(calls, gate.clone()),
                ready: false,
            }
            .map_request(Unnameable),
            timer: TokioRuntime,
        };
        let mut first_svc = Singleton::new(proto.http2(&config).layer(maker), shared);
        let mut second_svc = first_svc.clone();
        let request = connect_request(Protocol::Http2);

        std::future::poll_fn(|cx| first_svc.poll_ready(cx))
            .await
            .unwrap();
        let mut first = tokio_test::task::spawn(first_svc.call(request.clone()));
        assert!(first.poll().is_pending());

        // `second_svc.poll_ready` sees `State::Making` and skips inner readiness.
        std::future::poll_fn(|cx| second_svc.poll_ready(cx))
            .await
            .unwrap();
        drop(first);

        gate.add_permits(1);
        let second = second_svc.call(request).await.unwrap();
        assert_eq!(second.inner().version(), http::Version::HTTP_2);
    }
    #[cfg(feature = "http3")]
    {
        let runtime = DynRuntime::new(TokioRuntime);
        let config = ConnectConfig::default();
        let proto = proto::Builder::new(runtime.clone(), &config);
        let shared = Arc::new(Mutex::new(EntryState::default()));
        let connector = StrictConnector {
            inner: http3_connector(),
            ready: false,
        }
        .map_request(Unnameable);
        let mut first_svc = Singleton::new(proto.http3(&config).layer(connector), shared);
        let mut second_svc = first_svc.clone();
        let request = connect_request(Protocol::Http3);

        std::future::poll_fn(|cx| first_svc.poll_ready(cx))
            .await
            .unwrap();
        let mut first = tokio_test::task::spawn(first_svc.call(request.clone()));
        assert!(first.poll().is_pending());

        std::future::poll_fn(|cx| second_svc.poll_ready(cx))
            .await
            .unwrap();
        drop(first);

        let second = second_svc.call(request).await.unwrap();
        assert_eq!(second.inner().version(), http::Version::HTTP_3);
    }

    // Finding 3: Auto + ReuseFirst must observe an H2 upgrade published during the
    // reuse delay and reuse it without waiting out the delay or dialing twice.
    #[cfg(feature = "http2")]
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let pool = new_pool(
            TestConnector::Http2(calls.clone(), gate.clone()),
            Config {
                strategy: PoolStrategy::ReuseFirst(Duration::from_secs(3)),
                ..Config::default()
            },
            &ConnectConfig::default(),
        );
        let request = connect_request(Protocol::Auto);
        let key = request.reuse_key(Protocol::Auto);

        let mut first = tokio_test::task::spawn(Box::pin(pool.checkout(Some(&key), &request)));
        assert!(first.poll().is_pending());

        let mut second = tokio_test::task::spawn(Box::pin(pool.checkout(Some(&key), &request)));
        assert!(second.poll().is_pending());

        // Release the first dial: it negotiates H2, consumes pending, and completes.
        gate.add_permits(1);
        let first_pooled = tokio::time::timeout(Duration::from_secs(1), first.into_inner())
            .await
            .expect("first checkout should complete promptly")
            .unwrap();
        assert_eq!(first_pooled.version(), http::Version::HTTP_2);

        // Second checkout must wake from its 3s ReuseFirst wait and join H2 directly.
        let second_pooled = tokio::time::timeout(Duration::from_secs(1), second.into_inner())
            .await
            .expect("second checkout should observe H2 upgrade without waiting 3s")
            .unwrap();
        assert_eq!(second_pooled.version(), http::Version::HTTP_2);
        assert!(second_pooled.is_reused());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(first_pooled);
        drop(second_pooled);
    }

    // Finding 1 (round 2): Under ConcurrencyLimitLayer(1), a same-group H2 checkout must
    // join its group's Making batch even when the first checkout is still waiting on the
    // limiter, instead of queueing behind an unrelated group's dial.
    #[cfg(feature = "http2")]
    {
        use tower::limit::ConcurrencyLimitLayer;

        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let connector =
            ConcurrencyLimitLayer::new(1).layer(TestConnector::Http2(calls.clone(), gate.clone()));
        let pool = new_pool(connector, Config::default(), &ConnectConfig::default());

        let group_c = grouped_request(Group::new("c"), Protocol::Http2);
        let key_c = group_c.reuse_key(Protocol::Http2);
        let group_a = grouped_request(Group::new("a"), Protocol::Http2);
        let key_a = group_a.reuse_key(Protocol::Http2);
        let group_b = grouped_request(Group::new("b"), Protocol::Http2);
        let key_b = group_b.reuse_key(Protocol::Http2);

        // C1 holds the single ConcurrencyLimit permit while dialing.
        let mut c1 = tokio_test::task::spawn(Box::pin(pool.checkout(Some(&key_c), &group_c)));
        assert!(c1.poll().is_pending());

        // A1 registers group A's Making batch immediately even though it blocks on the limiter.
        let mut a1 = tokio_test::task::spawn(Box::pin(pool.checkout(Some(&key_a), &group_a)));
        assert!(a1.poll().is_pending());

        // B1 queues on the limiter behind A1.
        let mut b1 = tokio_test::task::spawn(Box::pin(pool.checkout(Some(&key_b), &group_b)));
        assert!(b1.poll().is_pending());

        // A2 must join A1's already-registered batch instead of queueing behind B1 on the limiter.
        let mut a2 = tokio_test::task::spawn(Box::pin(pool.checkout(Some(&key_a), &group_a)));
        assert!(a2.poll().is_pending());

        // Release C1 so A1 acquires the permit, then release A1; B1 stays blocked on its dial,
        // yet A2 must wake immediately and reuse A1's connection.
        gate.add_permits(1);
        let c1_pooled = tokio::time::timeout(Duration::from_secs(1), c1.into_inner())
            .await
            .expect("C1 should complete")
            .unwrap();
        assert_eq!(c1_pooled.version(), http::Version::HTTP_2);

        gate.add_permits(1);
        let a1_pooled = tokio::time::timeout(Duration::from_secs(1), a1.into_inner())
            .await
            .expect("A1 should complete after C1 releases permit")
            .unwrap();
        assert_eq!(a1_pooled.version(), http::Version::HTTP_2);
        assert!(a2.is_woken());

        let a2_pooled = tokio::time::timeout(Duration::from_secs(1), a2.into_inner())
            .await
            .expect("A2 must wake and reuse A1 without waiting on unrelated group B")
            .unwrap();
        assert_eq!(a2_pooled.version(), http::Version::HTTP_2);
        assert!(a2_pooled.is_reused());
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        drop(b1);
        drop(c1_pooled);
        drop(a1_pooled);
        drop(a2_pooled);
    }
}
