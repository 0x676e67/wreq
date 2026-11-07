use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    thread::{self, ThreadId},
    time::Duration,
};

use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::Version;
use quic::crypto::rustls::QuicServerConfig;
use tokio::{
    runtime::{Handle, Runtime},
    sync::{Semaphore, mpsc, oneshot},
    task::JoinHandle,
};
use tower::{BoxError, Layer, Service, limit::ConcurrencyLimitLayer, timeout::TimeoutLayer};
use wreq::{Client, tls::trust::CertStore};

use super::support::{layer::DelayLayer, server};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

struct Http3Server {
    endpoint: quic::Endpoint,
    certificate: Vec<u8>,
    task: JoinHandle<()>,
}

struct BackgroundRuntime(Option<Runtime>);

#[derive(Debug)]
enum Event {
    Entered(usize, ThreadId),
    Dropped(usize),
}

struct Operation {
    id: usize,
    events: mpsc::UnboundedSender<Event>,
}

#[derive(Clone)]
struct BackgroundLayer {
    runtime: Handle,
    gate: Arc<Semaphore>,
    events: mpsc::UnboundedSender<Event>,
    calls: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct Background<S> {
    inner: S,
    layer: BackgroundLayer,
}

// ===== impl Http3Server =====

impl Http3Server {
    fn new() -> Self {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let config =
            quic::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        let endpoint = quic::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let incoming = endpoint.clone();
        let task = tokio::spawn(async move {
            let connection = incoming.accept().await.unwrap().await.unwrap();
            let mut server = ::http3::server::builder()
                .build::<_, Bytes>(http3_quic::Connection::new(connection))
                .await
                .unwrap();
            while let Ok(Some(request)) = server.accept().await {
                let (_, mut stream) = request.resolve_request().await.unwrap();
                stream.send_response(http::Response::new(())).await.unwrap();
                stream.send_data(Bytes::from_static(b"ok")).await.unwrap();
                stream.finish().await.unwrap();
            }
        });
        Self {
            endpoint,
            certificate: certificate.cert.der().to_vec(),
            task,
        }
    }

    fn url(&self) -> String {
        format!(
            "https://localhost:{}/",
            self.endpoint.local_addr().unwrap().port()
        )
    }

    fn client(&self) -> wreq::ClientBuilder {
        Client::builder_tokio()
            .no_proxy()
            .resolve("localhost", self.endpoint.local_addr().unwrap())
            .tls_cert_store(CertStore::from_der_certs([&self.certificate]).unwrap())
            .timeout(TEST_TIMEOUT)
    }
}

impl Drop for Http3Server {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"done");
        self.task.abort();
    }
}

// ===== impl BackgroundRuntime =====

impl BackgroundRuntime {
    fn new() -> Self {
        Self(Some(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap(),
        ))
    }

    fn layer(&self) -> (BackgroundLayer, mpsc::UnboundedReceiver<Event>) {
        let (events, receiver) = mpsc::unbounded_channel();
        (
            BackgroundLayer {
                runtime: self.0.as_ref().unwrap().handle().clone(),
                gate: Arc::new(Semaphore::new(0)),
                events,
                calls: Arc::new(AtomicUsize::new(0)),
            },
            receiver,
        )
    }
}

impl Drop for BackgroundRuntime {
    fn drop(&mut self) {
        // Dropping a Runtime directly inside an async test would block and panic.
        self.0.take().unwrap().shutdown_background();
    }
}

// ===== impl Operation =====

impl Drop for Operation {
    fn drop(&mut self) {
        let _ = self.events.send(Event::Dropped(self.id));
    }
}

// ===== impl BackgroundLayer =====

impl<S> Layer<S> for BackgroundLayer {
    type Service = Background<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Background {
            inner,
            layer: self.clone(),
        }
    }
}

// ===== impl Background =====

impl<S, Request> Service<Request> for Background<S>
where
    S: Service<Request>,
    S::Response: Send + 'static,
    S::Error: Into<BoxError> + Send,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let response = self.inner.call(request);
        let layer = self.layer.clone();
        let id = layer.calls.fetch_add(1, Ordering::Relaxed);
        let (mut sender, receiver) = oneshot::channel();
        self.layer.runtime.spawn(async move {
            let _operation = Operation {
                id,
                events: layer.events.clone(),
            };
            layer
                .events
                .send(Event::Entered(id, thread::current().id()))
                .unwrap();
            tokio::select! {
                _ = sender.closed() => {}
                result = async {
                    layer.gate.acquire().await.unwrap().forget();
                    response.await.map_err(Into::into)
                } => {
                    let _ = sender.send(result);
                }
            }
        });
        Box::pin(async move { receiver.await.map_err(BoxError::from)? })
    }
}

async fn event(receiver: &mut mpsc::UnboundedReceiver<Event>) -> Event {
    tokio::time::timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("connector event timed out")
        .expect("connector event channel closed")
}

#[tokio::test]
async fn http3_connection_runs_on_the_layer_runtime() {
    let server = Http3Server::new();
    let runtime = BackgroundRuntime::new();
    let (layer, mut events) = runtime.layer();
    let client = server
        .client()
        .http3_only()
        .connector_layer(layer.clone())
        .build()
        .unwrap();
    let request = tokio::spawn(client.get(server.url()).send());

    let Event::Entered(0, worker) = event(&mut events).await else {
        panic!("HTTP/3 did not enter the connector layer");
    };
    assert_ne!(worker, thread::current().id());
    layer.gate.add_permits(1);
    let response = request.await.unwrap().unwrap();
    assert_eq!(response.version(), Version::HTTP_3);
    assert_eq!(response.text().await.unwrap(), "ok");
    assert!(matches!(event(&mut events).await, Event::Dropped(0)));
}

#[tokio::test]
async fn tcp_and_http3_share_the_limit_and_release_it_on_cancellation() {
    for first_is_http3 in [true, false] {
        let http3 = Http3Server::new();
        let http1 = server::http(|_| async { http::Response::default() });
        let runtime = BackgroundRuntime::new();
        let (layer, mut events) = runtime.layer();
        let client = http3
            .client()
            .http3_only()
            .connector_layer(layer.clone())
            .connector_layer(ConcurrencyLimitLayer::new(1))
            .build()
            .unwrap();
        let mut targets = [
            (http3.url(), Version::HTTP_3),
            (format!("http://{}/", http1.addr()), Version::HTTP_11),
        ];
        if !first_is_http3 {
            targets.reverse();
        }
        let [(first_url, first_version), (second_url, second_version)] = targets;
        let first = tokio::spawn(client.get(first_url).version(first_version).send());
        assert!(matches!(event(&mut events).await, Event::Entered(0, _)));

        let mut second = Box::pin(client.get(second_url).version(second_version).send());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), second.as_mut())
                .await
                .is_err()
        );
        assert!(
            events.try_recv().is_err(),
            "both protocols must share one permit"
        );

        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        let resumed = tokio::spawn(second);
        let mut dropped = false;
        let mut entered = false;
        while !dropped || !entered {
            match event(&mut events).await {
                Event::Dropped(0) => dropped = true,
                Event::Entered(1, _) => entered = true,
                event => panic!("unexpected connector event: {event:?}"),
            }
        }
        layer.gate.add_permits(1);
        let response = resumed.await.unwrap().unwrap();
        assert_eq!(response.version(), second_version);
        response.bytes().await.unwrap();
    }
}

#[tokio::test]
async fn http3_connection_timeouts_cover_user_layers() {
    let server = Http3Server::new();
    for tower_timeout in [false, true] {
        let builder = server
            .client()
            .connector_layer(DelayLayer::new(Duration::from_secs(60)));
        let builder = if tower_timeout {
            builder.connector_layer(TimeoutLayer::new(Duration::from_millis(50)))
        } else {
            builder.connect_timeout(Duration::from_millis(50))
        };
        let error = builder
            .build()
            .unwrap()
            .get(server.url())
            .version(Version::HTTP_3)
            .send()
            .await
            .unwrap_err();
        assert!(error.is_connect() && error.is_timeout(), "{error:?}");
    }
}

#[tokio::test]
async fn http3_connect_timeout_starts_after_admission() {
    let server = Http3Server::new();
    let runtime = BackgroundRuntime::new();
    let (layer, mut events) = runtime.layer();
    let client = server
        .client()
        .http3_only()
        .connect_timeout(Duration::from_millis(500))
        .connector_layer(layer.clone())
        .connector_layer(ConcurrencyLimitLayer::new(1))
        .build()
        .unwrap();

    // Another origin keeps the only permit until its connect timeout ends it.
    let first = tokio::spawn(client.get("https://127.0.0.1:1/").send());
    assert!(matches!(event(&mut events).await, Event::Entered(0, _)));
    let second = tokio::spawn(client.get(server.url()).send());
    let error = first.await.unwrap().unwrap_err();
    assert!(error.is_connect() && error.is_timeout(), "{error:?}");

    // The waiting connection gets its whole deadline once admitted.
    let mut dropped = false;
    let mut entered = false;
    while !dropped || !entered {
        match event(&mut events).await {
            Event::Dropped(0) => dropped = true,
            Event::Entered(1, _) => entered = true,
            event => panic!("unexpected connector event: {event:?}"),
        }
    }
    layer.gate.add_permits(1);
    let response = second.await.unwrap().unwrap();
    assert_eq!(response.version(), Version::HTTP_3);
}
