use bytes::{Buf, Bytes};
use std::collections::HashMap;
use std::future;
use std::pin::Pin;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;

use h3::client::SendRequest;
use h3_quinn::{Connection, OpenStreams};
use http::uri::{Authority, Scheme};
use http::{Request, Response, Uri};
use tower::BoxError;

use crate::client::body::Body;

pub(super) type Key = (Scheme, Authority);

#[derive(Clone)]
pub(super) struct Pool {
    inner: Arc<Mutex<PoolInner>>,
}

struct ConnectingLockInner {
    key: Key,
    pool: Arc<Mutex<PoolInner>>,
}

/// A lock that ensures only one HTTP/3 connection is established per host at a
/// time. The lock is automatically released when dropped.
pub(super) struct ConnectingLock(Option<ConnectingLockInner>);

/// A waiter that allows subscribers to receive updates when a new connection is
/// established or when the connection attempt fails.
pub(super) struct ConnectingWaiter {
    receiver: watch::Receiver<Option<PoolClient>>,
}

pub(super) enum Connecting {
    /// A connection attempt is already in progress.
    InProgress(ConnectingWaiter),
    /// The connection lock has been acquired.
    Acquired(ConnectingLock),
}

impl ConnectingLock {
    fn new(key: Key, pool: Arc<Mutex<PoolInner>>) -> Self {
        Self(Some(ConnectingLockInner { key, pool }))
    }

    /// Forget the lock and return the corresponding Key.
    fn forget(mut self) -> Key {
        self.0.take().unwrap().key
    }
}

impl Drop for ConnectingLock {
    fn drop(&mut self) {
        if let Some(ConnectingLockInner { key, pool }) = self.0.take() {
            let mut pool = pool.lock().unwrap();
            pool.connecting.remove(&key);
            trace!("HTTP/3 connecting lock for {:?} is dropped", key);
        }
    }
}

impl ConnectingWaiter {
    pub(super) async fn receive(mut self) -> Option<PoolClient> {
        match self.receiver.wait_for(Option::is_some).await {
            Ok(ok) => Some(ok.as_ref().unwrap().to_owned()),
            Err(_) => None,
        }
    }
}

impl Pool {
    pub(super) fn new(timeout: Option<Duration>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PoolInner {
                connecting: HashMap::new(),
                idle_conns: HashMap::new(),
                timeout,
            })),
        }
    }

    /// Acquire a connecting lock. This ensures only one HTTP/3 connection per host.
    pub(super) fn connecting(&self, key: &Key) -> Connecting {
        let mut inner = self.inner.lock().unwrap();

        if let Some(sender) = inner.connecting.get(key) {
            Connecting::InProgress(ConnectingWaiter {
                receiver: sender.subscribe(),
            })
        } else {
            let (tx, _) = watch::channel(None);
            inner.connecting.insert(key.clone(), tx);
            Connecting::Acquired(ConnectingLock::new(key.clone(), Arc::clone(&self.inner)))
        }
    }

    pub(super) fn try_pool(&self, key: &Key) -> Option<PoolClient> {
        let mut inner = self.inner.lock().unwrap();
        let timeout = inner.timeout;
        if let Some(conn) = inner.idle_conns.get(key) {
            if conn.is_invalid() {
                trace!("pooled HTTP/3 connection is invalid so removing it...");
                inner.idle_conns.remove(key);
                return None;
            }

            if let Some(duration) = timeout {
                if Instant::now().saturating_duration_since(conn.idle_timeout) > duration {
                    trace!("pooled connection expired");
                    inner.idle_conns.remove(key);
                    return None;
                }
            }
        }

        inner.idle_conns.get_mut(key).map(|conn| conn.pool())
    }

    pub(super) fn new_connection(
        &mut self,
        lock: ConnectingLock,
        mut driver: h3::client::Connection<Connection, Bytes>,
        tx: SendRequest<OpenStreams, Bytes>,
    ) -> PoolClient {
        let (close_tx, close_rx) = std::sync::mpsc::channel();
        tokio::spawn(async move {
            let e = future::poll_fn(|cx| driver.poll_close(cx)).await;
            trace!("poll_close returned error {e:?}");
            close_tx.send(e).ok();
        });

        let mut inner = self.inner.lock().unwrap();

        let key = lock.forget();
        let Some(notifier) = inner.connecting.remove(&key) else {
            unreachable!("there should be one connecting lock at a time");
        };
        let client = PoolClient::new(tx);

        let pool_client = if let Err(watch::error::SendError(Some(unsent_client))) =
            notifier.send(Some(client.clone()))
        {
            unsent_client
        } else {
            client.clone()
        };

        let conn = PoolConnection::new(pool_client, close_rx);
        inner.insert(key, conn);

        client
    }
}

struct PoolInner {
    connecting: HashMap<Key, watch::Sender<Option<PoolClient>>>,
    idle_conns: HashMap<Key, PoolConnection>,
    timeout: Option<Duration>,
}

impl PoolInner {
    fn insert(&mut self, key: Key, conn: PoolConnection) {
        if self.idle_conns.contains_key(&key) {
            trace!("connection already exists for key {key:?}");
        }

        self.idle_conns.insert(key, conn);
    }
}

#[derive(Clone)]
pub(super) struct PoolClient {
    inner: SendRequest<OpenStreams, Bytes>,
}

impl PoolClient {
    pub(super) fn new(tx: SendRequest<OpenStreams, Bytes>) -> Self {
        Self { inner: tx }
    }

    pub(super) async fn send_request(
        &mut self,
        req: Request<Body>,
        pseudo_order: Option<h3::PseudoOrder>,
    ) -> Result<Response<Incoming>, BoxError> {
        use http_body::Body as _;

        let (head, mut req_body) = req.into_parts();
        let mut req = Request::from_parts(head, ());

        if let Some(n) = req_body.size_hint().exact() {
            if n > 0 {
                req.headers_mut()
                    .insert(http::header::CONTENT_LENGTH, n.into());
            }
        }

        // Insert PseudoOrder into extensions so h3 picks it up.
        if let Some(order) = pseudo_order {
            req.extensions_mut().insert(order);
        }

        let (mut send, mut recv) = self.inner.send_request(req).await?.split();

        let (tx, mut rx) = oneshot::channel::<Result<(), BoxError>>();
        tokio::spawn(async move {
            let mut req_body = Pin::new(&mut req_body);
            loop {
                match std::future::poll_fn(|cx| req_body.as_mut().poll_frame(cx)).await {
                    Some(Ok(frame)) => {
                        if let Ok(b) = frame.into_data() {
                            if let Err(e) = send.send_data(Bytes::copy_from_slice(&b)).await {
                                if is_stop_sending(&e) {
                                    let _ = tx.send(Ok(()));
                                    return;
                                }
                                if let Err(e) = tx.send(Err(e.into())) {
                                    error!("Failed to communicate send.send_data() error: {e:?}");
                                }
                                return;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        if let Err(e) = tx.send(Err(e.into())) {
                            error!("Failed to communicate req_body read error: {e:?}");
                        }
                        return;
                    }

                    None => break,
                }
            }

            if let Err(e) = send.finish().await {
                if !is_stop_sending(&e) {
                    if let Err(e) = tx.send(Err(e.into())) {
                        error!("Failed to communicate send.finish read error: {e:?}");
                    }
                    return;
                }
            }

            let _ = tx.send(Ok(()));
        });

        tokio::select! {
            Ok(Err(e)) = &mut rx => Err(e),
            resp = recv.recv_response() => {
                let resp = resp?;
                let resp_body = Incoming::new(recv, resp.headers(), rx);
                Ok(resp.map(|_| resp_body))
            }
        }
    }
}

struct PoolConnection {
    close_rx: Receiver<h3::error::ConnectionError>,
    client: PoolClient,
    idle_timeout: Instant,
}

impl PoolConnection {
    fn new(client: PoolClient, close_rx: Receiver<h3::error::ConnectionError>) -> Self {
        Self {
            close_rx,
            client,
            idle_timeout: Instant::now(),
        }
    }

    fn pool(&mut self) -> PoolClient {
        self.idle_timeout = Instant::now();
        self.client.clone()
    }

    fn is_invalid(&self) -> bool {
        match self.close_rx.try_recv() {
            Err(TryRecvError::Empty) => false,
            Err(TryRecvError::Disconnected) => true,
            Ok(_) => true,
        }
    }
}

/// HTTP/3 response body.
pub struct Incoming {
    inner: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    content_length: Option<u64>,
    send_rx: oneshot::Receiver<Result<(), BoxError>>,
}

impl Incoming {
    fn new(
        stream: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
        headers: &http::header::HeaderMap,
        send_rx: oneshot::Receiver<Result<(), BoxError>>,
    ) -> Self {
        Self {
            inner: stream,
            content_length: headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|h| h.to_str().ok())
                .and_then(|v| v.parse().ok()),
            send_rx,
        }
    }
}

impl http_body::Body for Incoming {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Ok(Err(e)) = self.send_rx.try_recv() {
            return Poll::Ready(Some(Err(e)));
        }

        match futures_util::ready!(self.inner.poll_recv_data(cx)) {
            Ok(Some(mut b)) => Poll::Ready(Some(Ok(http_body::Frame::data(
                b.copy_to_bytes(b.remaining()),
            )))),
            Ok(None) => Poll::Ready(None),
            Err(e) => Poll::Ready(Some(Err(e.into()))),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if let Some(content_length) = self.content_length {
            http_body::SizeHint::with_exact(content_length)
        } else {
            http_body::SizeHint::default()
        }
    }
}

pub(super) fn extract_domain(uri: &mut Uri) -> Result<Key, BoxError> {
    let uri_clone = uri.clone();
    match (uri_clone.scheme(), uri_clone.authority()) {
        (Some(scheme), Some(auth)) => Ok((scheme.clone(), auth.clone())),
        _ => Err("missing scheme or authority in URI".into()),
    }
}

pub(super) fn domain_as_uri((scheme, auth): Key) -> Uri {
    http::uri::Builder::new()
        .scheme(scheme)
        .authority(auth)
        .path_and_query("/")
        .build()
        .expect("domain is valid Uri")
}

/// Indicates the remote requested the peer to stop sending data without error.
fn is_stop_sending(e: &h3::error::StreamError) -> bool {
    matches!(
        e,
        h3::error::StreamError::RemoteTerminate {
            code: h3::error::Code::H3_NO_ERROR,
            ..
        }
    )
}
