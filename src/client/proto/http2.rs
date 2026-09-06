//! HTTP/2 handshake, sender, and pooled connection lifecycle.

use std::{
    future::Future,
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures_util::{TryFutureExt, future::BoxFuture};
use http::{Request, Response};
use http_body::Body;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Layer, Service};
use wreq_proto::{body::Incoming, conn, rt::Executor as _};

use super::{Established, SendError, clock_now, is_expired};
use crate::{
    client::error::Error,
    conn::Connected,
    rt::{Executor, Timer},
    sync::Mutex,
};

/// Cloneable request-side handle for one HTTP/2 connection.
///
/// The pool singleton stores one instance and gives each checkout a sender
/// clone. Protocol stream availability remains owned by wreq-proto; the local
/// state records sender checkout only and is not an active-stream count.
pub struct Connection<B> {
    tx: conn::http2::SendRequest<B>,
    state: Arc<ConnectionState>,
    conn_info: Connected,
    timer: Timer,
}

/// Shared checkout state for one HTTP/2 physical connection.
///
/// This currently covers sender checkout through response headers. A complete
/// stream lease must also follow the accepted request body, response body, and
/// extended `CONNECT` upgrade until both stream directions terminate. The
/// lifecycle follows the lease boundary in the smithy-rs pool design:
/// <https://github.com/smithy-lang/smithy-rs/blob/connection-pool-main/rust-runtime/aws-smithy-http-client/docs/design/connection-pool.md>
struct ConnectionState {
    checkouts: AtomicUsize,
    idle_at: Mutex<Instant>,
}

/// Layers HTTP/2 handshaking over an established-transport service.
///
/// Fixed HTTP/2 wraps the connector directly; automatic mode supplies a
/// transport selected by negotiation. Both return a cloneable sender for the
/// pool's singleton service.
#[derive(Clone)]
pub struct ConnectLayer<B> {
    exec: Executor,
    timer: Timer,
    _body: PhantomData<fn(B)>,
}

/// Performs an HTTP/2 handshake for a transport-producing service.
///
/// The inner service either connects directly or yields a negotiated transport.
/// This service consumes it once, starts the protocol driver, and returns the
/// shared sender stored by the singleton pool.
pub struct Connect<S, B> {
    service: S,
    exec: Executor,
    timer: Timer,
    _body: PhantomData<fn(B)>,
}

// ===== impl ConnectLayer =====

impl<B> ConnectLayer<B> {
    /// Creates an HTTP/2 handshake layer for pooled connections.
    pub fn new(exec: Executor, timer: Timer) -> Self {
        Self {
            exec,
            timer,
            _body: PhantomData,
        }
    }
}

impl<S, B> Layer<S> for ConnectLayer<B> {
    type Service = Connect<S, B>;

    fn layer(&self, service: S) -> Self::Service {
        Connect {
            service,
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            _body: self._body,
        }
    }
}

// ===== impl Connect =====

impl<S: Clone, B> Clone for Connect<S, B> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            _body: self._body,
        }
    }
}

impl<S, T, B, Dst> Service<Dst> for Connect<S, B>
where
    S: Service<Dst, Response = Established<T>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Connection<B>;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, target: Dst) -> Self::Future {
        let future = self.service.call(target);
        let exec = self.exec.clone();
        let timer = self.timer.clone();
        Box::pin(Connection::handshake(future, exec, timer))
    }
}

// ===== impl ConnectionState =====

impl ConnectionState {
    /// Creates idle checkout state for a newly established connection.
    fn new(idle_at: Instant) -> Self {
        Self {
            checkouts: AtomicUsize::new(0),
            idle_at: Mutex::new(idle_at),
        }
    }

    /// Registers one sender checkout.
    fn acquire(&self) {
        let _ = self
            .checkouts
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_add(1))
            });
    }

    /// Releases one checkout and records the final release time.
    fn release(&self, now: Instant) -> bool {
        let mut checkouts = self.checkouts.load(Ordering::Acquire);

        loop {
            match checkouts {
                0 => return false,
                1 => {
                    let mut idle_at = self.idle_at.lock();
                    match self.checkouts.compare_exchange_weak(
                        1,
                        0,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            // Cleanup that observes zero must also observe this timestamp.
                            *idle_at = now;
                            return true;
                        }
                        Err(actual) => {
                            drop(idle_at);
                            checkouts = actual;
                        }
                    }
                }
                count => match self.checkouts.compare_exchange_weak(
                    count,
                    count - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return false,
                    Err(actual) => checkouts = actual,
                },
            }
        }
    }

    /// Returns whether no sender checkout is active.
    fn is_idle(&self) -> bool {
        self.checkouts.load(Ordering::Acquire) == 0
    }

    /// Returns the last time the final checkout was released.
    fn idle_at(&self) -> Instant {
        *self.idle_at.lock()
    }
}

// ===== impl Connection =====

impl<B> Clone for Connection<B> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            conn_info: self.conn_info.clone(),
            state: self.state.clone(),
            timer: self.timer.clone(),
        }
    }
}

impl<B> Connection<B>
where
    B: Body + 'static,
{
    /// Awaits a transport and returns a handshaken HTTP/2 sender.
    /// Starts the connection driver before waiting for sender readiness.
    async fn handshake<F, T>(established: F, exec: Executor, timer: Timer) -> Result<Self, BoxError>
    where
        F: Future<Output = Result<Established<T>, BoxError>>,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: Send + Unpin,
        B::Data: Send,
        B::Error: Into<BoxError>,
    {
        let Established {
            io,
            connected,
            config,
            ..
        } = established.await?;

        let (_, builder) = config.proto.as_ref();
        let builder = builder.clone();
        let builder = match &config.http2_options {
            Some(options) => builder.options(options.clone()),
            None => builder,
        };
        drop(config);
        let (mut tx, connection) = builder.handshake(io).await?;
        exec.execute(async move {
            if let Err(_error) = connection.await {
                debug!("client connection error: {_error}");
            }
        });
        tx.ready().await?;

        Ok(Self {
            tx,
            conn_info: connected,
            state: Arc::new(ConnectionState::new(clock_now(&timer))),
            timer,
        })
    }

    /// Returns metadata for the underlying transport.
    pub fn conn_info(&self) -> &Connected {
        &self.conn_info
    }

    /// Returns whether the protocol sender is immediately ready.
    pub fn is_ready(&self) -> bool {
        self.tx.is_ready()
    }

    /// Returns whether the protocol sender has closed.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Marks the shared sender checked out until response headers are returned.
    pub fn begin_checkout(&self) {
        self.state.acquire();
    }

    /// Ends response-header checkout and records when its count reaches zero.
    pub fn finish_checkout(&self) {
        let _ = self.state.release(clock_now(&self.timer));
    }

    /// Returns whether no response-header checkout currently uses this sender.
    pub fn is_idle(&self) -> bool {
        self.state.is_idle()
    }

    /// Returns whether the shared sender is healthy and reusable.
    pub fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        // TODO(task 9): Replace checkout-only idleness with a full-stream lease
        // after wreq-proto can observe both request and response endpoints,
        // including HTTP/2 extended CONNECT. Peer max-stream counts alone do
        // not expose local occupancy: https://github.com/hyperium/hyper/issues/3623
        !self.conn_info.poisoned()
            && !self.tx.is_closed()
            && (!self.is_idle() || !is_expired(self.state.idle_at(), now, timeout))
    }
}

impl<B> Service<Request<B>> for Connection<B>
where
    B: Body + Send + 'static,
{
    type Response = Response<Incoming>;
    type Error = SendError<B>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        let ready = self
            .tx
            .poll_ready(cx)
            .map_err(|error| SendError::Request(Error::closed(error)));
        if matches!(ready, Poll::Ready(Err(_))) {
            self.conn_info.poison();
        }
        ready
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        Box::pin(self.tx.try_send_request(req).map_err(SendError::protocol))
    }
}
