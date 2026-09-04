//! HTTP/2 handshake, sender, and pooled connection lifecycle.

use std::{
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
use wreq_proto::{body::Incoming, rt::Executor as _};

use super::{Established, SendError, clock_now, is_expired};
use crate::{
    client::error::Error,
    conn::Connected,
    rt::{Executor, Timer},
    sync::Mutex,
};

/// Cloneable HTTP/2 sender and its shared connection metadata.
///
/// The pool singleton stores one instance and gives each checkout a sender
/// clone. Protocol stream availability remains owned by wreq-proto; the local
/// state records sender checkout only and is not an active-stream count.
pub struct Http2Client<B> {
    /// Metadata and poisoning state for the connection.
    conn_info: Connected,

    /// Cloneable multiplexed request sender.
    tx: wreq_proto::conn::http2::SendRequest<B>,

    /// Checkout count and idle timestamp shared by sender clones.
    state: Arc<Http2State>,

    /// Clock used for idle timestamps.
    timer: Timer,
}

/// Shared checkout state for one HTTP/2 physical connection.
///
/// This currently covers sender checkout through response headers. A complete
/// stream lease must also follow the accepted request body, response body, and
/// extended `CONNECT` upgrade until both stream directions terminate. The
/// lifecycle is specified by smithy-rs's latest pool design:
/// <https://github.com/smithy-lang/smithy-rs/blob/connection-pool-main/rust-runtime/aws-smithy-http-client/docs/design/connection-pool.md>
struct Http2State {
    /// Number of `Pooled` handles currently using the sender.
    checkouts: AtomicUsize,

    /// Time when the final checkout was released.
    idle_at: Mutex<Instant>,
}

/// Layers HTTP/2 handshaking over an established-transport service.
///
/// Negotiation selects this layer only after it has inspected the established
/// transport. The resulting sender is cloneable and can be stored in the
/// pool's singleton service.
pub struct Http2Layer<B> {
    /// Runtime used by the protocol driver.
    exec: Executor,

    /// Clock used for idle timestamps.
    timer: Timer,

    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// Performs an HTTP/2 handshake for a negotiated transport.
///
/// The inner service yields the transport chosen by negotiation. This service
/// consumes it once, starts the protocol driver, and returns the shared sender
/// stored by the singleton pool.
pub struct Http2Connect<S, B> {
    /// Service yielding the inspected transport.
    service: S,

    /// Runtime used by the protocol driver.
    exec: Executor,

    /// Clock used for idle timestamps.
    timer: Timer,

    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

// ===== impl Http2Layer =====

impl<B> Http2Layer<B> {
    /// Creates an HTTP/2 handshake layer for pooled connections.
    pub fn new(exec: Executor, timer: Timer) -> Self {
        Self {
            exec,
            timer,
            _body: PhantomData,
        }
    }
}

impl<B> Clone for Http2Layer<B> {
    fn clone(&self) -> Self {
        Self::new(self.exec.clone(), self.timer.clone())
    }
}

impl<S, B> Layer<S> for Http2Layer<B> {
    type Service = Http2Connect<S, B>;

    fn layer(&self, service: S) -> Self::Service {
        Http2Connect {
            service,
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            _body: PhantomData,
        }
    }
}

// ===== impl Http2Connect =====

impl<S: Clone, B> Clone for Http2Connect<S, B> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            _body: PhantomData,
        }
    }
}

impl<S, T, B, Dst> Service<Dst> for Http2Connect<S, B>
where
    S: Service<Dst, Response = Established<T>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Http2Client<B>;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, target: Dst) -> Self::Future {
        let future = self.service.call(target);
        let exec = self.exec.clone();
        let timer = self.timer.clone();
        Box::pin(async move { establish_http2(future.await?, exec, timer).await })
    }
}

// ===== impl Http2State =====

impl Http2State {
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
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
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

// ===== impl Http2Client =====

impl<B> Clone for Http2Client<B> {
    fn clone(&self) -> Self {
        Self {
            conn_info: self.conn_info.clone(),
            tx: self.tx.clone(),
            state: self.state.clone(),
            timer: self.timer.clone(),
        }
    }
}

impl<B> Http2Client<B>
where
    B: Body + 'static,
{
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

impl<B> Service<Request<B>> for Http2Client<B>
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

/// Handshakes an HTTP/2 transport and starts its connection driver.
async fn establish_http2<T, B>(
    established: Established<T>,
    exec: Executor,
    timer: Timer,
) -> Result<Http2Client<B>, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let Established {
        io,
        connected,
        h2_builder,
        ..
    } = established;
    let (mut tx, connection) = h2_builder.handshake(io).await?;
    exec.execute(async move {
        if let Err(_error) = connection.await {
            debug!("client connection error: {_error}");
        }
    });
    tx.ready().await?;

    Ok(Http2Client {
        conn_info: connected,
        tx,
        state: Arc::new(Http2State::new(clock_now(&timer))),
        timer,
    })
}
