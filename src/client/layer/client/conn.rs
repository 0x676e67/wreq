//! Adapts established transports into protocol request senders.
//!
//! [`Http1Layer`] and [`Http2Layer`] place protocol handshakes behind Tower
//! services. The pool can therefore compose connection making, protocol
//! negotiation, and reuse without owning handshake state machines itself.
//!
//! A successful handshake starts the protocol driver and returns a sender with
//! the connection metadata needed by request middleware and pool health checks.

use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{self, Poll, ready},
    time::{Duration, Instant},
};

use futures_util::{TryFutureExt, future::BoxFuture};
use http::{Request, Response};
use http_body::Body;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Layer, Service, ServiceBuilder};
use wreq_proto::{
    body::Incoming,
    conn::{self as proto, TrySendError as ConnTrySendError},
    rt::{Executor as _, Timer as _},
};

use super::{
    Error, ErrorKind,
    pool::{Started, Ver},
    service::{Http1RequestTarget, SetHost},
};
use crate::{
    conn::Connected,
    rt::{Executor, Timer},
    sync::Mutex,
};

/// Physical transport and request-specific protocol configuration.
///
/// Connection making creates this value before protocol negotiation. The
/// selected handshake consumes it exactly once and transfers the transport to
/// the resulting protocol driver.
pub(super) struct Established<T> {
    /// Connected transport stream.
    io: T,

    /// Metadata supplied by the connector.
    connected: Connected,

    /// Requested protocol mode.
    version: Ver,

    /// HTTP/1 configuration supplied by this connection attempt.
    h1_builder: proto::http1::Builder,

    /// HTTP/2 configuration supplied by this connection attempt.
    h2_builder: proto::http2::Builder<Executor>,

    /// Time the transport became available for handshake.
    idle_at: Instant,
}

/// Reusable HTTP/1 sender and its physical connection metadata.
///
/// HTTP/1 permits one active checkout. The pool moves this value into a request
/// and receives it back after the response releases the checkout.
pub(super) struct Http1Client<B> {
    /// Metadata and poisoning state for the connection.
    conn_info: Connected,

    /// HTTP/1 request sender, uniquely checked out.
    tx: SetHost<Http1RequestTarget<Http1Sender<B>>>,

    /// Last time the sender became idle.
    idle_at: Instant,

    /// Clock used for idle timestamps.
    timer: Timer,
}

/// Cloneable HTTP/2 sender and its shared connection metadata.
///
/// The pool singleton stores one instance and gives each checkout a sender
/// clone. Protocol stream availability remains owned by wreq-proto; the local
/// state records sender checkout only and is not an active-stream count.
pub(super) struct Http2Client<B> {
    /// Metadata and poisoning state for the connection.
    conn_info: Connected,

    /// Cloneable multiplexed request sender.
    tx: proto::http2::SendRequest<B>,

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

/// Error returned while preparing or dispatching a protocol request.
///
/// Preparation failures originate in the HTTP/1 request middleware and never
/// carry a request for retry. Protocol failures preserve wreq-proto's optional
/// unsent request so the outer client can retry only when encoding did not
/// begin.
pub enum SendError<B> {
    /// Request middleware rejected the request before protocol dispatch.
    Request(Error),
    /// The protocol dispatcher failed and may return the unsent request.
    Protocol(ConnTrySendError<Request<B>>),
}

/// Adapts the HTTP/1 protocol sender to Tower's [`Service`] interface.
///
/// wreq-proto currently returns an opaque response future. This adapter boxes
/// that future so the HTTP/1 middleware chain can compose with it without
/// exposing protocol internals to the pool.
struct Http1Sender<B> {
    /// Raw protocol dispatcher created by the HTTP/1 handshake.
    inner: proto::http1::SendRequest<B>,
}

/// Layers HTTP/1 handshaking over a transport-producing service.
///
/// The resulting service waits for the physical connector, performs the
/// handshake, installs HTTP/1 request middleware, and returns a cacheable
/// [`Http1Client`].
pub(super) struct Http1Layer<B> {
    /// Runtime used by the protocol driver.
    exec: Executor,

    /// Clock used for idle timestamps.
    timer: Timer,

    /// Whether a missing `Host` field should be generated.
    set_host: bool,

    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// Layers HTTP/2 handshaking over an established-transport service.
///
/// Negotiation selects this layer only after it has inspected the established
/// transport. The resulting sender is cloneable and can be stored in the
/// pool's singleton service.
pub(super) struct Http2Layer<B> {
    /// Runtime used by the protocol driver.
    exec: Executor,

    /// Clock used for idle timestamps.
    timer: Timer,

    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// Connects a transport and performs an HTTP/1 handshake.
///
/// The inner service may include a reuse delay before connecting. Its
/// [`Started`] state is preserved so the HTTP/1 cache can decide whether a lost
/// reuse race should finish in the background.
pub(super) struct Http1Connect<S, B> {
    /// Service producing established transports.
    service: S,

    /// Runtime used by the protocol driver.
    exec: Executor,

    /// Clock used for idle timestamps.
    timer: Timer,

    /// Whether a missing `Host` field should be generated.
    set_host: bool,

    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// Performs an HTTP/2 handshake for a negotiated transport.
///
/// The inner service yields the transport chosen by negotiation. This service
/// consumes it once, starts the protocol driver, and returns the shared sender
/// stored by the singleton pool.
pub(super) struct Http2Connect<S, B> {
    /// Service yielding the inspected transport.
    service: S,

    /// Runtime used by the protocol driver.
    exec: Executor,

    /// Clock used for idle timestamps.
    timer: Timer,

    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// Connects a transport and then advances the HTTP/1 handshake.
///
/// The explicit state machine keeps the connector's [`Started`] signal visible
/// to the cache while the operation moves from transport creation to the boxed
/// protocol handshake future.
pub(super) struct Http1ConnectFuture<F, T, B> {
    /// Current connection or handshake phase.
    state: Http1ConnectState<F, B>,

    /// Runtime moved into the protocol driver.
    exec: Option<Executor>,

    /// Clock moved into the completed sender.
    timer: Option<Timer>,

    /// Whether a missing `Host` field should be generated.
    set_host: bool,

    /// Carries the transport type produced by the connection future.
    _io: PhantomData<fn(T)>,
}

/// Phases of an HTTP/1 connection service call.
enum Http1ConnectState<F, B> {
    /// Waiting for the physical transport.
    Connecting(F),
    /// Performing the protocol handshake.
    Handshaking(BoxFuture<'static, Result<Http1Client<B>, BoxError>>),
    /// Future has completed and owns no reusable state.
    Done,
}

// ===== impl SendError =====

impl<B> fmt::Debug for SendError<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => f.debug_tuple("Request").field(error).finish(),
            Self::Protocol(_) => f.write_str("Protocol(..)"),
        }
    }
}

impl<B> From<Error> for SendError<B> {
    fn from(error: Error) -> Self {
        Self::Request(error)
    }
}

impl<B> SendError<B> {
    /// Takes a request recovered before protocol encoding began.
    pub fn take_message(&mut self) -> Option<Request<B>> {
        match self {
            Self::Request(_) => None,
            Self::Protocol(error) => error.take_message(),
        }
    }

    /// Converts the failure into the requested client error category.
    pub fn into_client_error(self, kind: ErrorKind) -> Error {
        match self {
            Self::Request(error) => error,
            Self::Protocol(error) => Error::new(kind, error.into_error()),
        }
    }
}

// ===== impl Http1Sender =====

impl<B> Http1Sender<B> {
    /// Wraps a raw HTTP/1 protocol sender.
    fn new(inner: proto::http1::SendRequest<B>) -> Self {
        Self { inner }
    }

    /// Returns whether the protocol dispatcher currently wants a request.
    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
}

impl<B> Service<Request<B>> for Http1Sender<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Incoming>;
    type Error = SendError<B>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|error| SendError::Request(Error::closed(error)))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        Box::pin(
            self.inner
                .try_send_request(req)
                .map_err(SendError::Protocol),
        )
    }
}

// ===== impl Established =====

impl<T> Established<T> {
    /// Creates the protocol-neutral output of a physical connector.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        io: T,
        connected: Connected,
        version: Ver,
        h1_builder: proto::http1::Builder,
        h2_builder: proto::http2::Builder<Executor>,
        idle_at: Instant,
    ) -> Self {
        Self {
            io,
            connected,
            version,
            h1_builder,
            h2_builder,
            idle_at,
        }
    }

    /// Returns when this transport became available for protocol selection.
    pub(super) fn idle_at(&self) -> Instant {
        self.idle_at
    }

    /// Chooses HTTP/2 when requested explicitly or negotiated by the transport.
    pub(super) fn should_use_http2(&self) -> bool {
        self.version == Ver::Http2
            || (self.version != Ver::Http1 && self.connected.is_negotiated_h2())
    }
}

// ===== impl Http1Layer =====

impl<B> Http1Layer<B> {
    /// Creates an HTTP/1 handshake layer for pooled connections.
    pub(super) fn new(exec: Executor, timer: Timer, set_host: bool) -> Self {
        Self {
            exec,
            timer,
            set_host,
            _body: PhantomData,
        }
    }
}

impl<B> Clone for Http1Layer<B> {
    fn clone(&self) -> Self {
        Self::new(self.exec.clone(), self.timer.clone(), self.set_host)
    }
}

impl<S, B> Layer<S> for Http1Layer<B> {
    type Service = Http1Connect<S, B>;

    fn layer(&self, service: S) -> Self::Service {
        Http1Connect {
            service,
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            set_host: self.set_host,
            _body: PhantomData,
        }
    }
}

// ===== impl Http2Layer =====

impl<B> Http2Layer<B> {
    /// Creates an HTTP/2 handshake layer for pooled connections.
    pub(super) fn new(exec: Executor, timer: Timer) -> Self {
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

// ===== impl Http1Connect =====

impl<S: Clone, B> Clone for Http1Connect<S, B> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            set_host: self.set_host,
            _body: PhantomData,
        }
    }
}

impl<S, T, B, Dst> Service<Dst> for Http1Connect<S, B>
where
    S: Service<Dst, Response = Established<T>, Error = BoxError> + Clone,
    S::Future: Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Http1Client<B>;
    type Error = BoxError;
    type Future = Http1ConnectFuture<S::Future, T, B>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, target: Dst) -> Self::Future {
        Http1ConnectFuture {
            state: Http1ConnectState::Connecting(self.service.call(target)),
            exec: Some(self.exec.clone()),
            timer: Some(self.timer.clone()),
            set_host: self.set_host,
            _io: PhantomData,
        }
    }
}

// ===== impl Http1ConnectFuture =====

impl<F, T, B> Future for Http1ConnectFuture<F, T, B>
where
    F: Future<Output = Result<Established<T>, BoxError>> + Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Output = Result<Http1Client<B>, BoxError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        loop {
            match &mut self.state {
                Http1ConnectState::Connecting(future) => {
                    let established = match ready!(Pin::new(future).poll(cx)) {
                        Ok(established) => established,
                        Err(error) => {
                            self.state = Http1ConnectState::Done;
                            return Poll::Ready(Err(error));
                        }
                    };
                    let Some(exec) = self.exec.take() else {
                        self.state = Http1ConnectState::Done;
                        return Poll::Ready(Err(HandshakeStateError.into()));
                    };
                    let Some(timer) = self.timer.take() else {
                        self.state = Http1ConnectState::Done;
                        return Poll::Ready(Err(HandshakeStateError.into()));
                    };
                    self.state = Http1ConnectState::Handshaking(Box::pin(establish_http1(
                        established,
                        exec,
                        timer,
                        self.set_host,
                    )));
                }
                Http1ConnectState::Handshaking(future) => {
                    let result = ready!(future.as_mut().poll(cx));
                    self.state = Http1ConnectState::Done;
                    return Poll::Ready(result);
                }
                Http1ConnectState::Done => return Poll::Pending,
            }
        }
    }
}

impl<F, T, B> Started for Http1ConnectFuture<F, T, B>
where
    F: Future<Output = Result<Established<T>, BoxError>> + Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Returns whether connection or handshake work has started.
    fn started(&self) -> bool {
        match &self.state {
            Http1ConnectState::Connecting(future) => future.started(),
            Http1ConnectState::Handshaking(_) | Http1ConnectState::Done => true,
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

/// Handshakes an HTTP/1 transport and starts its connection driver.
async fn establish_http1<T, B>(
    established: Established<T>,
    exec: Executor,
    timer: Timer,
    set_host: bool,
) -> Result<Http1Client<B>, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let Established {
        io,
        connected,
        h1_builder,
        ..
    } = established;
    let (mut tx, connection) = h1_builder.handshake(io).await?;
    let (error_tx, error_rx) = tokio::sync::oneshot::channel();
    exec.execute(async move {
        if let Err(error) = connection.with_upgrades().await {
            debug!("client connection error: {error:?}");
            let _ = error_tx.send(error);
        }
    });

    match tx.ready().await {
        Ok(()) => drop(error_rx),
        Err(error) if error.is_closed() => match error_rx.await {
            Ok(connection_error) => return Err(connection_error.into()),
            Err(_) => return Err(error.into()),
        },
        Err(error) => return Err(error.into()),
    }

    let request_connected = connected.clone();
    let request_service = ServiceBuilder::new()
        .layer_fn(move |inner| SetHost::new(inner, set_host))
        .layer_fn(move |inner| Http1RequestTarget::new(inner, request_connected.clone()))
        .service(Http1Sender::new(tx));
    Ok(Http1Client {
        conn_info: connected,
        tx: request_service,
        idle_at: clock_now(&timer),
        timer,
    })
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

// ===== impl Http1Client =====

impl<B> Http1Client<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Polls whether the HTTP/1 sender can accept its next request.
    pub(super) fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        self.tx
            .poll_ready(cx)
            .map_err(|error| error.into_client_error(ErrorKind::ChannelClosed))
    }

    /// Returns metadata for the underlying transport.
    pub(super) fn conn_info(&self) -> &Connected {
        &self.conn_info
    }

    /// Returns whether the protocol sender is immediately ready.
    pub(super) fn is_ready(&self) -> bool {
        self.tx.inner().inner().is_ready()
    }

    /// Sends a request without an additional readiness transition.
    pub(super) fn try_send_request(
        &mut self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, SendError<B>>> {
        self.tx.call(req)
    }

    /// Records when the exclusive sender becomes idle.
    pub(super) fn mark_idle(&mut self) {
        self.idle_at = clock_now(&self.timer);
    }

    /// Returns whether the exclusive sender can safely re-enter the cache.
    pub(super) fn is_open(&self) -> bool {
        !self.conn_info.poisoned() && self.tx.inner().inner().is_ready()
    }

    /// Returns whether the sender is healthy and within its idle timeout.
    pub(super) fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        self.is_open() && !is_expired(self.idle_at, now, timeout)
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
    /// Polls whether the HTTP/2 sender can open another request stream.
    pub(super) fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        self.tx.poll_ready(cx).map_err(Error::closed)
    }

    /// Returns metadata for the underlying transport.
    pub(super) fn conn_info(&self) -> &Connected {
        &self.conn_info
    }

    /// Returns whether the protocol sender is immediately ready.
    pub(super) fn is_ready(&self) -> bool {
        self.tx.is_ready()
    }

    /// Returns whether the protocol sender has closed.
    pub(super) fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Marks the shared connection unusable for later checkouts.
    pub(super) fn poison(&self) {
        self.conn_info.poison();
    }

    /// Sends a request without an additional readiness transition.
    pub(super) fn try_send_request(
        &mut self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, SendError<B>>> {
        self.tx.try_send_request(req).map_err(SendError::Protocol)
    }

    /// Marks the shared sender checked out until response headers are returned.
    pub(super) fn begin_checkout(&self) {
        self.state.acquire();
    }

    /// Ends response-header checkout and records when its count reaches zero.
    pub(super) fn finish_checkout(&self) {
        let _ = self.state.release(clock_now(&self.timer));
    }

    /// Returns whether no response-header checkout currently uses this sender.
    pub(super) fn is_idle(&self) -> bool {
        self.state.is_idle()
    }

    /// Returns whether the shared sender is healthy and reusable.
    pub(super) fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        // TODO(task 9): Replace checkout-only idleness with a full-stream lease
        // after wreq-proto can observe both request and response endpoints,
        // including HTTP/2 extended CONNECT. Peer max-stream counts alone do
        // not expose local occupancy: https://github.com/hyperium/hyper/issues/3623
        !self.conn_info.poisoned()
            && !self.tx.is_closed()
            && (!self.is_idle() || !is_expired(self.state.idle_at(), now, timeout))
    }
}

/// Returns whether an idle timestamp exceeds the configured timeout.
fn is_expired(idle_at: Instant, now: Instant, timeout: Option<Duration>) -> bool {
    timeout.is_some_and(|timeout| now.saturating_duration_since(idle_at) > timeout)
}

/// Reads the configured runtime clock, falling back to the system clock.
fn clock_now(timer: &Timer) -> Instant {
    if timer.is_empty() {
        Instant::now()
    } else {
        timer.now()
    }
}

/// Reports a consumed HTTP/1 handshake state.
#[derive(Debug)]
struct HandshakeStateError;

// ===== impl HandshakeStateError =====

impl fmt::Display for HandshakeStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HTTP/1 handshake state was already consumed")
    }
}

impl std::error::Error for HandshakeStateError {}
