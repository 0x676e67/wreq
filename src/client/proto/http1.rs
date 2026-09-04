//! HTTP/1 handshake, sender, and pooled connection lifecycle.

use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{self, Poll, ready},
    time::{Duration, Instant},
};

use futures_util::{TryFutureExt, future::BoxFuture};
use http::{Request, Response};
use http_body::Body;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Layer, Service, ServiceBuilder};
use wreq_proto::{body::Incoming, rt::Executor as _};

use super::{Established, SendError, clock_now, is_expired};
use crate::{
    client::{
        error::Error,
        pool::Started,
        svc::{Http1RequestTarget, SetHost},
    },
    conn::Connected,
    rt::{Executor, Timer},
};

/// Reusable HTTP/1 sender and its physical connection metadata.
///
/// HTTP/1 permits one active checkout. The pool moves this value into a request
/// and receives it back after the response releases the checkout.
pub struct Http1Client<B> {
    /// Metadata and poisoning state for the connection.
    conn_info: Connected,

    /// HTTP/1 request sender, uniquely checked out.
    tx: SetHost<Http1RequestTarget<Http1Sender<B>>>,

    /// Last time the sender became idle.
    idle_at: Instant,

    /// Clock used for idle timestamps.
    timer: Timer,
}

/// Adapts the HTTP/1 protocol sender to Tower's [`Service`] interface.
///
/// wreq-proto currently returns an opaque response future. This adapter boxes
/// that future so the HTTP/1 middleware chain can compose with it without
/// exposing protocol internals to the pool.
pub struct Http1Sender<B> {
    /// Raw protocol dispatcher created by the HTTP/1 handshake.
    inner: wreq_proto::conn::http1::SendRequest<B>,
}

/// Layers HTTP/1 handshaking over a transport-producing service.
///
/// The resulting service waits for the physical connector, performs the
/// handshake, installs HTTP/1 request middleware, and returns a cacheable
/// [`Http1Client`].
pub struct Http1Layer<B> {
    /// Runtime used by the protocol driver.
    exec: Executor,

    /// Clock used for idle timestamps.
    timer: Timer,

    /// Whether a missing `Host` field should be generated.
    set_host: bool,

    /// Carries the request-body type without owning a body.
    _body: PhantomData<fn(B)>,
}

/// Connects a transport and performs an HTTP/1 handshake.
///
/// The inner service may include a reuse delay before connecting. Its
/// [`Started`] state is preserved so the HTTP/1 cache can decide whether a lost
/// reuse race should finish in the background.
pub struct Http1Connect<S, B> {
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

/// Connects a transport and then advances the HTTP/1 handshake.
///
/// The explicit state machine keeps the connector's [`Started`] signal visible
/// to the cache while the operation moves from transport creation to the boxed
/// protocol handshake future.
pub struct Http1ConnectFuture<F, T, B> {
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

/// Reports a consumed HTTP/1 handshake state.
#[derive(Debug)]
struct HandshakeStateError;

// ===== impl Http1Sender =====

impl<B> Http1Sender<B> {
    /// Wraps a raw HTTP/1 protocol sender.
    fn new(inner: wreq_proto::conn::http1::SendRequest<B>) -> Self {
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
                .map_err(SendError::protocol),
        )
    }
}

// ===== impl Http1Layer =====

impl<B> Http1Layer<B> {
    /// Creates an HTTP/1 handshake layer for pooled connections.
    pub fn new(exec: Executor, timer: Timer, set_host: bool) -> Self {
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

// ===== impl Http1Client =====

impl<B> Http1Client<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Returns metadata for the underlying transport.
    pub fn conn_info(&self) -> &Connected {
        &self.conn_info
    }

    /// Returns whether the protocol sender is immediately ready.
    pub fn is_ready(&self) -> bool {
        self.tx.inner().inner().is_ready()
    }

    /// Records when the exclusive sender becomes idle.
    pub fn mark_idle(&mut self) {
        self.idle_at = clock_now(&self.timer);
    }

    /// Returns whether the exclusive sender can safely re-enter the cache.
    pub fn is_open(&self) -> bool {
        !self.conn_info.poisoned() && self.tx.inner().inner().is_ready()
    }

    /// Returns whether the sender is healthy and within its idle timeout.
    pub fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        self.is_open() && !is_expired(self.idle_at, now, timeout)
    }
}

impl<B> Service<Request<B>> for Http1Client<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Incoming>;
    type Error = SendError<B>;
    type Future = <SetHost<Http1RequestTarget<Http1Sender<B>>> as Service<Request<B>>>::Future;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.tx.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        self.tx.call(req)
    }
}

// ===== impl HandshakeStateError =====

impl fmt::Display for HandshakeStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HTTP/1 handshake state was already consumed")
    }
}

impl std::error::Error for HandshakeStateError {}

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
