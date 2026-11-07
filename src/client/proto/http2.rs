//! HTTP/2 handshake, sender, and pooled connection lifecycle.

use std::{
    future::Future,
    marker::PhantomData,
    sync::Arc,
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures_util::{TryFutureExt, future::BoxFuture};
use http::{Request, Response};
use http_body::Body;
use netty::{body::Incoming, conn};
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Layer, Service};

use super::{ConnectionState, Established, SendError, is_expired};
use crate::{
    client::error::Error,
    conn::Connected,
    rt::{DynRuntime, Timer as _},
};

/// Cloneable request-side handle for one HTTP/2 connection.
///
/// The pool singleton stores one instance and gives each checkout a sender
/// clone. Protocol stream availability remains owned by netty; the local
/// state records sender checkout only and is not an active-stream count.
pub struct Connection<B> {
    tx: conn::http2::SendRequest<B>,
    state: Arc<ConnectionState>,
    connected: Connected,
    runtime: DynRuntime,
}

/// Layers HTTP/2 handshaking over an established-transport service.
///
/// Fixed HTTP/2 wraps the connector directly; automatic mode supplies a
/// transport selected by negotiation. Both return a cloneable sender for the
/// pool's singleton service.
#[derive(Clone)]
pub struct ConnectLayer<B> {
    runtime: DynRuntime,
    _body: PhantomData<fn(B)>,
}

/// Performs an HTTP/2 handshake for a transport-producing service.
///
/// The inner service either connects directly or yields a negotiated transport.
/// This service consumes it once, starts the protocol driver, and returns the
/// shared sender stored by the singleton pool.
pub struct Connect<S, B> {
    service: S,
    runtime: DynRuntime,
    _body: PhantomData<fn(B)>,
}

// ===== impl ConnectLayer =====

impl<B> ConnectLayer<B> {
    /// Creates an HTTP/2 handshake layer for pooled connections.
    pub fn new(runtime: DynRuntime) -> Self {
        Self {
            runtime,
            _body: PhantomData,
        }
    }
}

impl<S, B> Layer<S> for ConnectLayer<B> {
    type Service = Connect<S, B>;

    fn layer(&self, service: S) -> Self::Service {
        Connect {
            service,
            runtime: self.runtime.clone(),
            _body: self._body,
        }
    }
}

// ===== impl Connect =====

impl<S: Clone, B> Clone for Connect<S, B> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            runtime: self.runtime.clone(),
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
        let runtime = self.runtime.clone();
        Box::pin(Connection::handshake(future, runtime))
    }
}

// ===== impl Connection =====

impl<B> Clone for Connection<B> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            connected: self.connected.clone(),
            state: self.state.clone(),
            runtime: self.runtime.clone(),
        }
    }
}

impl<B> Connection<B>
where
    B: Body + 'static,
{
    /// Awaits a transport and returns a handshaken HTTP/2 sender.
    /// Starts the connection driver before waiting for sender readiness.
    async fn handshake<F, T>(established: F, runtime: DynRuntime) -> Result<Self, BoxError>
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

        let builder = config
            .req
            .config_override::<netty::http2::Http2Options>()
            .map_or_else(
                || config.proto.http2.clone(),
                |options| config.proto.http2.clone().options(options.clone()),
            );
        drop(config);

        let (mut tx, connection) = builder.handshake(io).await?;
        runtime.execute(Box::pin(async move {
            if let Err(_error) = connection.await {
                debug!("client connection error: {_error}");
            }
        }));
        tx.ready().await?;

        Ok(Self {
            tx,
            connected,
            state: Arc::new(ConnectionState::new(runtime.now())),
            runtime,
        })
    }

    /// Returns metadata for the underlying transport.
    pub fn connected(&self) -> &Connected {
        &self.connected
    }

    /// Returns whether the protocol sender is immediately ready.
    pub fn is_ready(&self) -> bool {
        self.tx.is_ready()
    }

    /// Returns whether the protocol sender has closed.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Returns whether the peer enabled extended CONNECT, or `None` before its SETTINGS.
    pub fn extended_connect(&self) -> Option<bool> {
        self.tx.is_extended_connect_protocol_enabled()
    }

    /// Marks the shared sender checked out until response headers are returned.
    pub fn begin_checkout(&self) {
        self.state.acquire();
    }

    /// Ends response-header checkout and records when its count reaches zero.
    pub fn finish_checkout(&self) {
        let _ = self.state.release(self.runtime.now());
    }

    /// Returns whether no response-header checkout currently uses this sender.
    pub fn is_idle(&self) -> bool {
        self.state.is_idle()
    }

    /// Returns whether the shared sender is healthy and reusable.
    pub fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        // TODO(task 9): Replace checkout-only idleness with a full-stream lease
        // after netty can observe both request and response endpoints,
        // including HTTP/2 extended CONNECT. Peer max-stream counts alone do
        // not expose local occupancy: https://github.com/hyperium/hyper/issues/3623
        !self.connected.poisoned()
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
            self.connected.poison();
        }
        ready
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        Box::pin(self.tx.try_send_request(req).map_err(SendError::protocol))
    }
}
