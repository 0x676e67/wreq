//! HTTP/1 handshake, request preparation, sender, and pooled connection lifecycle.
//!
//! [`Connection`] generates `Host` from the absolute URI before converting the
//! request target for a direct connection, forward proxy, or `CONNECT` tunnel.
//! HTTP/1 request-target forms are defined by RFC 9112 section 3.2:
//! <https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2>

use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{self, Poll, ready},
    time::{Duration, Instant},
};

use futures_util::{
    TryFutureExt,
    future::{self, BoxFuture, Either, Ready},
};
use http::{
    HeaderValue, Method, Request, Response, Uri,
    header::{HOST, PROXY_AUTHORIZATION},
};
use http_body::Body;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::oneshot,
};
use tower::{BoxError, Layer, Service};
use wreq_proto::{body::Incoming, conn, rt::Executor as _};

use super::{Established, SendError, clock_now, is_expired};
use crate::{
    client::{
        error::{Error, ErrorKind},
        pool::Started,
    },
    conn::Connected,
    rt::{Executor, Timer},
};

/// Prepares and sends requests over one reusable HTTP/1 connection.
///
/// HTTP/1 permits one active checkout. Dispatch returns this sender only after
/// it becomes ready again; a busy sender is held by a readiness task.
pub struct Connection<B> {
    tx: conn::http1::SendRequest<B>,
    conn_info: Connected,
    set_host: bool,
    idle_at: Instant,
    timer: Timer,
}

/// Layers HTTP/1 handshaking over a transport-producing service.
///
/// The resulting service waits for the physical connector, performs the
/// handshake, and returns a cacheable [`Connection`].
#[derive(Clone)]
pub struct ConnectLayer<B> {
    set_host: bool,
    exec: Executor,
    timer: Timer,
    _body: PhantomData<fn(B)>,
}

/// Connects a transport and performs an HTTP/1 handshake.
///
/// The inner service may include a reuse delay before connecting. Its
/// [`Started`] state is preserved so the HTTP/1 cache can decide whether a lost
/// reuse race should finish in the background.
pub struct Connect<S, B> {
    service: S,
    set_host: bool,
    exec: Executor,
    timer: Timer,
    _body: PhantomData<fn(B)>,
}

/// Connects a transport and then advances the HTTP/1 handshake.
///
/// The explicit state machine keeps the connector's [`Started`] signal visible
/// to the cache while the operation moves from transport creation to the boxed
/// protocol handshake future.
pub struct ConnectFuture<F, T, B> {
    state: ConnectState<F, B>,
    set_host: bool,
    exec: Option<Executor>,
    timer: Option<Timer>,
    _io: PhantomData<fn(T)>,
}

/// Phases of an HTTP/1 connection service call.
enum ConnectState<F, B> {
    /// Waiting for the physical transport.
    Connecting(F),
    /// Performing the protocol handshake.
    Handshaking(BoxFuture<'static, Result<Connection<B>, BoxError>>),
    /// Future has completed and owns no reusable state.
    Done,
}

/// Reports a consumed HTTP/1 handshake state.
/// Returned if the connect future no longer owns its executor or timer.
/// Carries no transport; the failed future releases its connection state.
#[derive(Debug)]
struct HandshakeStateError;

// ===== impl ConnectLayer =====

impl<B> ConnectLayer<B> {
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

impl<S, B> Layer<S> for ConnectLayer<B> {
    type Service = Connect<S, B>;

    fn layer(&self, service: S) -> Self::Service {
        Connect {
            service,
            exec: self.exec.clone(),
            timer: self.timer.clone(),
            set_host: self.set_host,
            _body: PhantomData,
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
            set_host: self.set_host,
            _body: PhantomData,
        }
    }
}

impl<S, T, B, Dst> Service<Dst> for Connect<S, B>
where
    S: Service<Dst, Response = Established<T>, Error = BoxError> + Clone,
    S::Future: Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Connection<B>;
    type Error = BoxError;
    type Future = ConnectFuture<S::Future, T, B>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, target: Dst) -> Self::Future {
        ConnectFuture {
            state: ConnectState::Connecting(self.service.call(target)),
            exec: Some(self.exec.clone()),
            timer: Some(self.timer.clone()),
            set_host: self.set_host,
            _io: PhantomData,
        }
    }
}

// ===== impl ConnectFuture =====

impl<F, T, B> Future for ConnectFuture<F, T, B>
where
    F: Future<Output = Result<Established<T>, BoxError>> + Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Output = Result<Connection<B>, BoxError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        loop {
            match &mut self.state {
                ConnectState::Connecting(future) => {
                    let established = match ready!(Pin::new(future).poll(cx)) {
                        Ok(established) => established,
                        Err(error) => {
                            self.state = ConnectState::Done;
                            return Poll::Ready(Err(error));
                        }
                    };
                    let Some(exec) = self.exec.take() else {
                        self.state = ConnectState::Done;
                        return Poll::Ready(Err(HandshakeStateError.into()));
                    };
                    let Some(timer) = self.timer.take() else {
                        self.state = ConnectState::Done;
                        return Poll::Ready(Err(HandshakeStateError.into()));
                    };

                    self.state = ConnectState::Handshaking(Box::pin(Connection::handshake(
                        established,
                        exec,
                        timer,
                        self.set_host,
                    )));
                }
                ConnectState::Handshaking(future) => {
                    let result = ready!(future.as_mut().poll(cx));
                    self.state = ConnectState::Done;
                    return Poll::Ready(result);
                }
                ConnectState::Done => return Poll::Pending,
            }
        }
    }
}

impl<F, T, B> Started for ConnectFuture<F, T, B>
where
    F: Future<Output = Result<Established<T>, BoxError>> + Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    fn started(&self) -> bool {
        match &self.state {
            ConnectState::Connecting(future) => future.started(),
            ConnectState::Handshaking(_) | ConnectState::Done => true,
        }
    }
}

// ===== impl Connection =====

impl<B> Connection<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Handshakes a transport and returns a ready HTTP/1 sender.
    /// Starts the driver before waiting for readiness, preserving its error if
    /// the sender closes during setup.
    async fn handshake<T>(
        established: Established<T>,
        exec: Executor,
        timer: Timer,
        set_host: bool,
    ) -> Result<Self, BoxError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: Unpin,
    {
        let Established {
            io,
            connected,
            config,
            ..
        } = established;

        let (builder, _) = config.proto.as_ref();
        let builder = builder.clone();
        let builder = match config
            .connect_context
            .extensions()
            .get::<wreq_proto::http1::Http1Options>()
        {
            Some(options) => builder.options(options.clone()),
            None => builder,
        };
        drop(config);
        let (mut tx, connection) = builder.handshake(io).await?;
        let (error_tx, error_rx) = oneshot::channel();
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

        Ok(Self {
            tx,
            conn_info: connected,
            set_host,
            idle_at: clock_now(&timer),
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

    /// Records when the exclusive sender becomes idle.
    pub fn mark_idle(&mut self) {
        self.idle_at = clock_now(&self.timer);
    }

    /// Returns whether the exclusive sender can safely re-enter the cache.
    pub fn is_open(&self) -> bool {
        !self.conn_info().poisoned() && self.is_ready()
    }

    /// Returns whether the sender is healthy and within its idle timeout.
    pub fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        self.is_open() && !is_expired(self.idle_at, now, timeout)
    }
}

impl<B> Service<Request<B>> for Connection<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Incoming>;
    type Error = SendError<B>;
    type Future = Either<
        BoxFuture<'static, Result<Self::Response, Self::Error>>,
        Ready<Result<Self::Response, Self::Error>>,
    >;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.tx
            .poll_ready(cx)
            .map_err(|error| SendError::Request(Error::closed(error)))
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        // Host must be derived before the absolute URI becomes a wire target.
        if self.set_host
            && !req.headers().contains_key(HOST)
            && let Some(host) = generate_host_header(req.uri())
        {
            req.headers_mut().insert(HOST, host);
        }

        let result = if req.method() == Method::CONNECT {
            authority_form(req.uri_mut())
        } else if self.conn_info.is_proxied() {
            if let Some(auth) = self.conn_info.proxy_auth() {
                req.headers_mut()
                    .entry(PROXY_AUTHORIZATION)
                    .or_insert_with(|| auth.clone());
            }
            if let Some(headers) = self.conn_info.proxy_headers() {
                crate::util::replace_headers(req.headers_mut(), headers.clone());
            }
            Ok(())
        } else {
            origin_form(req.uri_mut())
        };

        match result {
            Ok(()) => Either::Left(Box::pin(
                self.tx.try_send_request(req).map_err(SendError::protocol),
            )),
            Err(error) => Either::Right(future::err(error.into())),
        }
    }
}

// ===== impl HandshakeStateError =====

impl fmt::Display for HandshakeStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HTTP/1 handshake state was already consumed")
    }
}

impl std::error::Error for HandshakeStateError {}

/// Converts an absolute URI to origin-form while preserving path and query.
fn origin_form(uri: &mut Uri) -> Result<(), Error> {
    let target = match uri.path_and_query() {
        Some(path) if path.as_str() != "/" => {
            let mut parts = ::http::uri::Parts::default();
            parts.path_and_query = Some(path.clone());
            Uri::from_parts(parts).map_err(|error| Error::new(ErrorKind::SendRequest, error))?
        }
        _ => Uri::default(),
    };
    *uri = target;
    Ok(())
}

/// Converts an absolute URI to authority-form for an HTTP `CONNECT` request.
fn authority_form(uri: &mut Uri) -> Result<(), Error> {
    if let Some(path) = uri.path_and_query()
        && path != "/"
    {
        warn!("HTTP/1.1 CONNECT request stripping path: {:?}", path);
    }

    let Some(authority) = uri.authority() else {
        return Err(Error::from_kind(ErrorKind::UserAbsoluteUriRequired));
    };

    let mut parts = ::http::uri::Parts::default();
    parts.authority = Some(authority.clone());
    *uri = Uri::from_parts(parts).map_err(|error| Error::new(ErrorKind::SendRequest, error))?;
    Ok(())
}

/// Creates a `Host` value from the URI authority without an intermediate string.
fn generate_host_header(uri: &Uri) -> Option<HeaderValue> {
    let host = uri.host()?;
    let port = match (uri.port().map(|port| port.as_u16()), is_scheme_secure(uri)) {
        (Some(443), true) | (Some(80), false) => None,
        _ => uri.port(),
    };

    let value = if port.is_some() {
        let authority = uri.authority()?.as_str();
        authority
            .rsplit_once('@')
            .map_or(authority, |(_, host_and_port)| host_and_port)
    } else {
        host
    };

    HeaderValue::from_str(value).ok()
}

/// Returns whether the URI scheme uses a secure transport by default.
fn is_scheme_secure(uri: &Uri) -> bool {
    matches!(uri.scheme_str(), Some("https" | "wss"))
}
