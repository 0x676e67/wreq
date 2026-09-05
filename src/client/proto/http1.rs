//! HTTP/1 handshake, request preparation, sender, and pooled connection lifecycle.
//!
//! [`SetHost`] runs before [`Http1RequestTarget`] so `Host` is generated from
//! the absolute URI before the selected connection determines its wire form.
//! HTTP/1 request-target forms are defined by RFC 9112 section 3.2:
//! <https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2>

use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{self, Context, Poll, ready},
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

/// Reusable HTTP/1 sender and its physical connection metadata.
///
/// HTTP/1 permits one active checkout. The pool moves this value into a request
/// and receives it back after the response releases the checkout.
pub struct Http1Client<B> {
    conn_info: Connected,
    tx: SetHost<Http1RequestTarget<B>>,
    idle_at: Instant,
    timer: Timer,
}

/// Layers HTTP/1 handshaking over a transport-producing service.
///
/// The resulting service waits for the physical connector, performs the
/// handshake, installs HTTP/1 request middleware, and returns a cacheable
/// [`Http1Client`].
#[derive(Clone)]
pub struct Http1Layer<B> {
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
pub struct Http1Connect<S, B> {
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
pub struct Http1ConnectFuture<F, T, B> {
    state: Http1ConnectState<F, B>,
    set_host: bool,
    exec: Option<Executor>,
    timer: Option<Timer>,
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

/// Ensures an HTTP request has a `Host` field before protocol encoding.
///
/// The middleware can be disabled for callers that manage `Host` themselves.
/// It reads the absolute request URI before an inner target middleware converts
/// that URI to HTTP/1 origin-form or authority-form.
#[derive(Clone)]
pub struct SetHost<S> {
    inner: S,
    enabled: bool,
}

/// Prepares and sends requests over one established HTTP/1 connection.
///
/// Direct requests use origin-form, `CONNECT` uses authority-form, and forward
/// proxy requests retain absolute-form. Proxy authorization and configured
/// proxy headers are applied before the owned protocol sender encodes a request.
pub struct Http1RequestTarget<B> {
    inner: conn::http1::SendRequest<B>,
    connected: Connected,
}

// ===== impl SetHost =====

impl<S> SetHost<S> {
    /// Wraps a request service with optional `Host` generation.
    pub fn new(inner: S, enabled: bool) -> Self {
        Self { inner, enabled }
    }

    /// Borrows the wrapped request service.
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S, B> Service<Request<B>> for SetHost<S>
where
    S: Service<Request<B>>,
    S::Error: From<Error>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let result = if self.enabled && !req.headers().contains_key(HOST) {
            generate_host_header(req.uri()).map(|host| {
                req.headers_mut().insert(HOST, host);
            })
        } else {
            Ok(())
        };

        match result {
            Ok(()) => Either::Left(self.inner.call(req)),
            Err(error) => Either::Right(future::err(error.into())),
        }
    }
}

// ===== impl Http1RequestTarget =====

impl<B> Http1RequestTarget<B> {
    /// Wraps a protocol sender with connection-specific target handling.
    pub fn new(inner: conn::http1::SendRequest<B>, connected: Connected) -> Self {
        Self { inner, connected }
    }

    /// Borrows the wrapped protocol sender.
    pub fn inner(&self) -> &conn::http1::SendRequest<B> {
        &self.inner
    }
}

impl<B> Service<Request<B>> for Http1RequestTarget<B>
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

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|error| SendError::Request(Error::closed(error)))
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let result = if req.method() == Method::CONNECT {
            authority_form(req.uri_mut())
        } else if self.connected.is_proxied() {
            if let Some(auth) = self.connected.proxy_auth() {
                req.headers_mut()
                    .entry(PROXY_AUTHORIZATION)
                    .or_insert_with(|| auth.clone());
            }
            if let Some(headers) = self.connected.proxy_headers() {
                crate::util::replace_headers(req.headers_mut(), headers.clone());
            }
            Ok(())
        } else {
            origin_form(req.uri_mut())
        };

        match result {
            Ok(()) => Either::Left(Box::pin(
                self.inner
                    .try_send_request(req)
                    .map_err(SendError::protocol),
            )),
            Err(error) => Either::Right(future::err(error.into())),
        }
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

                    self.state = Http1ConnectState::Handshaking(Box::pin(Http1Client::handshake(
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
            h1_builder,
            ..
        } = established;

        let (mut tx, connection) = h1_builder.handshake(io).await?;
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
            conn_info: connected.clone(),
            tx: SetHost::new(Http1RequestTarget::new(tx, connected), set_host),
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
    type Future = <SetHost<Http1RequestTarget<B>> as Service<Request<B>>>::Future;

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

    let Some(authority) = uri.authority().cloned() else {
        return Err(Error::from_kind(ErrorKind::UserAbsoluteUriRequired));
    };
    let mut parts = ::http::uri::Parts::default();
    parts.authority = Some(authority);
    *uri = Uri::from_parts(parts).map_err(|error| Error::new(ErrorKind::SendRequest, error))?;
    Ok(())
}

/// Creates the HTTP/1 `Host` value without an intermediate string allocation.
fn generate_host_header(uri: &Uri) -> Result<HeaderValue, Error> {
    let Some(host) = uri.host() else {
        return Err(Error::from_kind(ErrorKind::UserAbsoluteUriRequired));
    };
    let port = match (uri.port().map(|port| port.as_u16()), is_scheme_secure(uri)) {
        (Some(443), true) | (Some(80), false) => None,
        _ => uri.port(),
    };
    let value = if port.is_some() {
        let Some(authority) = uri.authority() else {
            return Err(Error::from_kind(ErrorKind::UserAbsoluteUriRequired));
        };
        let authority = authority.as_str();
        authority
            .rsplit_once('@')
            .map_or(authority, |(_, host_and_port)| host_and_port)
    } else {
        host
    };

    HeaderValue::from_str(value).map_err(|error| Error::new(ErrorKind::SendRequest, error))
}

/// Returns whether the URI scheme uses a secure transport by default.
fn is_scheme_secure(uri: &Uri) -> bool {
    matches!(uri.scheme_str(), Some("https" | "wss"))
}
