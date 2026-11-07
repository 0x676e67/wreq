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
use netty::{body::Incoming, conn};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::oneshot,
};
use tower::{BoxError, Layer, Service};

use super::{Established, SendError, is_expired};
use crate::{
    Body,
    client::{
        error::{Error, ErrorKind},
        pool::cache::Started,
    },
    conn::Connected,
    rt::{DynRuntime, Timer as _},
};

/// Prepares and sends requests over one reusable HTTP/1 connection.
///
/// HTTP/1 permits one active checkout. Dispatch returns this sender only after
/// it becomes ready again; a busy sender is held by a readiness task.
pub struct Connection {
    tx: conn::http1::SendRequest<Body>,
    connected: Connected,
    set_host: bool,
    idle_at: Instant,
    runtime: DynRuntime,
}

/// Layers HTTP/1 handshaking over a transport-producing service.
///
/// The resulting service waits for the physical connector, performs the
/// handshake, and returns a cacheable [`Connection`].
#[derive(Clone)]
pub struct ConnectLayer {
    set_host: bool,
    runtime: DynRuntime,
}

/// Connects a transport and performs an HTTP/1 handshake.
///
/// The inner service may include a reuse delay before connecting. Its
/// [`Started`] state is preserved so the HTTP/1 cache can decide whether a lost
/// reuse race should finish in the background.
#[derive(Clone)]
pub struct Connect<S> {
    service: S,
    set_host: bool,
    runtime: DynRuntime,
}

/// Connects a transport and then advances the HTTP/1 handshake.
///
/// The explicit state machine keeps the connector's [`Started`] signal visible
/// to the cache while the operation moves from transport creation to the boxed
/// protocol handshake future.
pub struct ConnectFuture<F, T> {
    state: ConnectState<F>,
    set_host: bool,
    runtime: Option<DynRuntime>,
    _io: PhantomData<fn(T)>,
}

/// Phases of an HTTP/1 connection service call.
enum ConnectState<F> {
    /// Waiting for the physical transport.
    Connecting(F),
    /// Performing the protocol handshake.
    Handshaking(BoxFuture<'static, Result<Connection, BoxError>>),
    /// Future has completed and owns no reusable state.
    Done,
}

/// Reports a consumed HTTP/1 handshake state.
/// Returned if the connect future no longer owns its runtime.
/// Carries no transport; the failed future releases its connection state.
#[derive(Debug)]
struct HandshakeStateError;

// ===== impl ConnectLayer =====

impl ConnectLayer {
    /// Creates an HTTP/1 handshake layer for pooled connections.
    pub fn new(runtime: DynRuntime, set_host: bool) -> Self {
        Self { runtime, set_host }
    }
}

impl<S> Layer<S> for ConnectLayer {
    type Service = Connect<S>;

    fn layer(&self, service: S) -> Self::Service {
        Connect {
            service,
            runtime: self.runtime.clone(),
            set_host: self.set_host,
        }
    }
}

// ===== impl Connect =====

impl<S, T, Dst> Service<Dst> for Connect<S>
where
    S: Service<Dst, Response = Established<T>, Error = BoxError> + Clone,
    S::Future: Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Response = Connection;
    type Error = BoxError;
    type Future = ConnectFuture<S::Future, T>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, target: Dst) -> Self::Future {
        ConnectFuture {
            state: ConnectState::Connecting(self.service.call(target)),
            runtime: Some(self.runtime.clone()),
            set_host: self.set_host,
            _io: PhantomData,
        }
    }
}

// ===== impl ConnectFuture =====

impl<F, T> Future for ConnectFuture<F, T>
where
    F: Future<Output = Result<Established<T>, BoxError>> + Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = Result<Connection, BoxError>;

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
                    let Some(runtime) = self.runtime.take() else {
                        self.state = ConnectState::Done;
                        return Poll::Ready(Err(HandshakeStateError.into()));
                    };

                    self.state = ConnectState::Handshaking(Box::pin(Connection::handshake(
                        established,
                        runtime,
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

impl<F, T> Started for ConnectFuture<F, T>
where
    F: Future<Output = Result<Established<T>, BoxError>> + Started + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn started(&self) -> bool {
        match &self.state {
            ConnectState::Connecting(future) => future.started(),
            ConnectState::Handshaking(_) | ConnectState::Done => true,
        }
    }
}

// ===== impl Connection =====

impl Connection {
    /// Handshakes a transport and returns a ready HTTP/1 sender.
    /// Starts the driver before waiting for readiness, preserving its error if
    /// the sender closes during setup.
    async fn handshake<T>(
        established: Established<T>,
        runtime: DynRuntime,
        set_host: bool,
    ) -> Result<Self, BoxError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Established {
            io,
            connected,
            config,
            ..
        } = established;

        let builder = config
            .req
            .config_override::<netty::http1::Http1Options>()
            .map_or_else(
                || config.proto.http1.clone(),
                |options| config.proto.http1.clone().options(options.clone()),
            );
        drop(config);

        let (mut tx, connection) = builder.handshake(io).await?;
        let (error_tx, error_rx) = oneshot::channel();
        runtime.execute(Box::pin(async move {
            if let Err(error) = connection.with_upgrades().await {
                debug!("client connection error: {error:?}");
                let _ = error_tx.send(error);
            }
        }));

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
            connected,
            set_host,
            idle_at: runtime.now(),
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

    /// Records when the exclusive sender becomes idle.
    pub fn mark_idle(&mut self) {
        self.idle_at = self.runtime.now();
    }

    /// Returns whether the exclusive sender can safely re-enter the cache.
    pub fn is_open(&self) -> bool {
        !self.connected().poisoned() && self.is_ready()
    }

    /// Returns whether the sender is healthy and within its idle timeout.
    pub fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        self.is_open() && !is_expired(self.idle_at, now, timeout)
    }
}

impl Service<Request<Body>> for Connection {
    type Response = Response<Incoming>;
    type Error = SendError;
    type Future = Either<
        BoxFuture<'static, Result<Self::Response, Self::Error>>,
        Ready<Result<Self::Response, Self::Error>>,
    >;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.tx
            .poll_ready(cx)
            .map_err(|error| SendError::Request(Error::closed(error)))
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // Host must be derived before the absolute URI becomes a wire target.
        if self.set_host
            && !req.headers().contains_key(HOST)
            && let Some(host) = generate_host_header(req.uri())
        {
            req.headers_mut().insert(HOST, host);
        }

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
