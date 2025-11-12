#[macro_use]
pub mod error;
pub mod extra;
mod util;

use std::{
    fmt,
    future::Future,
    num::NonZeroU32,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_util::future::{Either, FutureExt, TryFutureExt};
use http::{HeaderValue, Method, Request, Response, Uri, Version, header::HOST};
use http_body::Body;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::util::Oneshot;

use self::{
    error::{ClientConnectError, Error, ErrorKind, TrySendError},
    extra::{ConnectExtra, Identifier},
};
use super::pool::Ver;
use crate::{
    core::{
        client::{
            body::Incoming,
            common::{Exec, Lazy, lazy},
            conn::{self, TrySendError as ConnTrySendError},
            connect::{Alpn, Connected, Connection},
            options::{RequestOptions, http1::Http1Options, http2::Http2Options},
            pool,
        },
        error::BoxError,
        ext::{RequestConfig, RequestLayerOptions},
        rt::{ArcTimer, Executor, Timer},
    },
    hash::{HASHER, HashMemo},
    tls::AlpnProtocol,
};

type BoxSendFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Parameters required to initiate a new connection.
///
/// [`ConnectRequest`] holds the target URI and all connection-specific options
/// (protocol, proxy, TCP/TLS settings) needed to establish a new network connection.
/// Used by connectors to drive the connection setup process.
#[must_use]
#[derive(Clone)]
pub struct ConnectRequest {
    uri: Uri,
    extra: Arc<HashMemo<ConnectExtra>>,
}

// ===== impl ConnectRequest =====

impl ConnectRequest {
    /// Create a new [`ConnectRequest`] with the given URI and options.
    #[inline]
    fn new(uri: Uri, options: Option<RequestOptions>) -> ConnectRequest {
        let extra = ConnectExtra::new(uri.clone(), options);
        let extra = HashMemo::with_hasher(extra, HASHER);
        ConnectRequest {
            uri,
            extra: Arc::new(extra),
        }
    }

    /// Returns a reference to the [`Uri`].
    #[inline]
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns a mutable reference to the [`Uri`].
    #[inline]
    pub fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }

    /// Returns a unique [`Identifier`].
    #[inline]
    pub(crate) fn identify(&self) -> Identifier {
        self.extra.clone()
    }

    /// Returns the [`ConnectExtra`] connection extra.
    #[inline]
    pub(crate) fn extra(&self) -> &ConnectExtra {
        self.extra.as_ref().as_ref()
    }
}

/// A HttpClient to make outgoing HTTP requests.
///
/// `HttpClient` is cheap to clone and cloning is the recommended way to share a `HttpClient`. The
/// underlying connection pool will be reused.
#[must_use]
pub struct HttpClient<C, B> {
    config: Config,
    connector: C,
    exec: Exec,
    h1_builder: conn::http1::Builder,
    h2_builder: conn::http2::Builder<Exec>,
    pool: pool::Pool<PoolClient<B>, Identifier>,
}

#[derive(Clone, Copy)]
struct Config {
    retry_canceled_requests: bool,
    set_host: bool,
    ver: Ver,
}

// ===== impl HttpClient =====

impl HttpClient<(), ()> {
    /// Create a builder to configure a new `HttpClient`.
    pub fn builder<E>(executor: E) -> Builder
    where
        E: Executor<BoxSendFuture> + Send + Sync + Clone + 'static,
    {
        Builder::new(executor)
    }
}

impl<C, B> HttpClient<C, B>
where
    C: tower::Service<ConnectRequest> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Send a constructed `Request` using this `HttpClient`.
    fn request(&self, mut req: Request<B>) -> ResponseFuture {
        let is_http_connect = req.method() == Method::CONNECT;
        // Validate HTTP version early
        match req.version() {
            Version::HTTP_10 if is_http_connect => {
                warn!("CONNECT is not allowed for HTTP/1.0");
                return ResponseFuture::new(futures_util::future::err(e!(
                    UserUnsupportedRequestMethod
                )));
            }
            Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2 => {}
            // completely unsupported HTTP version (like HTTP/0.9)!
            _unsupported => {
                warn!("Request has unsupported version: {:?}", _unsupported);
                return ResponseFuture::new(futures_util::future::err(e!(UserUnsupportedVersion)));
            }
        };

        // Extract and normalize URI
        let uri = match util::normalize_uri(&mut req, is_http_connect) {
            Ok(uri) => uri,
            Err(err) => return ResponseFuture::new(futures_util::future::err(err)),
        };

        let mut this = self.clone();

        // Extract per-request options from the request extensions and apply them to the client
        // builder. This allows each request to override HTTP/1 and HTTP/2 options as
        // needed.
        let options = RequestConfig::<RequestLayerOptions>::remove(req.extensions_mut());

        // Apply HTTP/1 and HTTP/2 options if provided
        if let Some(opts) = options.as_ref().map(RequestOptions::transport_opts) {
            if let Some(opts) = opts.http1_options() {
                this.h1_builder.options(opts.clone());
            }

            if let Some(opts) = opts.http2_options() {
                this.h2_builder.options(opts.clone());
            }
        }

        let connect_req = ConnectRequest::new(uri, options);
        ResponseFuture::new(this.send_request(req, connect_req))
    }

    async fn send_request(
        self,
        mut req: Request<B>,
        connect_req: ConnectRequest,
    ) -> Result<Response<Incoming>, Error> {
        let uri = req.uri().clone();

        loop {
            req = match self.try_send_request(req, connect_req.clone()).await {
                Ok(resp) => return Ok(resp),
                Err(TrySendError::Nope(err)) => return Err(err),
                Err(TrySendError::Retryable {
                    mut req,
                    error,
                    connection_reused,
                }) => {
                    if !self.config.retry_canceled_requests || !connection_reused {
                        // if client disabled, don't retry
                        // a fresh connection means we definitely can't retry
                        return Err(error);
                    }

                    trace!(
                        "unstarted request canceled, trying again (reason={:?})",
                        error
                    );
                    *req.uri_mut() = uri.clone();
                    req
                }
            }
        }
    }

    async fn try_send_request(
        &self,
        mut req: Request<B>,
        connect_req: ConnectRequest,
    ) -> Result<Response<Incoming>, TrySendError<B>> {
        let mut pooled = self
            .connection_for(connect_req)
            .await
            // `connection_for` already retries checkout errors, so if
            // it returns an error, there's not much else to retry
            .map_err(TrySendError::Nope)?;

        if pooled.is_http1() {
            if req.version() == Version::HTTP_2 {
                warn!("Connection is HTTP/1, but request requires HTTP/2");
                return Err(TrySendError::Nope(
                    e!(UserUnsupportedVersion).with_connect_info(pooled.conn_info.clone()),
                ));
            }

            if self.config.set_host {
                let uri = req.uri().clone();
                req.headers_mut().entry(HOST).or_insert_with(|| {
                    let hostname = uri.host().expect("authority implies host");
                    if let Some(port) = util::get_non_default_port(&uri) {
                        let s = format!("{hostname}:{port}");
                        HeaderValue::from_maybe_shared(Bytes::from(s))
                    } else {
                        HeaderValue::from_str(hostname)
                    }
                    .expect("uri host is valid header value")
                });
            }

            // CONNECT always sends authority-form, so check it first...
            if req.method() == Method::CONNECT {
                util::authority_form(req.uri_mut());
            } else if pooled.conn_info.is_proxied {
                util::absolute_form(req.uri_mut());
            } else {
                util::origin_form(req.uri_mut());
            }
        } else if req.method() == Method::CONNECT && !pooled.is_http2() {
            util::authority_form(req.uri_mut());
        }

        let mut res = match pooled.try_send_request(req).await {
            Ok(res) => res,
            Err(mut err) => {
                return if let Some(req) = err.take_message() {
                    Err(TrySendError::Retryable {
                        connection_reused: pooled.is_reused(),
                        error: e!(Canceled, err.into_error())
                            .with_connect_info(pooled.conn_info.clone()),
                        req,
                    })
                } else {
                    Err(TrySendError::Nope(
                        e!(SendRequest, err.into_error())
                            .with_connect_info(pooled.conn_info.clone()),
                    ))
                };
            }
        };

        // If the Connector included 'extra' info, add to Response...
        if let Some(extra) = &pooled.conn_info.extra {
            extra.set(res.extensions_mut());
        }

        // If pooled is HTTP/2, we can toss this reference immediately.
        //
        // when pooled is dropped, it will try to insert back into the
        // pool. To delay that, spawn a future that completes once the
        // sender is ready again.
        //
        // This *should* only be once the related `Connection` has polled
        // for a new request to start.
        //
        // It won't be ready if there is a body to stream.
        if pooled.is_http2() || !pooled.is_pool_enabled() || pooled.is_ready() {
            drop(pooled);
        } else {
            let on_idle = std::future::poll_fn(move |cx| pooled.poll_ready(cx)).map(|_| ());
            self.exec.execute(on_idle);
        }

        Ok(res)
    }

    async fn connection_for(
        &self,
        req: ConnectRequest,
    ) -> Result<pool::Pooled<PoolClient<B>, Identifier>, Error> {
        loop {
            match self.one_connection_for(req.clone()).await {
                Ok(pooled) => return Ok(pooled),
                Err(ClientConnectError::Normal(err)) => return Err(err),
                Err(ClientConnectError::CheckoutIsClosed(reason)) => {
                    if !self.config.retry_canceled_requests {
                        return Err(e!(Connect, reason));
                    }

                    trace!(
                        "unstarted request canceled, trying again (reason={:?})",
                        reason,
                    );
                    continue;
                }
            };
        }
    }

    async fn one_connection_for(
        &self,
        req: ConnectRequest,
    ) -> Result<pool::Pooled<PoolClient<B>, Identifier>, ClientConnectError> {
        // Return a single connection if pooling is not enabled
        if !self.pool.is_enabled() {
            return self
                .connect_to(req)
                .await
                .map_err(ClientConnectError::Normal);
        }

        // This actually races 2 different futures to try to get a ready
        // connection the fastest, and to reduce connection churn.
        //
        // - If the pool has an idle connection waiting, that's used immediately.
        // - Otherwise, the Connector is asked to start connecting to the destination Uri.
        // - Meanwhile, the pool Checkout is watching to see if any other request finishes and tries
        //   to insert an idle connection.
        // - If a new connection is started, but the Checkout wins after (an idle connection became
        //   available first), the started connection future is spawned into the runtime to
        //   complete, and then be inserted into the pool as an idle connection.
        let checkout = self.pool.checkout(req.identify());
        let connect = self.connect_to(req);
        let is_ver_h2 = self.config.ver == Ver::Http2;

        // The order of the `select` is depended on below...

        match futures_util::future::select(checkout, connect).await {
            // Checkout won, connect future may have been started or not.
            //
            // If it has, let it finish and insert back into the pool,
            // so as to not waste the socket...
            Either::Left((Ok(checked_out), connecting)) => {
                // This depends on the `select` above having the correct
                // order, such that if the checkout future were ready
                // immediately, the connect future will never have been
                // started.
                //
                // If it *wasn't* ready yet, then the connect future will
                // have been started...
                if connecting.started() {
                    let bg = connecting
                        .map_err(|_err| {
                            trace!("background connect error: {}", _err);
                        })
                        .map(|_pooled| {
                            // dropping here should just place it in
                            // the Pool for us...
                        });
                    // An execute error here isn't important, we're just trying
                    // to prevent a waste of a socket...
                    self.exec.execute(bg);
                }
                Ok(checked_out)
            }
            // Connect won, checkout can just be dropped.
            Either::Right((Ok(connected), _checkout)) => Ok(connected),
            // Either checkout or connect could get canceled:
            //
            // 1. Connect is canceled if this is HTTP/2 and there is an outstanding HTTP/2
            //    connecting task.
            // 2. Checkout is canceled if the pool cannot deliver an idle connection reliably.
            //
            // In both cases, we should just wait for the other future.
            Either::Left((Err(err), connecting)) => {
                if err.is_canceled() {
                    connecting.await.map_err(ClientConnectError::Normal)
                } else {
                    Err(ClientConnectError::Normal(e!(Connect, err)))
                }
            }
            Either::Right((Err(err), checkout)) => {
                if err.is_canceled() {
                    checkout.await.map_err(move |err| {
                        if is_ver_h2 && err.is_canceled() {
                            ClientConnectError::CheckoutIsClosed(err)
                        } else {
                            ClientConnectError::Normal(e!(Connect, err))
                        }
                    })
                } else {
                    Err(ClientConnectError::Normal(err))
                }
            }
        }
    }

    fn connect_to(
        &self,
        req: ConnectRequest,
    ) -> impl Lazy<Output = Result<pool::Pooled<PoolClient<B>, Identifier>, Error>>
    + Send
    + Unpin
    + 'static {
        let executor = self.exec.clone();
        let pool = self.pool.clone();

        let h1_builder = self.h1_builder.clone();
        let h2_builder = self.h2_builder.clone();
        let ver = match req.extra().alpn_protocol() {
            Some(AlpnProtocol::HTTP2) => Ver::Http2,
            _ => self.config.ver,
        };
        let is_ver_h2 = ver == Ver::Http2;
        let connector = self.connector.clone();
        lazy(move || {
            // Try to take a "connecting lock".
            //
            // If the pool_key is for HTTP/2, and there is already a
            // connection being established, then this can't take a
            // second lock. The "connect_to" future is Canceled.
            let connecting = match pool.connecting(req.identify(), ver) {
                Some(lock) => lock,
                None => {
                    let canceled = e!(Canceled);
                    // HTTP/2 connection in progress.
                    return Either::Right(futures_util::future::err(canceled));
                }
            };
            Either::Left(
                Oneshot::new(connector, req)
                    .map_err(|src| e!(Connect, src))
                    .and_then(move |io| {
                        let connected = io.connected();
                        // If ALPN is h2 and we aren't http2_only already,
                        // then we need to convert our pool checkout into
                        // a single HTTP2 one.
                        let connecting = if connected.alpn == Alpn::H2 && !is_ver_h2 {
                            match connecting.alpn_h2(&pool) {
                                Some(lock) => {
                                    trace!("ALPN negotiated h2, updating pool");
                                    lock
                                }
                                None => {
                                    // Another connection has already upgraded,
                                    // the pool checkout should finish up for us.
                                    let canceled = e!(Canceled, "ALPN upgraded to HTTP/2");
                                    return Either::Right(futures_util::future::err(canceled));
                                }
                            }
                        } else {
                            connecting
                        };

                        let is_h2 = is_ver_h2 || connected.alpn == Alpn::H2;

                        Either::Left(Box::pin(async move {
                            let tx = if is_h2 {
                               {
                                    let (mut tx, conn) =
                                        h2_builder.handshake(io).await.map_err(Error::tx)?;

                                    trace!(
                                        "http2 handshake complete, spawning background dispatcher task"
                                    );
                                    executor.execute(
                                        conn.map_err(|_e| debug!("client connection error: {}", _e))
                                            .map(|_| ()),
                                    );

                                    // Wait for 'conn' to ready up before we
                                    // declare this tx as usable
                                    tx.ready().await.map_err(Error::tx)?;
                                    PoolTx::Http2(tx)
                                }
                            } else {
                                 {
                                    // Perform the HTTP/1.1 handshake on the provided I/O stream. More actions
                                    // Uses the h1_builder to establish a connection, returning a sender (tx) for requests
                                    // and a connection task (conn) that manages the connection lifecycle.
                                    let (mut tx, conn) =
                                        h1_builder.handshake(io).await.map_err(Error::tx)?;

                                    // Log that the HTTP/1.1 handshake has completed successfully.
                                    // This indicates the connection is established and ready for request processing.
                                    trace!(
                                        "http1 handshake complete, spawning background dispatcher task"
                                    );

                                    // Create a oneshot channel to communicate errors from the connection task.
                                    // err_tx sends errors from the connection task, and err_rx receives them
                                    // to correlate connection failures with request readiness errors.
                                    let (err_tx, err_rx) = tokio::sync::oneshot::channel();
                                    // Spawn the connection task in the background using the executor.
                                    // The task manages the HTTP/1.1 connection, including upgrades (e.g., WebSocket).
                                    // Errors are sent via err_tx to ensure they can be checked if the sender (tx) fails.
                                    executor.execute(
                                        conn.with_upgrades()
                                                .map_err(|e| {
                                                // Log the connection error at debug level for diagnostic purposes.
                                                debug!("client connection error: {:?}", e);
                                                // Log that the error is being sent to the error channel.
                                                trace!("sending connection error to error channel");
                                                // Send the error via the oneshot channel, ignoring send failures
                                                // (e.g., if the receiver is dropped, which is handled later).
                                                let _ = err_tx.send(e);
                                            })
                                            .map(|_| ()),
                                    );

                                    // Log that the client is waiting for the connection to be ready.
                                    // Readiness indicates the sender (tx) can accept a request without blocking. More actions
                                    trace!("waiting for connection to be ready");

                                    // Check if the sender is ready to accept a request.
                                    // This ensures the connection is fully established before proceeding.
                                    // Wait for 'conn' to ready up before we
                                    // declare this tx as usable
                                    match tx.ready().await {
                                        // If ready, the connection is usable for sending requests.
                                        Ok(_) => {
                                            // Log that the connection is ready for use.
                                            trace!("connection is ready");
                                            // Drop the error receiver, as it’s no longer needed since the sender is ready.
                                            // This prevents waiting for errors that won’t occur in a successful case.
                                            drop(err_rx);
                                            // Wrap the sender in PoolTx::Http1 for use in the connection pool.
                                            PoolTx::Http1(tx)
                                        }
                                        // If the sender fails with a closed channel error, check for a specific connection error.
                                        // This distinguishes between a vague ChannelClosed error and an actual connection failure.
                                        Err(e) if e.is_closed() => {
                                            // Log that the channel is closed, indicating a potential connection issue.
                                            trace!("connection channel closed, checking for connection error");
                                            // Check the oneshot channel for a specific error from the connection task.
                                            match err_rx.await {
                                                // If an error was received, it’s a specific connection failure.
                                                Ok(err) => {
                                                     // Log the specific connection error for diagnostics.
                                                    trace!("received connection error: {:?}", err);
                                                    // Return the error wrapped in Error::tx to propagate it.
                                                    return Err(Error::tx(err));
                                                }
                                                // If the error channel is closed, no specific error was sent.
                                                // Fall back to the vague ChannelClosed error.
                                                Err(_) => {
                                                    // Log that the error channel is closed, indicating no specific error.
                                                    trace!("error channel closed, returning the vague ChannelClosed error");
                                                    // Return the original error wrapped in Error::tx.
                                                    return Err(Error::tx(e));
                                                }
                                            }
                                        }
                                        // For other errors (e.g., timeout, I/O issues), propagate them directly.
                                        // These are not ChannelClosed errors and don’t require error channel checks.
                                        Err(e) => {
                                            // Log the specific readiness failure for diagnostics.
                                            trace!("connection readiness failed: {:?}", e);
                                            // Return the error wrapped in Error::tx to propagate it.
                                            return Err(Error::tx(e));
                                        }
                                    }
                                }
                            };

                            Ok(pool.pooled(
                                connecting,
                                PoolClient {
                                    conn_info: connected,
                                    tx,
                                },
                            ))
                        }))
                    }),
            )
        })
    }
}

impl<C, B> tower::Service<Request<B>> for HttpClient<C, B>
where
    C: tower::Service<ConnectRequest> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Incoming>;
    type Error = Error;
    type Future = ResponseFuture;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        self.request(req)
    }
}

impl<C, B> tower::Service<Request<B>> for &'_ HttpClient<C, B>
where
    C: tower::Service<ConnectRequest> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Incoming>;
    type Error = Error;
    type Future = ResponseFuture;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        self.request(req)
    }
}

impl<C: Clone, B> Clone for HttpClient<C, B> {
    fn clone(&self) -> HttpClient<C, B> {
        HttpClient {
            config: self.config,
            exec: self.exec.clone(),

            h1_builder: self.h1_builder.clone(),
            h2_builder: self.h2_builder.clone(),
            connector: self.connector.clone(),
            pool: self.pool.clone(),
        }
    }
}

impl<C, B> fmt::Debug for HttpClient<C, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient").finish()
    }
}

/// A pooled HTTP connection that can send requests
struct PoolClient<B> {
    conn_info: Connected,
    tx: PoolTx<B>,
}

enum PoolTx<B> {
    Http1(conn::http1::SendRequest<B>),
    Http2(conn::http2::SendRequest<B>),
}

// ===== impl PoolClient =====

impl<B> PoolClient<B> {
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.tx {
            PoolTx::Http1(ref mut tx) => tx.poll_ready(cx).map_err(Error::closed),

            PoolTx::Http2(_) => Poll::Ready(Ok(())),
        }
    }

    fn is_http1(&self) -> bool {
        !self.is_http2()
    }

    fn is_http2(&self) -> bool {
        match self.tx {
            PoolTx::Http1(_) => false,

            PoolTx::Http2(_) => true,
        }
    }

    fn is_poisoned(&self) -> bool {
        self.conn_info.poisoned.poisoned()
    }

    fn is_ready(&self) -> bool {
        match self.tx {
            PoolTx::Http1(ref tx) => tx.is_ready(),

            PoolTx::Http2(ref tx) => tx.is_ready(),
        }
    }
}

impl<B: Body + 'static> PoolClient<B> {
    fn try_send_request(
        &mut self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, ConnTrySendError<Request<B>>>>
    where
        B: Send,
    {
        match self.tx {
            PoolTx::Http1(ref mut tx) => Either::Left(tx.try_send_request(req)),
            PoolTx::Http2(ref mut tx) => Either::Right(tx.try_send_request(req)),
        }
    }
}

impl<B> pool::Poolable for PoolClient<B>
where
    B: Send + 'static,
{
    fn is_open(&self) -> bool {
        !self.is_poisoned() && self.is_ready()
    }

    fn reserve(self) -> pool::Reservation<Self> {
        match self.tx {
            PoolTx::Http1(tx) => pool::Reservation::Unique(PoolClient {
                conn_info: self.conn_info,
                tx: PoolTx::Http1(tx),
            }),

            PoolTx::Http2(tx) => {
                let b = PoolClient {
                    conn_info: self.conn_info.clone(),
                    tx: PoolTx::Http2(tx.clone()),
                };
                let a = PoolClient {
                    conn_info: self.conn_info,
                    tx: PoolTx::Http2(tx),
                };
                pool::Reservation::Shared(a, b)
            }
        }
    }

    fn can_share(&self) -> bool {
        self.is_http2()
    }
}

/// A `Future` that will resolve to an HTTP Response.
#[must_use = "futures do nothing unless polled"]
pub struct ResponseFuture {
    inner: Pin<Box<dyn Future<Output = Result<Response<Incoming>, Error>> + Send>>,
}

// ===== impl ResponseFuture =====

impl ResponseFuture {
    #[inline]
    pub(super) fn new<F>(value: F) -> ResponseFuture
    where
        F: Future<Output = Result<Response<Incoming>, Error>> + Send + 'static,
    {
        ResponseFuture {
            inner: Box::pin(value),
        }
    }
}

impl Future for ResponseFuture {
    type Output = Result<Response<Incoming>, Error>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

/// A builder to configure a new [`HttpClient`].
#[derive(Clone)]
pub struct Builder {
    client_config: Config,
    exec: Exec,

    h1_builder: conn::http1::Builder,
    h2_builder: conn::http2::Builder<Exec>,
    pool_config: pool::Config,
    pool_timer: Option<ArcTimer>,
}

// ===== impl Builder =====

impl Builder {
    /// Construct a new Builder.
    pub fn new<E>(executor: E) -> Self
    where
        E: Executor<BoxSendFuture> + Send + Sync + Clone + 'static,
    {
        let exec = Exec::new(executor);
        Self {
            client_config: Config {
                retry_canceled_requests: true,
                set_host: true,
                ver: Ver::Auto,
            },
            exec: exec.clone(),

            h1_builder: conn::http1::Builder::new(),
            h2_builder: conn::http2::Builder::new(exec),
            pool_config: pool::Config {
                idle_timeout: Some(Duration::from_secs(90)),
                max_idle_per_host: usize::MAX,
                max_pool_size: None,
            },
            pool_timer: None,
        }
    }
    /// Set an optional timeout for idle sockets being kept-alive.
    /// A `Timer` is required for this to take effect. See `Builder::pool_timer`
    ///
    /// Pass `None` to disable timeout.
    ///
    /// Default is 90 seconds.
    #[inline]
    pub fn pool_idle_timeout<D>(mut self, val: D) -> Self
    where
        D: Into<Option<Duration>>,
    {
        self.pool_config.idle_timeout = val.into();
        self
    }

    /// Sets the maximum idle connection per host allowed in the pool.
    ///
    /// Default is `usize::MAX` (no limit).
    #[inline]
    pub fn pool_max_idle_per_host(mut self, max_idle: usize) -> Self {
        self.pool_config.max_idle_per_host = max_idle;
        self
    }

    /// Sets the maximum number of connections in the pool.
    ///
    /// Default is `None` (no limit).
    #[inline]
    pub fn pool_max_size(mut self, max_size: impl Into<Option<NonZeroU32>>) -> Self {
        self.pool_config.max_pool_size = max_size.into();
        self
    }

    /// Set whether the connection **must** use HTTP/2.
    ///
    /// The destination must either allow HTTP2 Prior Knowledge, or the
    /// `Connect` should be configured to do use ALPN to upgrade to `h2`
    /// as part of the connection process. This will not make the `HttpClient`
    /// utilize ALPN by itself.
    ///
    /// Note that setting this to true prevents HTTP/1 from being allowed.
    ///
    /// Default is false.
    #[inline]
    pub fn http2_only(mut self, val: bool) -> Self {
        self.client_config.ver = if val { Ver::Http2 } else { Ver::Auto };
        self
    }

    /// Provide a timer to be used for http2
    ///
    /// See the documentation of [`http2::client::Builder::timer`] for more
    /// details.
    ///
    /// [`http2::client::Builder::timer`]: https://docs.rs/http2/latest/http2/client/struct.Builder.html#method.timer
    #[inline]
    pub fn http2_timer<M>(mut self, timer: M) -> Self
    where
        M: Timer + Send + Sync + 'static,
    {
        self.h2_builder.timer(timer);
        self
    }

    /// Provide a configuration for HTTP/1.
    #[inline]
    pub fn http1_options<O>(mut self, opts: O) -> Self
    where
        O: Into<Option<Http1Options>>,
    {
        if let Some(opts) = opts.into() {
            self.h1_builder.options(opts);
        }

        self
    }

    /// Provide a configuration for HTTP/2.
    #[inline]
    pub fn http2_options<O>(mut self, opts: O) -> Self
    where
        O: Into<Option<Http2Options>>,
    {
        if let Some(opts) = opts.into() {
            self.h2_builder.options(opts);
        }
        self
    }

    /// Provide a timer to be used for timeouts and intervals in connection pools.
    #[inline]
    pub fn pool_timer<M>(mut self, timer: M) -> Self
    where
        M: Timer + Clone + Send + Sync + 'static,
    {
        self.pool_timer = Some(ArcTimer::new(timer));
        self
    }

    /// Set whether to retry requests that get disrupted before ever starting
    /// to write.
    ///
    /// This means a request that is queued, and gets given an idle, reused
    /// connection, and then encounters an error immediately as the idle
    /// connection was found to be unusable.
    ///
    /// When this is set to `false`, the related `ResponseFuture` would instead
    /// resolve to an `Error::Cancel`.
    ///
    /// Default is `true`.
    #[inline]
    pub fn retry_canceled_requests(mut self, val: bool) -> Self {
        self.client_config.retry_canceled_requests = val;
        self
    }

    /// Set whether to automatically add the `Host` header to requests.
    ///
    /// If true, and a request does not include a `Host` header, one will be
    /// added automatically, derived from the authority of the `Uri`.
    ///
    /// Default is `true`.
    #[inline]
    pub fn set_host(mut self, val: bool) -> Self {
        self.client_config.set_host = val;
        self
    }

    /// Combine the configuration of this builder with a connector to create a `HttpClient`.
    pub fn build<C, B>(self, connector: C) -> HttpClient<C, B>
    where
        C: tower::Service<ConnectRequest> + Clone + Send + Sync + 'static,
        C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
        C::Error: Into<BoxError>,
        C::Future: Unpin + Send + 'static,
        B: Body + Send,
        B::Data: Send,
    {
        let exec = self.exec.clone();
        let timer = self.pool_timer.clone();
        HttpClient {
            config: self.client_config,
            exec: exec.clone(),

            h1_builder: self.h1_builder,
            h2_builder: self.h2_builder,
            connector,
            pool: pool::Pool::new(self.pool_config, exec, timer),
        }
    }
}
