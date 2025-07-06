//! HTTP Client
//!
//! crate::core: provides HTTP over a single connection. See the [`conn`] module.

pub mod config;
pub mod conn;
pub(super) mod dispatch;

pub mod connect;
// Publicly available, but just for legacy purposes. A better pool will be
// designed.
mod pool;

use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    num::NonZeroU32,
    pin::Pin,
    task::{self, Poll},
    time::Duration,
};

use futures_util::future::{self, Either, FutureExt, TryFutureExt};
use http::{
    HeaderValue, Method, Request, Response, Uri, Version,
    header::HOST,
    uri::{Authority, PathAndQuery, Scheme},
};
use http_body::Body;
use pool::Ver;
use sync_wrapper::SyncWrapper;

use crate::{
    core::{
        body::Incoming,
        client::{
            config::{TransportConfig, http1::Http1Config, http2::Http2Config},
            conn::TrySendError as ConnTrySendError,
            connect::{Alpn, Connect, Connected, Connection, TcpConnectOptions},
        },
        common::{Exec, Lazy, lazy, timer},
        error::BoxError,
        ext::{
            RequestConfig, RequestEnforcedHttpVersion, RequestProxyMatcher,
            RequestTcpConnectOptions, RequestTransportConfig,
        },
        rt::{Executor, Timer},
    },
    proxy::Matcher as ProxyMacher,
    tls::{AlpnProtocol, TlsConfig},
};

type BoxSendFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Describes the reusable connection metadata for a network session.
///
/// This includes all the parameters that uniquely identify a pooled connection,
/// such as the target URI, protocol version, proxy configuration, and TCP settings.
///
/// This type is typically used as the core content for a [`ConnKey`],
/// and is shared across `ConnRequest` and other connection-related logic.
///
/// It implements `Eq`, `Hash`, and `Clone` to support caching and deduplication.
#[derive(Clone, Hash, Debug, Eq, PartialEq)]
pub struct ConnExtra {
    scheme: Option<Scheme>,
    authority: Option<Authority>,
    alpn_protocol: Option<AlpnProtocol>,
    proxy_matcher: Option<ProxyMacher>,
    tcp_options: Option<TcpConnectOptions>,
    tls_config: Option<TlsConfig>,
}

impl ConnExtra {
    /// Returns the negotiated ALPN protocol.
    #[inline]
    pub(crate) fn alpn_protocol(&self) -> Option<AlpnProtocol> {
        self.alpn_protocol
    }

    /// Return a reference to the proxy matcher.
    #[inline]
    pub(crate) fn proxy_matcher(&self) -> Option<&ProxyMacher> {
        self.proxy_matcher.as_ref()
    }

    /// Return the TCP connection options.
    #[inline]
    pub(crate) fn tcp_connect_options(&self) -> Option<&TcpConnectOptions> {
        self.tcp_options.as_ref()
    }

    /// Return the TLS configuration.
    #[inline]
    pub(crate) fn tls_config(&self) -> Option<&TlsConfig> {
        self.tls_config.as_ref()
    }
}

/// Uniquely identifies a reusable connection.
///
/// `ConnKey` is used to group connections that share identical
/// connection-level parameters such as the target URI, HTTP version,
/// proxy rules, and low-level TCP options. This is typically used as
/// a key in connection pooling logic to determine whether a new
/// connection can be reused.
///
/// This type implements `Hash`, `Eq`, and `Clone` to support use
/// in maps, caches, or deduplicated pools.
#[derive(Clone, Hash, Debug, Eq, PartialEq)]
pub(crate) struct ConnKey(Box<ConnExtra>);

/// Describes all the parameters needed to initiate a client connection.
///
/// A `ConnRequest` encapsulates the information required to initiate
/// an outgoing network connection, including the HTTP target URI, protocol
/// version, optional proxy handling, TCP options, and TLS configuration.
///
/// This struct is used internally to drive the connection setup process
/// and may influence connection pooling, ALPN negotiation, and proxy routing.
#[derive(Debug, Clone)]
pub struct ConnRequest {
    uri: Uri,
    extra: Box<ConnExtra>,
}

impl ConnRequest {
    /// Return a reference to the destination URI for this request.
    #[inline]
    pub(crate) fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Return a mutable reference to the target URI for this connection request.
    #[inline]
    pub(crate) fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }

    /// Return the extra connection parameters for this request.
    #[inline]
    pub(crate) fn ex_data(&self) -> &ConnExtra {
        &self.extra
    }

    /// Converts the request into its corresponding `ConnKey`.
    #[inline]
    pub(crate) fn into_key(self) -> ConnKey {
        ConnKey(self.extra)
    }
}

/// A Client to make outgoing HTTP requests.
///
/// `Client` is cheap to clone and cloning is the recommended way to share a `Client`. The
/// underlying connection pool will be reused.
pub struct Client<C, B> {
    config: Config,
    connector: C,
    exec: Exec,
    h1_builder: conn::http1::Builder,
    h2_builder: conn::http2::Builder<Exec>,
    pool: pool::Pool<PoolClient<B>, ConnKey>,
}

#[derive(Clone, Copy, Debug)]
struct Config {
    retry_canceled_requests: bool,
    set_host: bool,
    ver: Ver,
}

/// Client errors
pub struct Error {
    kind: ErrorKind,
    source: Option<BoxError>,

    connect_info: Option<Connected>,
}

impl From<http::Error> for Error {
    #[inline]
    fn from(err: http::Error) -> Error {
        Error {
            kind: ErrorKind::UserAbsoluteUriRequired,
            source: Some(err.into()),
            connect_info: None,
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Canceled,
    ChannelClosed,
    Connect,
    UserUnsupportedRequestMethod,
    UserUnsupportedVersion,
    UserAbsoluteUriRequired,
    SendRequest,
}

macro_rules! e {
    ($kind:ident) => {
        Error {
            kind: ErrorKind::$kind,
            source: None,
            connect_info: None,
        }
    };
    ($kind:ident, $src:expr) => {
        Error {
            kind: ErrorKind::$kind,
            source: Some($src.into()),
            connect_info: None,
        }
    };
}

#[allow(clippy::large_enum_variant)]
enum TrySendError<B> {
    Retryable {
        error: Error,
        req: Request<B>,
        connection_reused: bool,
    },
    Nope(Error),
}

type ResponseWrapper =
    SyncWrapper<Pin<Box<dyn Future<Output = Result<Response<Incoming>, Error>> + Send>>>;

/// A `Future` that will resolve to an HTTP Response.
///
/// This is returned by `Client::request` (and `Client::get`).
#[must_use = "futures do nothing unless polled"]
pub struct ResponseFuture {
    inner: ResponseWrapper,
}

// ===== impl Client =====

impl Client<(), ()> {
    /// Create a builder to configure a new `Client`.
    ///
    /// # Example
    ///
    /// ```
    /// #
    /// # fn run () {
    /// use crate::{
    ///     core::rt::TokioExecutor,
    ///     util::client::Client,
    /// };
    /// use std::time::Duration;
    ///
    /// let client = Client::builder(TokioExecutor::new())
    ///     .pool_idle_timeout(Duration::from_secs(30))
    ///     .http2_only(true)
    ///     .build_http();
    /// # let infer: Client<_, http_body_util::Full<bytes::Bytes>> = client;
    /// # drop(infer);
    /// # }
    /// # fn main() {}
    /// ```
    pub fn builder<E>(executor: E) -> Builder
    where
        E: Executor<BoxSendFuture> + Send + Sync + Clone + 'static,
    {
        Builder::new(executor)
    }
}

impl<C, B> Client<C, B>
where
    C: Connect + Clone + Send + Sync + 'static,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Send a constructed `Request` using this `Client`.
    ///
    /// # Example
    ///
    /// ```
    /// #
    /// # fn run () {
    /// use crate::{
    ///     core::{
    ///         Method,
    ///         Request,
    ///         rt::TokioExecutor,
    ///     },
    ///     util::client::Client,
    /// };
    /// use bytes::Bytes;
    /// use http_body_util::Full;
    ///
    /// let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    ///
    /// let req: Request<Full<Bytes>> = Request::builder()
    ///     .method(Method::POST)
    ///     .uri("http://httpbin.org/post")
    ///     .body(Full::from("Hallo!"))
    ///     .expect("request builder");
    ///
    /// let future = client.request(req);
    /// # }
    /// # fn main() {}
    /// ```
    pub fn request(&self, mut req: Request<B>) -> ResponseFuture {
        let is_http_connect = req.method() == Method::CONNECT;
        // Validate HTTP version early
        match req.version() {
            Version::HTTP_10 if is_http_connect => {
                warn!("CONNECT is not allowed for HTTP/1.0");
                return ResponseFuture::new(future::err(e!(UserUnsupportedRequestMethod)));
            }
            Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2 => {}
            // completely unsupported HTTP version (like HTTP/0.9)!
            unsupported => return ResponseFuture::error_version(unsupported),
        };

        // Extract and normalize URI
        let uri = match normalize_uri(&mut req, is_http_connect) {
            Ok(uri) => uri,
            Err(err) => return ResponseFuture::new(future::err(err)),
        };

        // Extract config extensions
        let (transport_cfg, version, proxy_matcher, tcp_options) =
            extract_request_configs(req.extensions_mut());

        let mut tls_config = None;
        let mut this = self.clone();

        // Parse to specific ALPN protocol
        let alpn_protocol = match version {
            Some(Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09) => {
                Some(AlpnProtocol::HTTP1)
            }
            Some(Version::HTTP_2) => Some(AlpnProtocol::HTTP2),
            _ => None,
        };

        // Apply transport configuration
        if let Some(mut cfg) = transport_cfg {
            if let Some(config) = cfg.http1_config.take() {
                this.h1_builder.config(config);
            }
            if let Some(config) = cfg.http2_config.take() {
                this.h2_builder.config(config);
            }
            tls_config = cfg.tls_config.take();
        }

        let conn_req = ConnRequest {
            extra: Box::new(ConnExtra {
                scheme: uri.scheme().cloned(),
                authority: uri.authority().cloned(),
                alpn_protocol,
                proxy_matcher,
                tcp_options,
                tls_config,
            }),
            uri,
        };

        ResponseFuture::new(this.send_request(req, conn_req))
    }

    async fn send_request(
        self,
        mut req: Request<B>,
        conn_req: ConnRequest,
    ) -> Result<Response<Incoming>, Error> {
        let uri = req.uri().clone();

        loop {
            req = match self.try_send_request(req, conn_req.clone()).await {
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
        conn_req: ConnRequest,
    ) -> Result<Response<Incoming>, TrySendError<B>> {
        let mut pooled = self
            .connection_for(conn_req)
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
                    if let Some(port) = get_non_default_port(&uri) {
                        let s = format!("{hostname}:{port}");
                        HeaderValue::from_str(&s)
                    } else {
                        HeaderValue::from_str(hostname)
                    }
                    .expect("uri host is valid header value")
                });
            }

            // CONNECT always sends authority-form, so check it first...
            if req.method() == Method::CONNECT {
                authority_form(req.uri_mut());
            } else if pooled.conn_info.is_proxied {
                absolute_form(req.uri_mut());
            } else {
                origin_form(req.uri_mut());
            }
        } else if req.method() == Method::CONNECT && !pooled.is_http2() {
            authority_form(req.uri_mut());
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
        conn_req: ConnRequest,
    ) -> Result<pool::Pooled<PoolClient<B>, ConnKey>, Error> {
        loop {
            match self.one_connection_for(conn_req.clone()).await {
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
        conn_req: ConnRequest,
    ) -> Result<pool::Pooled<PoolClient<B>, ConnKey>, ClientConnectError> {
        // Return a single connection if pooling is not enabled
        if !self.pool.is_enabled() {
            return self
                .connect_to(conn_req)
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
        let checkout = self.pool.checkout(ConnKey(conn_req.extra.clone()));
        let connect = self.connect_to(conn_req);
        let is_ver_h2 = self.config.ver == Ver::Http2;

        // The order of the `select` is depended on below...

        match future::select(checkout, connect).await {
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
        conn_req: ConnRequest,
    ) -> impl Lazy<Output = Result<pool::Pooled<PoolClient<B>, ConnKey>, Error>> + Send + Unpin + 'static
    {
        let executor = self.exec.clone();
        let pool = self.pool.clone();

        let h1_builder = self.h1_builder.clone();
        let h2_builder = self.h2_builder.clone();
        let ver = match conn_req.extra.alpn_protocol {
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
            let connecting = match pool.connecting(ConnKey(conn_req.extra.clone()), ver) {
                Some(lock) => lock,
                None => {
                    let canceled = e!(Canceled);
                    // HTTP/2 connection in progress.
                    return Either::Right(future::err(canceled));
                }
            };
            Either::Left(
                connector
                    .connect(connect::sealed::Internal, conn_req)
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
                                    return Either::Right(future::err(canceled));
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

impl<C, B> tower_service::Service<Request<B>> for Client<C, B>
where
    C: Connect + Clone + Send + Sync + 'static,
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

impl<C, B> tower_service::Service<Request<B>> for &'_ Client<C, B>
where
    C: Connect + Clone + Send + Sync + 'static,
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

impl<C: Clone, B> Clone for Client<C, B> {
    fn clone(&self) -> Client<C, B> {
        Client {
            config: self.config,
            exec: self.exec.clone(),

            h1_builder: self.h1_builder.clone(),
            h2_builder: self.h2_builder.clone(),
            connector: self.connector.clone(),
            pool: self.pool.clone(),
        }
    }
}

impl<C, B> fmt::Debug for Client<C, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish()
    }
}

// ===== impl ResponseFuture =====

impl ResponseFuture {
    fn new<F>(value: F) -> Self
    where
        F: Future<Output = Result<Response<Incoming>, Error>> + Send + 'static,
    {
        Self {
            inner: SyncWrapper::new(Box::pin(value)),
        }
    }

    fn error_version(_ver: Version) -> Self {
        warn!("Request has unsupported version \"{:?}\"", _ver);
        ResponseFuture::new(Box::pin(future::err(e!(UserUnsupportedVersion))))
    }
}

impl fmt::Debug for ResponseFuture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("Future<Response>")
    }
}

impl Future for ResponseFuture {
    type Output = Result<Response<Incoming>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.inner.get_mut().as_mut().poll(cx)
    }
}

// ===== impl PoolClient =====

// FIXME: allow() required due to `impl Trait` leaking types to this lint
#[allow(missing_debug_implementations)]
struct PoolClient<B> {
    conn_info: Connected,
    tx: PoolTx<B>,
}

enum PoolTx<B> {
    Http1(conn::http1::SendRequest<B>),

    Http2(conn::http2::SendRequest<B>),
}

impl<B> PoolClient<B> {
    fn poll_ready(
        &mut self,
        #[allow(unused_variables)] cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Error>> {
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

enum ClientConnectError {
    Normal(Error),
    CheckoutIsClosed(pool::Error),
}

fn origin_form(uri: &mut Uri) {
    let path = match uri.path_and_query() {
        Some(path) if path.as_str() != "/" => {
            let mut parts = ::http::uri::Parts::default();
            parts.path_and_query = Some(path.clone());
            Uri::from_parts(parts).expect("path is valid uri")
        }
        _none_or_just_slash => {
            debug_assert!(Uri::default() == "/");
            Uri::default()
        }
    };
    *uri = path
}

fn absolute_form(uri: &mut Uri) {
    debug_assert!(uri.scheme().is_some(), "absolute_form needs a scheme");
    debug_assert!(
        uri.authority().is_some(),
        "absolute_form needs an authority"
    );
    // If the URI is to HTTPS, and the connector claimed to be a proxy,
    // then it *should* have tunneled, and so we don't want to send
    // absolute-form in that case.
    if uri.scheme() == Some(&Scheme::HTTPS) {
        origin_form(uri);
    }
}

fn authority_form(uri: &mut Uri) {
    if let Some(path) = uri.path_and_query() {
        // `https://hyper.rs` would parse with `/` path, don't
        // annoy people about that...
        if path != "/" {
            warn!("HTTP/1.1 CONNECT request stripping path: {:?}", path);
        }
    }
    *uri = match uri.authority() {
        Some(auth) => {
            let mut parts = ::http::uri::Parts::default();
            parts.authority = Some(auth.clone());
            Uri::from_parts(parts).expect("authority is valid")
        }
        None => {
            unreachable!("authority_form with relative uri");
        }
    };
}

fn extract_request_configs(
    extensions: &mut http::Extensions,
) -> (
    Option<TransportConfig>,
    Option<Version>,
    Option<ProxyMacher>,
    Option<TcpConnectOptions>,
) {
    let transport_config = RequestConfig::<RequestTransportConfig>::remove(extensions);
    let version = RequestConfig::<RequestEnforcedHttpVersion>::remove(extensions);
    let proxy = RequestConfig::<RequestProxyMatcher>::remove(extensions);
    let tcp = RequestConfig::<RequestTcpConnectOptions>::remove(extensions);
    (transport_config, version, proxy, tcp)
}

fn normalize_uri<B>(req: &mut Request<B>, is_http_connect: bool) -> Result<Uri, Error> {
    let uri = req.uri().clone();

    let build_base_uri = |scheme: Scheme, authority: Authority| {
        Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query(PathAndQuery::from_static("/"))
            .build()
            .expect("valid base URI")
    };

    match (uri.scheme(), uri.authority()) {
        (Some(scheme), Some(auth)) => Ok(build_base_uri(scheme.clone(), auth.clone())),
        (None, Some(auth)) if is_http_connect => {
            let scheme = match auth.port_u16() {
                Some(443) => Scheme::HTTPS,
                _ => Scheme::HTTP,
            };
            set_scheme(req.uri_mut(), scheme.clone());
            Ok(build_base_uri(scheme, auth.clone()))
        }
        _ => {
            debug!("Client requires absolute-form URIs, received: {:?}", uri);
            Err(e!(UserAbsoluteUriRequired))
        }
    }
}

fn set_scheme(uri: &mut Uri, scheme: Scheme) {
    debug_assert!(
        uri.scheme().is_none(),
        "set_scheme expects no existing scheme"
    );
    let old = std::mem::take(uri);
    let mut parts: ::http::uri::Parts = old.into();
    parts.scheme = Some(scheme);
    parts.path_and_query = Some("/".parse().expect("slash is a valid path"));
    *uri = Uri::from_parts(parts).expect("scheme is valid");
}

fn get_non_default_port(uri: &Uri) -> Option<http::uri::Port<&str>> {
    match (uri.port().map(|p| p.as_u16()), is_schema_secure(uri)) {
        (Some(443), true) => None,
        (Some(80), false) => None,
        _ => uri.port(),
    }
}

fn is_schema_secure(uri: &Uri) -> bool {
    uri.scheme_str()
        .map(|scheme_str| matches!(scheme_str, "wss" | "https"))
        .unwrap_or_default()
}

/// A builder to configure a new [`Client`].
///
/// # Example
///
/// ```
/// #
/// # fn run () {
/// use crate::{
///     core::rt::TokioExecutor,
///     util::client::Client,
/// };
/// use std::time::Duration;
///
/// let client = Client::builder(TokioExecutor::new())
///     .pool_idle_timeout(Duration::from_secs(30))
///     .http2_only(true)
///     .build_http();
/// # let infer: Client<_, http_body_util::Full<bytes::Bytes>> = client;
/// # drop(infer);
/// # }
/// # fn main() {}
/// ```
#[derive(Clone)]
pub struct Builder {
    client_config: Config,
    exec: Exec,

    h1_builder: conn::http1::Builder,
    h2_builder: conn::http2::Builder<Exec>,
    pool_config: pool::Config,
    pool_timer: Option<timer::Timer>,
}

impl Builder {
    /// Construct a new Builder.
    pub fn new<E>(executor: E) -> Self
    where
        E: crate::core::rt::Executor<BoxSendFuture> + Send + Sync + Clone + 'static,
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
    ///
    /// # Example
    ///
    /// ```
    /// #
    /// # fn run () {
    /// use crate::{
    ///     core::rt::{
    ///         TokioExecutor,
    ///         TokioTimer,
    ///     },
    ///     util::client::Client,
    /// };
    /// use std::time::Duration;
    ///
    /// let client = Client::builder(TokioExecutor::new())
    ///     .pool_idle_timeout(Duration::from_secs(30))
    ///     .pool_timer(TokioTimer::new())
    ///     .build_http();
    ///
    /// # let infer: Client<_, http_body_util::Full<bytes::Bytes>> = client;
    /// # }
    /// # fn main() {}
    /// ```
    pub fn pool_idle_timeout<D>(&mut self, val: D) -> &mut Self
    where
        D: Into<Option<Duration>>,
    {
        self.pool_config.idle_timeout = val.into();
        self
    }

    /// Sets the maximum idle connection per host allowed in the pool.
    ///
    /// Default is `usize::MAX` (no limit).
    pub fn pool_max_idle_per_host(&mut self, max_idle: usize) -> &mut Self {
        self.pool_config.max_idle_per_host = max_idle;
        self
    }

    /// Sets the maximum number of connections in the pool.
    ///
    /// Default is `None` (no limit).
    pub fn pool_max_size(&mut self, max_size: impl Into<Option<NonZeroU32>>) -> &mut Self {
        self.pool_config.max_pool_size = max_size.into();
        self
    }

    /// Set whether the connection **must** use HTTP/2.
    ///
    /// The destination must either allow HTTP2 Prior Knowledge, or the
    /// `Connect` should be configured to do use ALPN to upgrade to `h2`
    /// as part of the connection process. This will not make the `Client`
    /// utilize ALPN by itself.
    ///
    /// Note that setting this to true prevents HTTP/1 from being allowed.
    ///
    /// Default is false.
    pub fn http2_only(&mut self, val: bool) -> &mut Self {
        self.client_config.ver = if val { Ver::Http2 } else { Ver::Auto };
        self
    }

    /// Provide a timer to be used for http2
    ///
    /// See the documentation of [`http2::client::Builder::timer`] for more
    /// details.
    ///
    /// [`http2::client::Builder::timer`]: https://docs.rs/http2/latest/http2/client/struct.Builder.html#method.timer
    pub fn http2_timer<M>(&mut self, timer: M) -> &mut Self
    where
        M: Timer + Send + Sync + 'static,
    {
        self.h2_builder.timer(timer);
        self
    }

    /// Provide a configuration for HTTP/1.
    pub fn http1_config(&mut self, config: Http1Config) -> &mut Self {
        self.h1_builder.config(config);
        self
    }

    /// Provide a configuration for HTTP/2.
    pub fn http2_config(&mut self, config: Http2Config) -> &mut Self {
        self.h2_builder.config(config);
        self
    }

    /// Provide a timer to be used for timeouts and intervals in connection pools.
    pub fn pool_timer<M>(&mut self, timer: M) -> &mut Self
    where
        M: Timer + Clone + Send + Sync + 'static,
    {
        self.pool_timer = Some(timer::Timer::new(timer.clone()));
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
    pub fn retry_canceled_requests(&mut self, val: bool) -> &mut Self {
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
    pub fn set_host(&mut self, val: bool) -> &mut Self {
        self.client_config.set_host = val;
        self
    }

    /// Combine the configuration of this builder with a connector to create a `Client`.
    pub fn build<C, B>(&self, connector: C) -> Client<C, B>
    where
        C: Connect + Clone,
        B: Body + Send,
        B::Data: Send,
    {
        let exec = self.exec.clone();
        let timer = self.pool_timer.clone();
        Client {
            config: self.client_config,
            exec: exec.clone(),

            h1_builder: self.h1_builder.clone(),
            h2_builder: self.h2_builder.clone(),
            connector,
            pool: pool::Pool::new(self.pool_config, exec, timer),
        }
    }
}

impl fmt::Debug for Builder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Builder")
            .field("client_config", &self.client_config)
            .field("pool_config", &self.pool_config)
            .finish()
    }
}

// ==== impl Error ====

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("crate::util::client::Error");
        f.field(&self.kind);
        if let Some(ref cause) = self.source {
            f.field(cause);
        }
        f.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "client error ({:?})", self.kind)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|e| &**e as _)
    }
}

impl Error {
    /// Returns true if this was an error from `Connect`.
    pub fn is_connect(&self) -> bool {
        matches!(self.kind, ErrorKind::Connect)
    }

    /// Returns the info of the client connection on which this error occurred.
    pub fn connect_info(&self) -> Option<&Connected> {
        self.connect_info.as_ref()
    }

    fn with_connect_info(self, connect_info: Connected) -> Self {
        Self {
            connect_info: Some(connect_info),
            ..self
        }
    }
    fn is_canceled(&self) -> bool {
        matches!(self.kind, ErrorKind::Canceled)
    }

    fn tx(src: crate::core::Error) -> Self {
        e!(SendRequest, src)
    }

    fn closed(src: crate::core::Error) -> Self {
        e!(ChannelClosed, src)
    }
}
