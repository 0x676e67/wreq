//! Low-level Tower service for request preparation, pool checkout, and unsent retries.
//!
//! [`Client`] prepares the connection config and pool key once, then checks out a sender
//! and applies the negotiated protocol and cookies. Unsent retries reuse the prepared
//! request without cloning its body.

use std::{
    future::{Future, poll_fn},
    mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

#[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
use http::{
    HeaderMap,
    header::{CONNECTION, SEC_WEBSOCKET_KEY, UPGRADE},
};
use http::{HeaderValue, Method, Response, Uri, Version, header::HOST, uri::Authority};
use netty::{body::Incoming, conn::TrySendError};
use tower::{BoxError, Service};
#[cfg(feature = "cookies")]
use {
    crate::cookie::{CookieStore, Cookies},
    http::header::COOKIE,
    std::sync::Arc,
};

use super::{
    error::{self, ErrorKind},
    pool, proto,
    request::RequestVersion,
};
use crate::{
    Body,
    config::{ConnectConfig, RequestConfig},
    conn,
    dns::DynResolver,
    ext::UriExt,
    protocol::Protocol,
    reuse,
    rt::{DynRuntime, Executor},
};

/// Maximum unsent or canceled-checkout retries performed within a single poll.
const MAX_ATTEMPTS_PER_POLL: usize = 2;

/// Client-wide settings assembled by [`ClientBuilder`](crate::ClientBuilder) to construct
/// the low-level [`Client`] service.
///
/// Bundles transport connector settings, pool policy, default connection options, protocol
/// mode, and optional cookie storage.
pub(super) struct Config {
    pub(super) protocol: Protocol,
    pub(super) conn_config: conn::Config,
    pub(super) pool_config: pool::Config,
    pub(super) config: ConnectConfig,
    #[cfg(feature = "cookies")]
    pub(super) cookie_store: Option<Arc<dyn CookieStore>>,
}

/// Internal HTTP service beneath [`crate::Client`].
///
/// Prepares requests once, checks out pooled senders, applies cookies and protocol
/// reconciliation, and retries unsent failures without cloning bodies.
#[derive(Clone)]
pub(super) struct Client {
    pool: pool::Pool<reuse::Key, conn::ConnectService, DynRuntime>,
    protocol: Protocol,
    config: RequestConfig<ConnectConfig>,
    #[cfg(feature = "cookies")]
    cookie_store: RequestConfig<Arc<dyn CookieStore>>,
}

/// Requests a dedicated HTTP/1 connection that bypasses the pool.
///
/// When `extended_connect` is set, dispatch first probes for an established HTTP/2 or HTTP/3
/// connection in the default group whose peer enabled extended CONNECT (RFC 8441, RFC 9220).
#[cfg(feature = "ws")]
#[derive(Clone, Copy)]
pub(super) struct DedicatedConnection {
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) extended_connect: bool,
}

/// Validated connection request and pool keys extracted once before dispatch.
struct Prepared {
    /// Origin, protocol mode, and merged connection options used when dialing.
    connect: conn::Request<ConnectConfig>,
    /// Pool compatibility key; absent for dedicated connections that bypass the pool.
    pool_key: Option<reuse::Key>,
    /// Allows reconciling an HTTPS `HTTP/2` request down to HTTP/1.1 if ALPN picks HTTP/1.
    negotiable: bool,
    /// Default-group key probed for an established extended CONNECT sender.
    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    extended_connect_key: Option<reuse::Key>,
}

/// Named response future returned by [`Client`].
///
/// Stored inline inside `Client`'s outer `Pending` box; boxing `Pending` would add a
/// second per-request allocation.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub(super) struct ResponseFuture(ResponseFutureKind);

#[allow(clippy::large_enum_variant)]
enum ResponseFutureKind {
    /// Request dispatch and retry state machine.
    Pending(Retry<Dispatch>),
    /// Request preparation failure deferred until the first poll.
    Error(Option<error::Error>),
}

/// Cold-path error and unsent request carried out of an [`Attempt`] for retry.
struct Retryable {
    error: error::Error,
    request: http::Request<Body>,
}

/// Terminal or retryable outcome of a single dispatch attempt.
enum AttemptOutcome<T> {
    /// Attempt completed with a response or terminal error.
    Done(Result<T, error::Error>),
    /// A shared checkout batch was canceled before connecting; retry intact.
    CheckoutCanceled(Box<Retryable>),
    /// Connection failed before encoding any bytes; retry only if `connection_reused`.
    Unsent {
        retry: Box<Retryable>,
        connection_reused: bool,
    },
}

/// Result of advancing an [`Attempt`]: either in-flight state `S` or a final outcome.
enum Step<S, T> {
    Pending(S),
    Ready(AttemptOutcome<T>),
}

/// Single-attempt state machine driven by [`Retry`], borrowing shared context across polls.
trait Attempt {
    type Output;
    type State;

    /// Starts a new attempt from `request` and polls it until it yields or finishes.
    fn start(
        &mut self,
        request: http::Request<Body>,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Step<Self::State, Self::Output>;

    /// Polls an in-flight attempt stored in `state`.
    fn poll(
        &mut self,
        state: &mut Self::State,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Poll<AttemptOutcome<Self::Output>>;
}

/// Retries a canceled checkout or an unsent request from a reused connection.
///
/// Restores the original URI, wire version, and auto-generated `Cookie` headers before
/// each retry, yielding after a bounded number of attempts per poll.
#[must_use = "futures do nothing unless you `.await` or poll them"]
struct Retry<A: Attempt> {
    attempt: A,
    uri: Uri,
    version: Version,
    #[cfg(feature = "cookies")]
    had_cookie: bool,
    state: RetryState<A::State>,
}

// `S` is `SendState` (~168 B) in production; boxing `Start` would add a per-request allocation.
#[allow(clippy::large_enum_variant)]
enum RetryState<S> {
    Start(http::Request<Body>),
    Running(S),
    Done,
}

/// Shared pool, cookie store, and prepared connection metadata for one HTTP dispatch.
struct Dispatch {
    pool: pool::Pool<reuse::Key, conn::ConnectService, DynRuntime>,
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn CookieStore>>,
    prepared: Prepared,
}

/// Per-attempt dispatch state owned by [`Retry`] while [`Dispatch`] is in flight.
enum SendState {
    /// Cold dial or queued checkout; boxed so warm hits do not pay for `Checkout + Request`.
    Checkout(Box<(pool::Checkout, http::Request<Body>)>),
    /// `future` drops before `pooled` so cancellation tears down the stream first.
    Sending {
        future: netty::conn::ResponseFuture<Body>,
        pooled: pool::Pooled,
        #[cfg(any(feature = "http2", feature = "http3"))]
        extended: bool,
        #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
        upgrade: Option<Http1Upgrade>,
    },
    Done,
}

/// Original RFC 6455 headers of a WebSocket handshake rewritten for extended CONNECT.
///
/// Boxed so non-WebSocket requests do not reserve space for a `HeaderMap` in [`State::Sending`].
/// Restored in order if the request returns unsent so a retry can fall back to HTTP/1.1.
#[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
struct Http1Upgrade(Box<HeaderMap>);

// ===== impl Config =====

impl Default for Config {
    fn default() -> Self {
        Self {
            conn_config: conn::Config::default(),
            config: ConnectConfig::default(),
            pool_config: pool::Config::default(),
            protocol: Protocol::Auto,
            #[cfg(feature = "cookies")]
            cookie_store: None,
        }
    }
}

// ===== impl Client =====

impl Client {
    /// Builds the shared connector, pool, and HTTP request service.
    pub(super) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        config: Config,
    ) -> crate::Result<Self> {
        let connector = conn::Connect::new(
            runtime.clone(),
            resolver,
            config.conn_config,
            &config.config,
        )?;
        Ok(Self {
            pool: pool::Pool::new(
                connector,
                runtime.clone(),
                config.pool_config,
                proto::Builder::new(runtime, &config.config, true),
            ),
            protocol: config.protocol,
            config: RequestConfig::new(config.config),
            #[cfg(feature = "cookies")]
            cookie_store: RequestConfig::new(config.cookie_store),
        })
    }
}

impl Service<http::Request<Body>> for Client {
    type Response = Response<Incoming>;
    type Error = BoxError;
    type Future = ResponseFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        let dispatch = match Prepared::prepare(&mut request, self.protocol, &self.config) {
            Ok(prepared) => Dispatch {
                #[cfg(feature = "cookies")]
                cookie_store: self.cookie_store.fetch(request.extensions()).cloned(),
                prepared,
                pool: self.pool.clone(),
            },
            Err(error) => return ResponseFuture(ResponseFutureKind::Error(Some(error))),
        };

        ResponseFuture(ResponseFutureKind::Pending(Retry::new(request, dispatch)))
    }
}

// ===== impl ResponseFuture =====

impl Future for ResponseFuture {
    type Output = Result<Response<Incoming>, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.get_mut().0 {
            ResponseFutureKind::Pending(retry) => Pin::new(retry).poll(cx),
            ResponseFutureKind::Error(error) => match error.take() {
                Some(error) => Poll::Ready(Err(error.into())),
                None => Poll::Pending,
            },
        }
    }
}

// ===== impl Retry =====

impl<A: Attempt> Retry<A> {
    /// Captures retry restoration metadata and defers the first attempt until polled.
    fn new(request: http::Request<Body>, attempt: A) -> Self {
        let uri = request.uri().clone();
        let version = request.version();
        #[cfg(feature = "cookies")]
        let had_cookie = request.headers().contains_key(COOKIE);

        Self {
            attempt,
            uri,
            version,
            #[cfg(feature = "cookies")]
            had_cookie,
            state: RetryState::Start(request),
        }
    }
}

impl<A: Attempt> Future for Retry<A>
where
    A: Unpin,
    A::State: Unpin,
{
    type Output = Result<A::Output, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Retry recovery follows hyper-util's legacy client.
        // Poll budgeting follows Hyper's HTTP/1 dispatcher.
        for _ in 0..MAX_ATTEMPTS_PER_POLL {
            let outcome = match &mut this.state {
                RetryState::Start(_) => {
                    let RetryState::Start(request) =
                        mem::replace(&mut this.state, RetryState::Done)
                    else {
                        return Poll::Pending;
                    };
                    match this.attempt.start(request, &this.uri, cx) {
                        Step::Pending(state) => {
                            this.state = RetryState::Running(state);
                            return Poll::Pending;
                        }
                        Step::Ready(outcome) => outcome,
                    }
                }
                RetryState::Running(state) => {
                    let outcome = ready!(this.attempt.poll(state, &this.uri, cx));
                    this.state = RetryState::Done;
                    outcome
                }
                RetryState::Done => return Poll::Pending,
            };

            let mut request = match outcome {
                AttemptOutcome::Done(result) => return Poll::Ready(result.map_err(Into::into)),
                AttemptOutcome::CheckoutCanceled(retry) => {
                    let Retryable {
                        error: _error,
                        request,
                    } = *retry;
                    trace!("singleton connection batch canceled, trying again (reason={_error:?})");
                    request
                }
                AttemptOutcome::Unsent {
                    retry,
                    connection_reused: true,
                } => {
                    let Retryable {
                        error: _error,
                        request,
                    } = *retry;
                    trace!("unstarted request canceled, trying again (reason={_error:?})");
                    request
                }
                AttemptOutcome::Unsent {
                    retry,
                    connection_reused: false,
                } => return Poll::Ready(Err(retry.error.into())),
            };

            *request.uri_mut() = this.uri.clone();
            *request.version_mut() = this.version;
            // Regenerate automatic cookies for the next protocol; retain user headers.
            #[cfg(feature = "cookies")]
            if !this.had_cookie {
                request.headers_mut().remove(COOKIE);
            }
            this.state = RetryState::Start(request);
        }

        // The next attempt has not registered a waker; resume it after yielding.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ===== impl Dispatch =====

impl Dispatch {
    /// Transitions after a completed pool checkout.
    fn on_checkout(
        &self,
        result: Result<pool::Pooled, BoxError>,
        request: http::Request<Body>,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Step<SendState, Response<Incoming>> {
        match result {
            Ok(pooled) => self.poll_send(
                request,
                pooled,
                #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
                None,
                uri,
                cx,
            ),
            Err(error) if pool::is_canceled(&*error) => {
                Step::Ready(AttemptOutcome::CheckoutCanceled(Box::new(Retryable {
                    error: error::Error::new(ErrorKind::Connect, error),
                    request,
                })))
            }
            Err(error) => Step::Ready(AttemptOutcome::Done(Err(error::Error::new(
                ErrorKind::Connect,
                error,
            )))),
        }
    }

    /// Reconciles `request` for `pooled`, applies cookies, sends, and polls once.
    fn poll_send(
        &self,
        mut request: http::Request<Body>,
        mut pooled: pool::Pooled,
        #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))] upgrade: Option<
            Http1Upgrade,
        >,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Step<SendState, Response<Incoming>> {
        let _extended = match reconcile(&mut request, &pooled, self.prepared.negotiable) {
            Ok(extended) => extended,
            Err(error) => return Step::Ready(AttemptOutcome::Done(Err(error))),
        };

        // Cookies keep the original request URI; only the wire target of a CONNECT changes.
        #[cfg(feature = "cookies")]
        if let Some(cookie_store) = self.cookie_store.as_deref() {
            apply_request_cookies(&mut request, cookie_store, uri, pooled.version());
        }

        let mut future = match pooled.send_request(request) {
            Ok(future) => future,
            Err(error) => {
                return Step::Ready(AttemptOutcome::Done(Err(
                    error.with_connect_info(pooled.connected().clone())
                )));
            }
        };

        match Pin::new(&mut future).poll(cx) {
            Poll::Pending => Step::Pending(SendState::Sending {
                future,
                pooled,
                #[cfg(any(feature = "http2", feature = "http3"))]
                extended: _extended,
                #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
                upgrade,
            }),
            Poll::Ready(result) => {
                drop(future);
                Step::Ready(self.finish(
                    result,
                    pooled,
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    _extended,
                    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
                    upgrade,
                    uri,
                ))
            }
        }
    }

    /// Finalizes a completed send, classifying unsent errors or attaching metadata and cookies.
    fn finish(
        &self,
        result: Result<Response<Incoming>, TrySendError<http::Request<Body>>>,
        mut pooled: pool::Pooled,
        #[cfg(any(feature = "http2", feature = "http3"))] extended: bool,
        #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))] upgrade: Option<
            Http1Upgrade,
        >,
        uri: &Uri,
    ) -> AttemptOutcome<Response<Incoming>> {
        let mut response = match result {
            Ok(response) => response,
            Err(mut error) => {
                let connection_reused = pooled.is_reused();
                let connect_info = pooled.connected().clone();
                let unnegotiated_h2 = pooled.version() == Version::HTTP_2
                    && uri.is_https()
                    && !connect_info.is_negotiated_h2();

                // A returned request was not sent; only protocol rejections are final,
                // since they repeat on the same connection.
                if !error.error().is_user()
                    && let Some(unsent) = error.take_message()
                {
                    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
                    let mut unsent = unsent;
                    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
                    if let Some(upgrade) = upgrade {
                        upgrade.restore(&mut unsent);
                    }

                    return AttemptOutcome::Unsent {
                        retry: Box::new(Retryable {
                            error: with_h2_alpn_context(
                                error::Error::new(ErrorKind::Canceled, error.into_error()),
                                unnegotiated_h2,
                            )
                            .with_connect_info(connect_info),
                            request: unsent,
                        }),
                        connection_reused,
                    };
                }

                // The peer's SETTINGS may have arrived while the send was pending.
                #[cfg(any(feature = "http2", feature = "http3"))]
                if extended && pooled.extended_connect() == Some(false) {
                    return AttemptOutcome::Done(Err(extended_connect_disabled(&pooled)));
                }

                return AttemptOutcome::Done(Err(with_h2_alpn_context(
                    error::Error::new(ErrorKind::SendRequest, error.into_error()),
                    unnegotiated_h2,
                )
                .with_connect_info(connect_info)));
            }
        };

        #[cfg(feature = "cookies")]
        if let Some(cookie_store) = self.cookie_store.as_deref() {
            store_response_cookies(&response, cookie_store, uri);
        }

        pooled.connected().set_extras(response.extensions_mut());
        response.extensions_mut().insert(pooled.connected().clone());

        // Multiplexed senders are shared; only busy HTTP/1 senders wait for readiness
        // before dropping so they can return to the pool once the response finishes.
        if pooled.version() != Version::HTTP_11 || !pooled.is_pool_enabled() || pooled.is_ready() {
            drop(pooled);
        } else {
            self.pool.execute(Box::pin(async move {
                let _ = poll_fn(|cx| pooled.poll_ready(cx)).await;
            }));
        }

        AttemptOutcome::Done(Ok(response))
    }
}

impl Attempt for Dispatch {
    type Output = Response<Incoming>;
    type State = SendState;

    fn start(
        &mut self,
        request: http::Request<Body>,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Step<Self::State, Self::Output> {
        // RFC 8441 §3 and RFC 9220 §3: extended CONNECT only after the peer enabled it.
        // A miss keeps the dedicated HTTP/1.1 upgrade without opening H2/H3.
        #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
        if let Some(pooled) = self
            .prepared
            .extended_connect_key
            .as_ref()
            .and_then(|key| self.pool.checkout_extended_connect(key))
        {
            let mut request = request;
            let upgrade = Http1Upgrade::into_extended_connect(&mut request, pooled.version());
            return self.poll_send(request, pooled, Some(upgrade), uri, cx);
        }

        let mut future = self
            .pool
            .checkout(self.prepared.pool_key.as_ref(), &self.prepared.connect);
        match Pin::new(&mut future).poll(cx) {
            Poll::Pending => Step::Pending(SendState::Checkout(Box::new((future, request)))),
            Poll::Ready(result) => {
                drop(future);
                self.on_checkout(result, request, uri, cx)
            }
        }
    }

    fn poll(
        &mut self,
        state: &mut Self::State,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Poll<AttemptOutcome<Self::Output>> {
        match state {
            SendState::Checkout(pending) => {
                let result = ready!(Pin::new(&mut pending.0).poll(cx));
                let SendState::Checkout(pending) = mem::replace(state, SendState::Done) else {
                    return Poll::Pending;
                };
                let (future, request) = *pending;
                drop(future);
                match self.on_checkout(result, request, uri, cx) {
                    Step::Pending(next) => {
                        *state = next;
                        Poll::Pending
                    }
                    Step::Ready(outcome) => Poll::Ready(outcome),
                }
            }
            SendState::Sending { future, .. } => {
                let result = ready!(Pin::new(future).poll(cx));
                let SendState::Sending {
                    pooled,
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    extended,
                    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
                    upgrade,
                    ..
                } = mem::replace(state, SendState::Done)
                else {
                    return Poll::Pending;
                };
                Poll::Ready(self.finish(
                    result,
                    pooled,
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    extended,
                    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
                    upgrade,
                    uri,
                ))
            }
            SendState::Done => Poll::Pending,
        }
    }
}

// ===== impl Prepared =====

impl Prepared {
    /// Validates `request` and freezes its pool key and connection config before dispatch.
    ///
    /// Redirect hops and user-level retries pass through here again.
    fn prepare(
        request: &mut http::Request<Body>,
        client_protocol: Protocol,
        config: &RequestConfig<ConnectConfig>,
    ) -> Result<Self, error::Error> {
        match request.version() {
            Version::HTTP_10 if request.method() == Method::CONNECT => {
                warn!("CONNECT is not allowed for HTTP/1.0");
                return Err(error::Error::from_kind(
                    ErrorKind::UserUnsupportedRequestMethod,
                ));
            }
            Version::HTTP_10 | Version::HTTP_11 => {}
            #[cfg(feature = "http2")]
            Version::HTTP_2 => {}
            #[cfg(feature = "http3")]
            Version::HTTP_3 => {}
            _unsupported => {
                warn!("Request has unsupported version: {:?}", _unsupported);
                return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion));
            }
        }

        // Senders must not generate userinfo (RFC 9110 section 4.2.4), and the
        // connection origin is taken from this authority:
        // <https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.4>
        if request
            .uri()
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        {
            request.uri_mut().set_userinfo("", None);
        }

        let extensions = request.extensions_mut();
        #[cfg(feature = "ws")]
        let dedicated = extensions.remove::<DedicatedConnection>();

        // Normalize wire versions to protocol choices; HTTP/1.0 and HTTP/1.1 share a pool.
        let version = RequestConfig::<RequestVersion>::default().remove(extensions);
        let uri = request.uri();

        // curl's ordinary H2 mode allows HTTPS negotiation; prior knowledge
        // remains explicit: https://curl.se/libcurl/c/CURLOPT_HTTP_VERSION.html
        let protocol = match version {
            Some(Version::HTTP_10 | Version::HTTP_11) => Some(Protocol::Http1),
            #[cfg(feature = "http2")]
            Some(Version::HTTP_2) if uri.is_https() && client_protocol != Protocol::Http2 => {
                Some(Protocol::Auto)
            }
            #[cfg(feature = "http2")]
            Some(Version::HTTP_2) => Some(Protocol::Http2),
            #[cfg(feature = "http3")]
            Some(Version::HTTP_3) => Some(Protocol::Http3),
            Some(_) => {
                return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion));
            }
            None => None,
        };

        let origin = uri.origin().map_err(|source| {
            debug!("Client requires absolute-form URIs, received: {uri:?}");
            error::Error::new(ErrorKind::UserAbsoluteUriRequired, source)
        })?;
        let negotiable = protocol == Some(Protocol::Auto);
        let protocol = protocol.unwrap_or(client_protocol);

        // HTTP/3 has no cleartext form; an https-to-http redirect also ends here:
        // https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1
        #[cfg(feature = "http3")]
        if protocol == Protocol::Http3 && !uri.is_https() {
            warn!("HTTP/3 requires an https URI");
            return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
                .with_context("HTTP/3 requires an https URI"));
        }

        let config = config
            .remove(request.extensions_mut())
            .unwrap_or_default()
            .with_base(config.as_ref());
        let connect = conn::Request::new(origin, protocol, config);
        let pool_key = cfg_select! {
            feature = "ws" => dedicated.is_none(),
            _ => true,
        }
        .then(|| connect.reuse_key(protocol));

        // Probe the default group only where it may be HTTP/2, or HTTP/3 over https. Without
        // Alt-Svc discovery, an automatic client's explicit HTTP/3 group is not probed.
        #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
        let extended_connect_key = (dedicated.is_some_and(|d| d.extended_connect)
            && match client_protocol {
                #[cfg(feature = "http2")]
                Protocol::Auto | Protocol::Http2 => true,
                #[cfg(feature = "http3")]
                Protocol::Http3 => request.uri().is_https(),
                _ => false,
            })
        .then(|| connect.reuse_key(client_protocol));

        Ok(Self {
            connect,
            pool_key,
            negotiable,
            #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
            extended_connect_key,
        })
    }
}

// ===== impl Http1Upgrade =====

#[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
impl Http1Upgrade {
    /// Rewrites the GET upgrade as extended CONNECT for a sender of `version`, keeping the
    /// other WebSocket fields ([RFC 8441 §5](https://www.rfc-editor.org/rfc/rfc8441#section-5),
    /// [RFC 9220 §3](https://www.rfc-editor.org/rfc/rfc9220#section-3)).
    #[must_use]
    fn into_extended_connect<B>(request: &mut http::Request<B>, version: Version) -> Self {
        *request.method_mut() = Method::CONNECT;
        *request.version_mut() = version;
        let extensions = request.extensions_mut();
        match version {
            #[cfg(feature = "http2")]
            Version::HTTP_2 => {
                extensions.insert(http2::ext::Protocol::from_static("websocket"));
            }
            #[cfg(feature = "http3")]
            Version::HTTP_3 => {
                extensions.insert(netty::http3::Protocol::WEBSOCKET);
            }
            _ => {}
        }
        let headers = mem::take(request.headers_mut());
        // Connection-specific fields are malformed in HTTP/2 and HTTP/3; the rest keep their order:
        // https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2
        // https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        let extended = request.headers_mut();
        extended.reserve(headers.len());
        for (name, value) in &headers {
            if ![UPGRADE, CONNECTION, SEC_WEBSOCKET_KEY].contains(name) {
                extended.append(name, value.clone());
            }
        }
        Self(Box::new(headers))
    }

    /// Restores the RFC 6455 GET after an unsent extended CONNECT, removing either marker.
    fn restore<B>(self, request: &mut http::Request<B>) {
        *request.method_mut() = Method::GET;
        *request.version_mut() = Version::HTTP_11;
        #[cfg(feature = "http2")]
        request.extensions_mut().remove::<http2::ext::Protocol>();
        #[cfg(feature = "http3")]
        request.extensions_mut().remove::<netty::http3::Protocol>();
        *request.headers_mut() = *self.0;
    }
}

/// Explains failures of HTTP/2 used over HTTPS without negotiating `h2` in ALPN.
#[must_use]
fn with_h2_alpn_context(error: error::Error, unnegotiated_h2: bool) -> error::Error {
    if unnegotiated_h2 {
        error.with_context(
            "HTTP/2 was used for HTTPS without reported h2 ALPN; \
             the peer may not support HTTP/2",
        )
    } else {
        error
    }
}

/// Adjusts `request` to match `pooled` and returns `true` if it uses extended CONNECT.
///
/// Sets the wire version for multiplexed or negotiable requests, rejects incompatible
/// versions on HTTP/1, and fills in the default port for plain CONNECT targets.
fn reconcile(
    request: &mut http::Request<Body>,
    pooled: &pool::Pooled,
    negotiable: bool,
) -> Result<bool, error::Error> {
    let extended = cfg_select! {
        any(feature = "http2", feature = "http3") => {{
            let extended = matched_extended_connect(request, pooled)?;
            if extended && pooled.extended_connect() == Some(false) {
                return Err(extended_connect_disabled(pooled));
            }
            extended
        }}
        _ => false,
    };

    let version = pooled.version();
    let multiplexed = version != Version::HTTP_11;
    if multiplexed || negotiable {
        *request.version_mut() = version;
    } else if !matches!(request.version(), Version::HTTP_10 | Version::HTTP_11) {
        warn!(
            "Connection is HTTP/1, but request requires {:?}",
            request.version()
        );
        return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
            .with_connect_info(pooled.connected().clone()));
    }

    if request.method() == Method::CONNECT && !extended {
        connect_target_port(request, multiplexed)?;
    }
    Ok(extended)
}

/// Returns `true` if `request` carries an extended CONNECT `:protocol` marker matching
/// `pooled`'s HTTP version ([RFC 8441 §4], [RFC 9220 §3]).
///
/// Fails instead of falling back to plain CONNECT when the marker targets a different version.
///
/// [RFC 8441 §4]: https://www.rfc-editor.org/rfc/rfc8441#section-4
/// [RFC 9220 §3]: https://www.rfc-editor.org/rfc/rfc9220#section-3
#[cfg(any(feature = "http2", feature = "http3"))]
fn matched_extended_connect<B>(
    request: &http::Request<B>,
    pooled: &pool::Pooled,
) -> Result<bool, error::Error> {
    let extensions = request.extensions();
    let http2 = cfg_select! {
        feature = "http2" => extensions.get::<http2::ext::Protocol>().is_some(),
        _ => false,
    };
    let http3 = cfg_select! {
        feature = "http3" => extensions.get::<netty::http3::Protocol>().is_some(),
        _ => false,
    };
    let matched = match pooled.version() {
        Version::HTTP_2 => http2,
        Version::HTTP_3 => http3,
        _ => false,
    };
    if (http2 || http3) && !matched {
        warn!("extended CONNECT protocol does not match the connection's HTTP version");
        return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
            .with_context("extended CONNECT protocol does not match the connection's HTTP version")
            .with_connect_info(pooled.connected().clone()));
    }
    Ok(matched)
}

/// Rejects extended CONNECT unless the peer enabled it (RFC 8441 §3, RFC 9220 §3).
#[must_use]
#[cfg(any(feature = "http2", feature = "http3"))]
fn extended_connect_disabled(pooled: &pool::Pooled) -> error::Error {
    warn!("peer did not enable extended CONNECT");
    error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
        .with_context("peer did not enable extended CONNECT")
        .with_connect_info(pooled.connected().clone())
}

/// Fills in the scheme's default port on a plain CONNECT target when omitted
/// ([RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6)).
///
/// On HTTP/2 and HTTP/3, also updates a matching `Host` header so it stays consistent with
/// `:authority` ([RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113#section-8.3.1),
/// [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1)).
fn connect_target_port<B>(
    request: &mut http::Request<B>,
    multiplexed: bool,
) -> Result<(), error::Error> {
    let uri = request.uri();
    let Some(authority) = uri.authority() else {
        return Ok(());
    };

    // `Uri` also accepts ports a u16 cannot hold; only an absent or empty port is elided.
    let port = authority
        .as_str()
        .rsplit('@')
        .next()
        .and_then(|host_port| host_port.strip_prefix(authority.host()));

    if !matches!(port, Some("" | ":")) {
        return Ok(());
    }

    let target = format!("{}:{}", authority.host(), uri.port_or_default())
        .parse::<Authority>()
        .map_err(|error| error::Error::new(ErrorKind::SendRequest, error))?;

    if multiplexed
        && request
            .headers()
            .get(HOST)
            .is_some_and(|host| host == authority.as_str())
    {
        let host = HeaderValue::from_str(target.as_str())
            .map_err(|error| error::Error::new(ErrorKind::SendRequest, error))?;
        request.headers_mut().insert(HOST, host);
    }

    let mut parts = mem::take(request.uri_mut()).into_parts();
    parts.authority = Some(target);
    *request.uri_mut() =
        Uri::from_parts(parts).map_err(|error| error::Error::new(ErrorKind::SendRequest, error))?;
    Ok(())
}

/// Populates `Cookie` headers from `cookie_store` unless the caller already set one.
#[cfg(feature = "cookies")]
fn apply_request_cookies<B>(
    request: &mut http::Request<B>,
    cookie_store: &dyn CookieStore,
    uri: &Uri,
    version: Version,
) {
    let headers = request.headers_mut();
    if headers.contains_key(COOKIE) {
        return;
    }
    match cookie_store.cookies(uri, version) {
        Cookies::Compressed(value) => {
            headers.insert(COOKIE, value);
        }
        Cookies::Uncompressed(values) => {
            for value in values {
                headers.append(COOKIE, value);
            }
        }
        Cookies::Empty => {}
    }
}

/// Persists any `Set-Cookie` response headers into `cookie_store`.
#[cfg(feature = "cookies")]
fn store_response_cookies(
    response: &Response<Incoming>,
    cookie_store: &dyn CookieStore,
    uri: &Uri,
) {
    let mut cookies = response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .peekable();
    if cookies.peek().is_some() {
        cookie_store.set_cookies(&mut cookies, uri);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures_util::future::{self, Ready};
    use tower::ServiceExt;

    use super::*;
    use crate::conn::{BoxedConnectLayer, Conn, Unnameable};

    impl<F, T> Attempt for F
    where
        F: FnMut(http::Request<Body>) -> AttemptOutcome<T>,
    {
        type Output = T;
        type State = std::convert::Infallible;

        fn start(
            &mut self,
            request: http::Request<Body>,
            _uri: &Uri,
            _cx: &mut Context<'_>,
        ) -> Step<Self::State, Self::Output> {
            Step::Ready(self(request))
        }

        fn poll(
            &mut self,
            state: &mut Self::State,
            _uri: &Uri,
            _cx: &mut Context<'_>,
        ) -> Poll<AttemptOutcome<Self::Output>> {
            match *state {}
        }
    }

    fn client(
        mut config: Config,
        connect: impl Fn(Unnameable) -> Ready<Result<Conn, BoxError>> + Clone + Send + Sync + 'static,
    ) -> Client {
        config
            .conn_config
            .layers
            .push(BoxedConnectLayer::new(tower::layer::layer_fn(move |_| {
                tower::service_fn(connect.clone())
            })));
        let runtime = DynRuntime::new(crate::rt::tokio::TokioRuntime);
        let resolver = DynResolver::new(runtime.resolver());
        Client::new(runtime, resolver, config).unwrap()
    }

    #[test]
    fn entry_checks_reject_requests_and_strip_userinfo_before_keying() {
        let connect_config = RequestConfig::new(ConnectConfig::default());
        let prepare = |mut request: http::Request<Body>| {
            Prepared::prepare(&mut request, Protocol::Auto, &connect_config)
                .map(|prepared| (request, prepared))
        };
        for (method, version, uri, kind) in [
            (
                Method::CONNECT,
                Version::HTTP_10,
                "http://localhost/",
                "UserUnsupportedRequestMethod",
            ),
            (
                Method::GET,
                Version::HTTP_09,
                "http://localhost/",
                "UserUnsupportedVersion",
            ),
            (
                Method::GET,
                Version::HTTP_11,
                "/relative",
                "UserAbsoluteUriRequired",
            ),
        ] {
            let request = http::Request::builder()
                .method(method)
                .version(version)
                .uri(uri)
                .body(Body::default())
                .unwrap();
            let Err(error) = prepare(request) else {
                panic!("{kind} must reject the request");
            };
            assert_eq!(error.to_string(), format!("client error ({kind})"));
        }

        let prepare_uri =
            |uri| prepare(http::Request::get(uri).body(Body::default()).unwrap()).unwrap();
        let (_, plain) = prepare_uri("http://localhost/");
        let (userinfo_req, userinfo) = prepare_uri("http://user:pw@localhost/");
        assert!(plain.pool_key.is_some());
        assert_eq!(userinfo_req.uri(), "http://localhost/");
        assert_eq!(userinfo.pool_key, plain.pool_key);

        #[cfg(feature = "ws")]
        {
            let request = http::Request::get("http://localhost/")
                .extension(RequestConfig::<RequestVersion>::new(Some(Version::HTTP_11)))
                .extension(DedicatedConnection {
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    extended_connect: true,
                })
                .body(Body::default())
                .unwrap();
            let (_, prepared) = prepare(request).unwrap();
            assert!(prepared.pool_key.is_none());
            #[cfg(feature = "http2")]
            assert_eq!(prepared.extended_connect_key, plain.pool_key);
        }
    }

    #[tokio::test]
    async fn unsent_retries_restore_request_state_and_respect_reused_flag() {
        use http_body_util::BodyExt;

        let connect_config = RequestConfig::new(ConnectConfig::default());
        for reused in [true, false] {
            let mut calls = 0;
            let mut request = http::Request::builder()
                .version(Version::HTTP_10)
                .uri("http://localhost/upload?part=1")
                .body(Body::from("payload"))
                .unwrap();
            let prepared =
                Prepared::prepare(&mut request, Protocol::Auto, &connect_config).unwrap();
            assert!(prepared.pool_key.is_some());

            let mut retry = Retry::new(request, |mut request: http::Request<Body>| {
                calls += 1;
                if calls == 1 {
                    *request.uri_mut() = Uri::from_static("/upload?part=1");
                    *request.version_mut() = Version::HTTP_2;
                    #[cfg(feature = "cookies")]
                    request
                        .headers_mut()
                        .append(COOKIE, HeaderValue::from_static("h2=1"));
                    AttemptOutcome::Unsent {
                        retry: Box::new(Retryable {
                            error: error::Error::new(
                                ErrorKind::Canceled,
                                std::io::Error::other("unsent"),
                            ),
                            request,
                        }),
                        connection_reused: reused,
                    }
                } else {
                    assert_eq!(request.uri(), "http://localhost/upload?part=1");
                    assert_eq!(request.version(), Version::HTTP_10);
                    #[cfg(feature = "cookies")]
                    assert!(!request.headers().contains_key(COOKIE));
                    if calls == 2 {
                        AttemptOutcome::CheckoutCanceled(Box::new(Retryable {
                            error: error::Error::from_kind(ErrorKind::Connect),
                            request,
                        }))
                    } else {
                        AttemptOutcome::Done(Ok(request.into_body()))
                    }
                }
            });

            let result = if reused {
                let mut task = tokio_test::task::spawn(retry);
                assert!(task.poll().is_pending());
                assert!(task.is_woken());
                let Poll::Ready(result) = task.poll() else {
                    panic!("the third attempt must finish on the next poll");
                };
                result
            } else {
                Pin::new(&mut retry).await
            };

            if reused {
                assert_eq!(calls, 3);
                let body = result.unwrap().collect().await.unwrap().to_bytes();
                assert_eq!(body, "payload");
            } else {
                let error = result.unwrap_err();
                assert_eq!(calls, 1);
                assert!(error.is::<error::Error>());
                assert_eq!(error.source().unwrap().to_string(), "unsent");
            }
        }

        #[cfg(feature = "cookies")]
        {
            let mut calls = 0;
            let request = http::Request::builder()
                .uri("https://localhost/")
                .header(COOKIE, "user=1")
                .header(COOKIE, "other=2")
                .body(Body::default())
                .unwrap();
            Retry::new(request, |request: http::Request<Body>| {
                let values: Vec<_> = request.headers().get_all(COOKIE).iter().collect();
                assert_eq!(values, ["user=1", "other=2"]);
                calls += 1;
                if calls == 1 {
                    AttemptOutcome::Unsent {
                        retry: Box::new(Retryable {
                            error: error::Error::from_kind(ErrorKind::Canceled),
                            request,
                        }),
                        connection_reused: true,
                    }
                } else {
                    AttemptOutcome::Done(Ok(()))
                }
            })
            .await
            .unwrap();
            assert_eq!(calls, 2);
        }
    }

    #[tokio::test]
    async fn connect_config_reaches_the_connector_without_partitioning_the_pool() {
        use bytes::Bytes;
        use http_body_util::Empty;

        struct DialOption(u8);

        let attempts = Arc::new(crate::sync::Mutex::new(Vec::new()));
        let connect = {
            let attempts = attempts.clone();
            move |Unnameable(request)| {
                attempts.lock().push(
                    request
                        .body()
                        .get_ref::<DialOption>()
                        .map(|option| option.0),
                );
                let (client, server) = tokio::io::duplex(4096);
                let service = hyper::service::service_fn(|_| async {
                    Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new()))
                });
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(server), service),
                );
                future::ready(Ok::<_, BoxError>(Conn::test(client)))
            }
        };
        let mut config = ConnectConfig::default();
        config.insert(DialOption(1));
        let mut client = client(
            Config {
                protocol: Protocol::Http1,
                config,
                ..Config::default()
            },
            connect,
        );
        for (uri, option) in [
            ("http://localhost/", None),
            ("http://localhost/", Some(DialOption(2))),
            ("http://localhost:8080/", Some(DialOption(3))),
        ] {
            let mut request = http::Request::get(uri).body(Body::default()).unwrap();
            if let Some(option) = option {
                RequestConfig::<ConnectConfig>::get_mut(request.extensions_mut())
                    .get_or_insert_default()
                    .insert(option);
            }
            let response = client.ready().await.unwrap().call(request).await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
        }
        assert_eq!(*attempts.lock(), [Some(1), Some(3)]);
    }

    #[cfg(feature = "cookies")]
    #[tokio::test]
    async fn cookies_keep_the_request_uri_of_a_connect_target() {
        use std::convert::Infallible;

        use http_body_util::BodyExt;

        #[derive(Default)]
        struct Recorder(crate::sync::Mutex<Vec<String>>);

        impl CookieStore for Recorder {
            fn set_cookies(&self, _: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri) {
                self.0.lock().push(format!("set {uri}"));
            }

            fn cookies(&self, uri: &Uri, _: Version) -> Cookies {
                self.0.lock().push(format!("get {uri}"));
                Cookies::Compressed(HeaderValue::from_static("a=1"))
            }
        }

        let connect = |_: Unnameable| {
            let (client, server) = tokio::io::duplex(16384);
            let service =
                hyper::service::service_fn(|request: http::Request<hyper::body::Incoming>| {
                    let target = format!("{} {:?}", request.uri(), request.headers()[COOKIE]);
                    future::ready(Ok::<_, Infallible>(
                        Response::builder()
                            .status(http::StatusCode::FORBIDDEN)
                            .header(http::header::SET_COOKIE, "b=2")
                            .body(target)
                            .unwrap(),
                    ))
                });
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(server), service),
            );
            future::ready(Ok::<_, BoxError>(crate::conn::Conn::test(client)))
        };
        let store = Arc::new(Recorder::default());
        let client = client(
            Config {
                cookie_store: Some(store.clone()),
                ..Config::default()
            },
            connect,
        );
        let response = client
            .oneshot(
                http::Request::connect("http://localhost/")
                    .body(Body::default())
                    .unwrap(),
            )
            .await
            .unwrap();

        let target = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(target, "localhost:80 \"a=1\"");
        assert_eq!(
            *store.0.lock(),
            ["get http://localhost/", "set http://localhost/"]
        );
    }

    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    #[test]
    fn websocket_upgrade_is_restored_after_extended_connect() {
        for version in [
            #[cfg(feature = "http2")]
            Version::HTTP_2,
            #[cfg(feature = "http3")]
            Version::HTTP_3,
        ] {
            let mut request = http::Request::get("https://localhost/chat")
                .version(Version::HTTP_11)
                .header(http::header::SEC_WEBSOCKET_VERSION, "13")
                .header(UPGRADE, "websocket")
                .header(http::header::ORIGIN, "https://localhost")
                .header(CONNECTION, "upgrade")
                .header(SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
                .header(http::header::SEC_WEBSOCKET_PROTOCOL, "chat")
                .body(())
                .unwrap();
            let original = request.headers().clone();
            let upgrade = Http1Upgrade::into_extended_connect(&mut request, version);

            assert_eq!(request.method(), Method::CONNECT);
            assert_eq!(request.version(), version);
            #[cfg(feature = "http2")]
            assert_eq!(
                request
                    .extensions()
                    .get::<http2::ext::Protocol>()
                    .map(http2::ext::Protocol::as_str),
                (version == Version::HTTP_2).then_some("websocket")
            );
            #[cfg(feature = "http3")]
            assert_eq!(
                request.extensions().get::<netty::http3::Protocol>(),
                (version == Version::HTTP_3).then_some(&netty::http3::Protocol::WEBSOCKET)
            );
            assert!(request.headers().keys().map(|name| name.as_str()).eq([
                "sec-websocket-version",
                "origin",
                "sec-websocket-protocol"
            ]));

            upgrade.restore(&mut request);
            assert_eq!(request.method(), Method::GET);
            assert_eq!(request.version(), Version::HTTP_11);
            #[cfg(feature = "http2")]
            assert!(request.extensions().get::<http2::ext::Protocol>().is_none());
            #[cfg(feature = "http3")]
            assert!(
                request
                    .extensions()
                    .get::<netty::http3::Protocol>()
                    .is_none()
            );
            assert!(request.headers().iter().eq(original.iter()));
        }
    }
}
