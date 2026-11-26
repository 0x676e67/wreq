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
    upgrade,
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
    pub(super) connect: conn::Config,
    pub(super) pool_config: pool::Config,
    pub(super) connect_config: ConnectConfig,
    pub(super) protocol: Protocol,
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
    config: ConnectConfig,
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn CookieStore>>,
}

/// Validated connection request and pool keys extracted once before dispatch.
struct Prepared {
    /// Origin, protocol mode, and merged connection options used when dialing.
    connect: conn::Request<ConnectConfig>,
    /// Pool compatibility key; absent for dedicated connections that bypass the pool.
    pool_key: Option<reuse::Key>,
    /// Allows reconciling an HTTPS `HTTP/2` request down to HTTP/1.1 if ALPN picks HTTP/1.
    negotiable: bool,
    /// Prepared Extended CONNECT or adaptive upgrade plan, boxed to keep `Prepared` compact.
    #[cfg(any(feature = "http2", feature = "http3"))]
    upgrade: Option<Box<upgrade::Plan>>,
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
        #[cfg(any(feature = "http2", feature = "http3"))]
        rewritten: Option<Box<upgrade::Rewritten>>,
    },
    Done,
}

// ===== impl Config =====

impl Default for Config {
    fn default() -> Self {
        Self {
            connect: conn::Config::default(),
            connect_config: ConnectConfig::default(),
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
            config.connect,
            &config.connect_config,
        )?;
        Ok(Self {
            pool: pool::Pool::new(
                connector,
                runtime.clone(),
                config.pool_config,
                proto::Builder::new(runtime, &config.connect_config, true),
            ),
            protocol: config.protocol,
            config: config.connect_config,
            #[cfg(feature = "cookies")]
            cookie_store: config.cookie_store,
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
        let prepared = match Prepared::prepare(&mut request, self.protocol, &self.config) {
            Ok(prepared) => prepared,
            Err(error) => return ResponseFuture(ResponseFutureKind::Error(Some(error))),
        };

        #[cfg(feature = "cookies")]
        let cookie_store = RequestConfig::<Arc<dyn CookieStore>>::get(request.extensions())
            .cloned()
            .or_else(|| self.cookie_store.clone());

        ResponseFuture(ResponseFutureKind::Pending(Retry::new(
            request,
            Dispatch {
                pool: self.pool.clone(),
                #[cfg(feature = "cookies")]
                cookie_store,
                prepared,
            },
        )))
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
                #[cfg(any(feature = "http2", feature = "http3"))]
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
        #[cfg(any(feature = "http2", feature = "http3"))] rewritten: Option<
            Box<upgrade::Rewritten>,
        >,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Step<SendState, Response<Incoming>> {
        let _extended = match reconcile(
            &mut request,
            &pooled,
            self.prepared.negotiable,
            #[cfg(any(feature = "http2", feature = "http3"))]
            self.prepared.upgrade.as_deref(),
            #[cfg(any(feature = "http2", feature = "http3"))]
            rewritten.is_some(),
        ) {
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
                #[cfg(any(feature = "http2", feature = "http3"))]
                rewritten,
            }),
            Poll::Ready(result) => {
                drop(future);
                Step::Ready(self.finish(
                    result,
                    pooled,
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    _extended,
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    rewritten,
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
        #[cfg(any(feature = "http2", feature = "http3"))] rewritten: Option<
            Box<upgrade::Rewritten>,
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
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    let mut unsent = unsent;
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    if let Some(rewritten) = rewritten {
                        rewritten.restore(&mut unsent);
                    } else if extended {
                        upgrade::Protocol::clear_from(&mut unsent);
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
        #[allow(unused_mut)] mut request: http::Request<Body>,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Step<Self::State, Self::Output> {
        // RFC 8441 §3 and RFC 9220 §3: extended CONNECT only after the peer enabled it.
        // A miss keeps the dedicated HTTP/1.1 upgrade without opening H2/H3.
        #[cfg(any(feature = "http2", feature = "http3"))]
        if let Some(upgrade::Plan::Adaptive {
            key,
            protocol,
            strip_headers,
        }) = self.prepared.upgrade.as_deref()
            && let Some(pooled) = self.pool.checkout_extended_connect(key)
        {
            if let Some(rewritten) = upgrade::Rewritten::try_rewrite(
                &mut request,
                pooled.version(),
                protocol,
                strip_headers.as_deref().unwrap_or(&[]),
            ) {
                return self.poll_send(request, pooled, Some(rewritten), uri, cx);
            }
            drop(pooled);
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
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    rewritten,
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
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    rewritten,
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
        connect_config: &ConnectConfig,
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
        let upgrade = RequestConfig::<upgrade::Upgrade>::remove(extensions);
        // Normalize wire versions to protocol choices; HTTP/1.0 and HTTP/1.1 share a pool.
        let version = RequestConfig::<RequestVersion>::remove(extensions);
        let uri = request.uri();

        let dedicated = match upgrade.as_ref() {
            Some(upgrade) => {
                upgrade.validate_request(request.method(), request.version(), version)?
            }
            None => false,
        };

        // curl's ordinary H2 mode allows HTTPS negotiation; prior knowledge
        // remains explicit: https://curl.se/libcurl/c/CURLOPT_HTTP_VERSION.html
        let protocol = if dedicated {
            Some(Protocol::Http1)
        } else {
            match version {
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
            }
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

        // Attach client defaults to any request-level connection overrides.
        let config = request
            .extensions_mut()
            .remove::<ConnectConfig>()
            .unwrap_or_default()
            .with_base(connect_config);
        let connect = conn::Request::new(origin, protocol, config);
        let pool_key = (!dedicated).then(|| connect.reuse_key(protocol));

        #[cfg(any(feature = "http2", feature = "http3"))]
        let upgrade = match upgrade {
            Some(upgrade) => upgrade.into_plan(
                protocol,
                client_protocol,
                request.uri().is_https(),
                |protocol| connect.reuse_key(protocol),
            )?,
            None => None,
        };

        Ok(Self {
            connect,
            pool_key,
            negotiable,
            #[cfg(any(feature = "http2", feature = "http3"))]
            upgrade,
        })
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
    #[cfg(any(feature = "http2", feature = "http3"))] plan: Option<&upgrade::Plan>,
    #[cfg(any(feature = "http2", feature = "http3"))] rewritten: bool,
) -> Result<bool, error::Error> {
    let extended = cfg_select! {
        any(feature = "http2", feature = "http3") => {
            if rewritten {
                true
            } else if let Some(upgrade::Plan::ExtendedConnect(protocol)) = plan {
                protocol
                    .insert_into(request, pooled.version())
                    .map_err(|error| error.with_connect_info(pooled.connected().clone()))?;
                if pooled.extended_connect() == Some(false) {
                    return Err(extended_connect_disabled(pooled));
                }
                true
            } else {
                false
            }
        }
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
            .connect
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
        let connect_config = ConnectConfig::default();
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

        let prepare_upgrade =
            |method: Method, version: Option<Version>, mode: Protocol, u: upgrade::Upgrade| {
                let mut builder = http::Request::builder()
                    .method(method)
                    .uri("https://localhost/");
                if let Some(version) = version {
                    builder = builder
                        .version(version)
                        .extension(RequestConfig::<RequestVersion>::new(Some(version)));
                }
                let mut request = builder
                    .extension(RequestConfig::<upgrade::Upgrade>::new(Some(u)))
                    .body(Body::default())
                    .unwrap();
                Prepared::prepare(&mut request, mode, &connect_config)
            };

        let (_, plain_https) = prepare_uri("https://localhost/");
        let http1 =
            prepare_upgrade(Method::GET, None, Protocol::Auto, upgrade::Upgrade::http1()).unwrap();
        assert!(http1.pool_key.is_none());
        #[cfg(any(feature = "http2", feature = "http3"))]
        assert!(http1.upgrade.is_none());

        let adaptive = prepare_upgrade(
            Method::GET,
            None,
            Protocol::Auto,
            upgrade::Upgrade::adaptive(upgrade::Protocol::WEBSOCKET),
        )
        .unwrap();
        assert!(adaptive.pool_key.is_none());
        #[cfg(feature = "http2")]
        assert!(matches!(
            adaptive.upgrade.as_deref(),
            Some(upgrade::Plan::Adaptive { key, .. }) if plain_https.pool_key.as_ref() == Some(key)
        ));

        for (method, version, mode, u, expected) in [
            (
                Method::GET,
                None,
                Protocol::Auto,
                upgrade::Upgrade::extended_connect(upgrade::Protocol::WEBSOCKET),
                "client error (UserUnsupportedRequestMethod)",
            ),
            (
                Method::CONNECT,
                Some(Version::HTTP_11),
                Protocol::Auto,
                upgrade::Upgrade::extended_connect(upgrade::Protocol::WEBSOCKET),
                "client error (UserUnsupportedVersion): extended CONNECT requires HTTP/2 or HTTP/3",
            ),
            #[cfg(feature = "http2")]
            (
                Method::GET,
                Some(Version::HTTP_2),
                Protocol::Auto,
                upgrade::Upgrade::http1(),
                "client error (UserUnsupportedVersion)",
            ),
            #[cfg(feature = "http3")]
            (
                Method::CONNECT,
                None,
                Protocol::Http3,
                upgrade::Upgrade::extended_connect(upgrade::Protocol::from_static("custom")),
                "client error (UserUnsupportedVersion): extended CONNECT protocol is not supported on HTTP/3",
            ),
        ] {
            assert_eq!(
                prepare_upgrade(method, version, mode, u)
                    .err()
                    .unwrap()
                    .to_string(),
                expected
            );
        }

        // Adaptive upgrade skips HTTP/3 probing when the protocol is unsupported on HTTP/3.
        #[cfg(feature = "http3")]
        {
            let adaptive_h3 = prepare_upgrade(
                Method::GET,
                None,
                Protocol::Http3,
                upgrade::Upgrade::adaptive(upgrade::Protocol::from_static("custom")),
            )
            .unwrap();
            assert!(adaptive_h3.pool_key.is_none() && adaptive_h3.upgrade.is_none());
        }
    }

    #[tokio::test]
    async fn unsent_retries_restore_request_state_and_respect_reused_flag() {
        use http_body_util::BodyExt;

        let connect_config = ConnectConfig::default();
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
        let mut connect_config = ConnectConfig::default();
        connect_config.insert(DialOption(1));
        let mut client = client(
            Config {
                protocol: Protocol::Http1,
                connect_config,
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
                let mut connect_config = ConnectConfig::default();
                connect_config.insert(option);
                request.extensions_mut().insert(connect_config);
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

    #[cfg(any(feature = "http2", feature = "http3"))]
    #[test]
    fn adaptive_upgrade_is_restored_after_extended_connect() {
        use http::{
            HeaderName,
            header::{CONNECTION, SEC_WEBSOCKET_KEY, UPGRADE},
        };

        const CUSTOM_KEY: HeaderName = HeaderName::from_static("x-upgrade-nonce");
        for (method, orig_version, target_version, protocol, strip) in [
            #[cfg(feature = "http2")]
            (
                Method::GET,
                Version::HTTP_11,
                Version::HTTP_2,
                upgrade::Protocol::WEBSOCKET,
                SEC_WEBSOCKET_KEY,
            ),
            #[cfg(feature = "http3")]
            (
                Method::GET,
                Version::HTTP_11,
                Version::HTTP_3,
                upgrade::Protocol::WEBSOCKET,
                SEC_WEBSOCKET_KEY,
            ),
            #[cfg(feature = "http2")]
            (
                Method::POST,
                Version::HTTP_10,
                Version::HTTP_2,
                upgrade::Protocol::from_static("custom"),
                CUSTOM_KEY,
            ),
        ] {
            let mut request = http::Request::builder()
                .method(method.clone())
                .uri("https://localhost/chat")
                .version(orig_version)
                .header(http::header::ORIGIN, "https://localhost")
                .header(UPGRADE, protocol.as_str())
                .header(CONNECTION, "upgrade")
                .header(strip.clone(), "nonce")
                .header("x-keep", "1")
                .body(())
                .unwrap();
            let original = request.headers().clone();
            let rewritten =
                upgrade::Rewritten::try_rewrite(&mut request, target_version, &protocol, &[strip])
                    .unwrap();

            assert_eq!(request.method(), Method::CONNECT);
            assert_eq!(request.version(), target_version);
            #[cfg(feature = "http2")]
            assert_eq!(
                request
                    .extensions()
                    .get::<http2::ext::Protocol>()
                    .map(http2::ext::Protocol::as_str),
                (target_version == Version::HTTP_2).then_some(protocol.as_str())
            );
            #[cfg(feature = "http3")]
            assert_eq!(
                request.extensions().get::<netty::http3::Protocol>(),
                (target_version == Version::HTTP_3).then_some(&netty::http3::Protocol::WEBSOCKET)
            );
            assert!(
                request
                    .headers()
                    .keys()
                    .map(|name| name.as_str())
                    .eq(["origin", "x-keep"])
            );

            rewritten.restore(&mut request);
            assert_eq!(request.method(), method);
            assert_eq!(request.version(), orig_version);
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
