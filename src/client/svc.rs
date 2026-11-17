//! Tower services used by the low-level client request path.
//!
//! Configuration runs once before internal retries. Each attempt checks out a sender, fits the
//! request to it, and dispatches it, handing a busy HTTP/1 sender to a readiness task. Only
//! requests returned before encoding can be retried; bodies are never reconstructed.

use std::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures_util::future::{self, BoxFuture, Either, Ready};
#[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
use http::{
    HeaderMap,
    header::{CONNECTION, SEC_WEBSOCKET_KEY, UPGRADE},
};
use http::{HeaderValue, Method, Request, Response, Uri, Version, header::HOST, uri::Authority};
use netty::body::Incoming;
use pin_project_lite::pin_project;
use tower::{BoxError, Layer, Service, ServiceExt, layer::layer_fn, util::Oneshot};
#[cfg(feature = "cookies")]
use {
    crate::cookie::{CookieStore, Cookies},
    http::header::COOKIE,
    std::sync::Arc,
};

use super::{
    error::{Error, ErrorKind},
    pool::{self, ConnectService, PoolKey},
    request::RequestVersion,
};
use crate::{
    Body,
    config::{connect::ConnectConfig, request::RequestConfig},
    ext::UriExt,
    protocol::Protocol,
    rt::DynRuntime,
};

/// Low-level Tower client service beneath [`crate::Client`].
/// Applies request validation, unsent retries, pool checkout and protocol dispatch.
pub(super) type Client<C> = Stack<Dispatch<C>>;

/// Checks and configures requests, then drives unsent retries and terminal error mapping.
/// Client values are shared; request-local options are captured once before any attempt,
/// without cloning the body.
#[derive(Clone)]
pub(super) struct Stack<S> {
    inner: S,
    protocol: Protocol,
    config: ConnectConfig,
    retry_unsent: bool,
}

/// Requests a new HTTP/1 connection that is never taken from or returned to the pool.
///
/// With `extended_connect`, dispatch first tries an established connection of the
/// default request group whose peer enabled extended CONNECT (RFC 8441, RFC 9220).
#[cfg(feature = "ws")]
#[derive(Clone, Copy)]
pub(super) struct DedicatedConnection {
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) extended_connect: bool,
}

pin_project! {
    /// Drives internal retries without cloning the request body.
    /// The first call consumes the caller's readiness reservation; subsequent
    /// attempts use `Oneshot` to pair readiness and dispatch on the same service.
    pub(super) struct RetryUnsentFuture<S, B>
    where
        S: Service<DispatchRequest<B>>,
    {
        #[pin]
        future: Either<S::Future, Oneshot<S, DispatchRequest<B>>>,
        service: S,
        original: Original,
        enabled: bool,
    }
}

/// Request state restored before each unsent retry.
/// Kept outside `pin_project!`, whose fields cannot carry `cfg` attributes.
struct Original {
    uri: Uri,
    /// Wire version before a connection fitted it; the next connection may differ.
    version: Version,
    /// Whether the caller set `Cookie`; otherwise each attempt regenerates it.
    #[cfg(feature = "cookies")]
    had_cookie: bool,
}

/// An HTTP request and the pool key it keeps across unsent retries.
/// Dispatch returns this value only when the original body has not been sent.
pub(super) struct DispatchRequest<B> {
    request: Request<B>,
    pool_key: PoolKey,
    /// Whether checkout always connects and never returns the sender to the pool.
    #[cfg(feature = "ws")]
    dedicated: bool,
    /// Whether the wire version follows the connection, as an explicit `Protocol::Auto` asks.
    negotiable: bool,
    /// Default-group key whose established sender may carry this WebSocket.
    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    extended_connect_key: Option<PoolKey>,
}

/// Performs one connection-pool checkout and protocol send attempt.
///
/// Each call checks out a compatible sender, fits the request to it, applies cookies,
/// dispatches the request, and attaches connection metadata. HTTP/2 and HTTP/3 release their
/// local checkout after response headers. HTTP/1 returns immediately only when
/// its sender is ready again; otherwise a pool-owned task waits before returning
/// it. Errors preserve an unsent request when the protocol dispatcher can prove
/// encoding never began.
pub(super) struct Dispatch<C> {
    pool: pool::Pool<C>,
    #[cfg(feature = "cookies")]
    cookie_store: RequestConfig<Arc<dyn CookieStore>>,
    runtime: DynRuntime,
}

/// Failure from one pool checkout and send attempt.
pub(super) enum DispatchError<B> {
    /// A shared HTTP/2 or HTTP/3 checkout batch was canceled before connecting.
    CheckoutCanceled {
        error: Error,
        request: Box<DispatchRequest<B>>,
    },
    /// The connection failed before encoding any request bytes on a reused sender.
    Unsent {
        error: Error,
        request: Box<DispatchRequest<B>>,
        connection_reused: bool,
    },
    /// A non-retryable checkout or transport failure.
    Terminal(Error),
}

/// Original RFC 6455 header fields of a WebSocket handshake riding extended CONNECT.
/// They are restored in order if the request returns unsent, so a retry can use HTTP/1.1.
#[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
struct Http1Upgrade {
    headers: HeaderMap,
}

/// Sender checked out for one attempt.
/// A struct rather than a tuple, since the upgrade field exists only with WebSocket + H2/H3.
struct CheckedOut {
    pooled: pool::pooled::Pooled,
    /// WebSocket upgrade rewritten for an extended CONNECT sender, restored if unsent.
    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    upgrade: Option<Http1Upgrade>,
}

/// Creates the configuration and unsent-retry layer for a dispatch service.
///
/// Configuration runs once and shares the client's values across service clones.
/// Terminal dispatch errors are mapped only after retry classification, preserving
/// ownership of any request returned before encoding.
#[must_use]
pub(super) fn layer<S>(
    protocol: Protocol,
    config: ConnectConfig,
    retry_unsent: bool,
) -> impl Layer<S, Service = Stack<S>> + Clone {
    layer_fn(move |inner| Stack {
        inner,
        protocol,
        config: config.clone(),
        retry_unsent,
    })
}

// ===== impl Stack =====

impl<S> Stack<S> {
    /// Checks the request, then freezes connection settings before checkout and unsent
    /// retries. Every redirect hop and public retry passes here again.
    fn prepare<B>(&self, mut request: Request<B>) -> Result<DispatchRequest<B>, Error> {
        match request.version() {
            Version::HTTP_10 if request.method() == Method::CONNECT => {
                warn!("CONNECT is not allowed for HTTP/1.0");
                return Err(Error::from_kind(ErrorKind::UserUnsupportedRequestMethod));
            }
            Version::HTTP_10 | Version::HTTP_11 => {}
            #[cfg(feature = "http2")]
            Version::HTTP_2 => {}
            #[cfg(feature = "http3")]
            Version::HTTP_3 => {}
            _unsupported => {
                warn!("Request has unsupported version: {:?}", _unsupported);
                return Err(Error::from_kind(ErrorKind::UserUnsupportedVersion));
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
        let request_config = extensions.remove::<ConnectConfig>().unwrap_or_default();
        #[cfg(feature = "ws")]
        let dedicated = extensions.remove::<DedicatedConnection>();

        // Normalize wire versions to protocol choices; HTTP/1.0 and HTTP/1.1 share a pool.
        let version = RequestConfig::<RequestVersion>::remove(extensions);
        let uri = request.uri();

        // curl's ordinary H2 mode allows HTTPS negotiation; prior knowledge
        // remains explicit: https://curl.se/libcurl/c/CURLOPT_HTTP_VERSION.html
        let protocol = match version {
            Some(Version::HTTP_10 | Version::HTTP_11) => Some(Protocol::Http1),
            #[cfg(feature = "http2")]
            Some(Version::HTTP_2) if uri.is_https() && self.protocol != Protocol::Http2 => {
                Some(Protocol::Auto)
            }
            #[cfg(feature = "http2")]
            Some(Version::HTTP_2) => Some(Protocol::Http2),
            #[cfg(feature = "http3")]
            Some(Version::HTTP_3) => Some(Protocol::Http3),
            Some(_) => {
                return Err(Error::from_kind(ErrorKind::UserUnsupportedVersion));
            }
            None => None,
        };

        let origin = uri.origin().map_err(|source| {
            debug!("Client requires absolute-form URIs, received: {uri:?}");
            Error::new(ErrorKind::UserAbsoluteUriRequired, source)
        })?;
        let negotiable = protocol == Some(Protocol::Auto);
        let protocol = protocol.unwrap_or(self.protocol);

        // HTTP/3 has no cleartext form; an https-to-http redirect also ends here:
        // https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1
        #[cfg(feature = "http3")]
        if protocol == Protocol::Http3 && !uri.is_https() {
            warn!("HTTP/3 requires an https URI");
            return Err(Error::from_kind(ErrorKind::UserUnsupportedVersion)
                .with_context("HTTP/3 requires an https URI"));
        }

        // Probe the default group only where it may be HTTP/2, or HTTP/3 over https. Without
        // Alt-Svc discovery, an automatic client's explicit HTTP/3 group is not probed.
        #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
        let extended_connect_key = (dedicated.is_some_and(|d| d.extended_connect)
            && match self.protocol {
                #[cfg(feature = "http2")]
                Protocol::Auto | Protocol::Http2 => true,
                #[cfg(feature = "http3")]
                Protocol::Http3 => uri.is_https(),
                _ => false,
            })
        .then(|| self.pool_key(origin.clone(), self.protocol, &request_config));

        Ok(DispatchRequest {
            request,
            pool_key: self.pool_key(origin, protocol, &request_config),
            #[cfg(feature = "ws")]
            dedicated: dedicated.is_some(),
            negotiable,
            #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
            extended_connect_key,
        })
    }

    #[must_use]
    fn pool_key(&self, origin: Uri, protocol: Protocol, request: &ConnectConfig) -> PoolKey {
        PoolKey::new(
            origin,
            protocol,
            request.for_protocol(protocol, &self.config),
        )
    }
}

impl<S, B> Service<Request<B>> for Stack<S>
where
    S: Service<DispatchRequest<B>, Error = DispatchError<B>> + Clone,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Either<RetryUnsentFuture<S, B>, Ready<Result<Self::Response, Self::Error>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(DispatchError::into_error)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let request = match self.prepare(request) {
            Ok(request) => request,
            Err(error) => return Either::Right(future::err(error.into())),
        };

        let original = Original {
            uri: request.request.uri().clone(),
            version: request.request.version(),
            #[cfg(feature = "cookies")]
            had_cookie: request.request.headers().contains_key(COOKIE),
        };
        let replacement = self.inner.clone();
        let mut service = mem::replace(&mut self.inner, replacement);
        let future = service.call(request);

        Either::Left(RetryUnsentFuture {
            future: Either::Left(future),
            service,
            original,
            enabled: self.retry_unsent,
        })
    }
}

// ===== impl RetryUnsentFuture =====

impl<S, B> Future for RetryUnsentFuture<S, B>
where
    S: Service<DispatchRequest<B>, Error = DispatchError<B>> + Clone,
{
    type Output = Result<S::Response, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        const MAX_ATTEMPTS_PER_POLL: usize = 2;

        let mut this = self.project();

        // Retry recovery follows hyper-util's legacy client.
        // Poll budgeting follows Hyper's HTTP/1 dispatcher.
        for _ in 0..MAX_ATTEMPTS_PER_POLL {
            let mut request = match ready!(this.future.as_mut().poll(cx)) {
                Ok(response) => return Poll::Ready(Ok(response)),
                Err(DispatchError::CheckoutCanceled {
                    error: _error,
                    request,
                }) if *this.enabled => {
                    trace!("singleton connection batch canceled, trying again (reason={_error:?})");
                    *request
                }
                Err(DispatchError::Unsent {
                    error: _error,
                    request,
                    connection_reused: true,
                }) if *this.enabled => {
                    trace!("unstarted request canceled, trying again (reason={_error:?})");
                    *request
                }
                Err(error) => return Poll::Ready(Err(error.into_error())),
            };

            *request.request.uri_mut() = this.original.uri.clone();
            *request.request.version_mut() = this.original.version;
            // Regenerate automatic cookies for the next protocol; retain user headers.
            #[cfg(feature = "cookies")]
            if !this.original.had_cookie {
                request.request.headers_mut().remove(COOKIE);
            }
            this.future
                .set(Either::Right(Oneshot::new(this.service.clone(), request)));
        }

        // The next Oneshot has not registered a waker; resume it after yielding.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ===== impl Dispatch =====

impl<C> Dispatch<C>
where
    C: ConnectService,
{
    /// Creates the terminal request service and its shared connection pool.
    /// Handshakes start from the client's connection settings, and HTTP/1 generates
    /// any missing `Host` header.
    #[must_use]
    pub(super) fn new(
        pool_config: pool::Config,
        connector: C,
        config: &ConnectConfig,
        #[cfg(feature = "cookies")] cookie_store: Option<Arc<dyn CookieStore>>,
        runtime: DynRuntime,
    ) -> Self {
        Self {
            pool: pool::Pool::new(pool_config, connector, runtime.clone(), config, true),
            #[cfg(feature = "cookies")]
            cookie_store: RequestConfig::new(cookie_store),
            runtime,
        }
    }

    /// Checks out a sender for the request, first probing for an extended CONNECT sender.
    /// A canceled singleton batch returns the request for an unsent retry.
    async fn checkout(
        &self,
        request: DispatchRequest<Body>,
    ) -> Result<(DispatchRequest<Body>, CheckedOut), DispatchError<Body>> {
        // RFC 8441 §3 and RFC 9220 §3: extended CONNECT only after the peer enabled it. A
        // miss keeps the dedicated HTTP/1.1 upgrade, so no HTTP/2 or HTTP/3 connection opens.
        let reused: Option<pool::pooled::Pooled> = cfg_select! {
            all(feature = "ws", any(feature = "http2", feature = "http3")) => request
                .extended_connect_key
                .as_ref()
                .and_then(|key| self.pool.checkout_extended_connect(key)),
            _ => None,
        };

        #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
        let mut request = request;
        #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
        let upgrade = reused.as_ref().map(|pooled| {
            Http1Upgrade::into_extended_connect(&mut request.request, pooled.version())
        });

        let dedicated = cfg_select! {
            feature = "ws" => request.dedicated,
            _ => false,
        };
        let pooled = match reused {
            Some(pooled) => pooled,
            None => match self.pool.checkout(&request.pool_key, dedicated).await {
                Ok(pooled) => pooled,
                Err(error) if pool::is_canceled(&*error) => {
                    return Err(DispatchError::CheckoutCanceled {
                        error: Error::new(ErrorKind::Connect, error),
                        request: Box::new(request),
                    });
                }
                Err(error) => {
                    return Err(DispatchError::Terminal(Error::new(
                        ErrorKind::Connect,
                        error,
                    )));
                }
            },
        };

        let checked_out = CheckedOut {
            pooled,
            #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
            upgrade,
        };
        Ok((request, checked_out))
    }

    /// Fits the request to the checked-out sender, dispatches it, then attaches cookies and
    /// connection metadata. A request returned before encoding comes back unsent.
    async fn send(
        &self,
        mut request: DispatchRequest<Body>,
        checked_out: CheckedOut,
    ) -> Result<Response<Incoming>, DispatchError<Body>> {
        // Cookies keep the request URI; only the wire target of a CONNECT changes.
        #[cfg(feature = "cookies")]
        let uri = request.request.uri().clone();
        let extended = reconcile(
            &mut request.request,
            &checked_out.pooled,
            request.negotiable,
        )
        .map_err(DispatchError::Terminal)?;
        #[cfg(not(any(feature = "http2", feature = "http3")))]
        let _ = extended;

        let CheckedOut {
            mut pooled,
            #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
            upgrade,
        } = checked_out;

        #[cfg(feature = "cookies")]
        let cookie_store = self
            .cookie_store
            .fetch(request.request.extensions())
            .cloned();

        #[cfg(feature = "cookies")]
        if let Some(ref cookie_store) = cookie_store {
            apply_request_cookies(
                &mut request.request,
                cookie_store.as_ref(),
                &uri,
                pooled.version(),
            );
        }

        let mut response = match pooled.call(request.request).await {
            Ok(response) => response,
            Err(mut error) => {
                let connection_reused = pooled.is_reused();
                let connect_info = pooled.connected().clone();
                let unnegotiated_h2 = pooled.version() == Version::HTTP_2
                    && request.pool_key.origin().is_https()
                    && !connect_info.is_negotiated_h2();

                // A returned request was not sent; only protocol rejections are final,
                // since they repeat on the same connection.
                if let Some(unsent) = (!error.is_user()).then(|| error.take_message()).flatten() {
                    request.request = unsent;
                    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
                    if let Some(upgrade) = upgrade {
                        upgrade.restore(&mut request.request);
                    }

                    return Err(DispatchError::Unsent {
                        error: with_h2_alpn_context(
                            error.into_client_error(ErrorKind::Canceled),
                            unnegotiated_h2,
                        )
                        .with_connect_info(connect_info),
                        request: Box::new(request),
                        connection_reused,
                    });
                }

                #[cfg(any(feature = "http2", feature = "http3"))]
                if extended && pooled.extended_connect() == Some(false) {
                    return Err(DispatchError::Terminal(extended_connect_disabled(&pooled)));
                }

                return Err(DispatchError::Terminal(
                    with_h2_alpn_context(
                        error.into_client_error(ErrorKind::SendRequest),
                        unnegotiated_h2,
                    )
                    .with_connect_info(connect_info),
                ));
            }
        };

        #[cfg(feature = "cookies")]
        if let Some(cookie_store) = cookie_store {
            store_response_cookies(&response, cookie_store.as_ref(), &uri);
        }

        pooled.connected().set_extras(response.extensions_mut());
        response.extensions_mut().insert(pooled.connected().clone());

        // Multiplexed senders are shared, so only HTTP/1 waits to become ready again.
        if pooled.version() != Version::HTTP_11 || !pooled.is_pool_enabled() || pooled.is_ready() {
            drop(pooled);
        } else {
            self.runtime.execute(Box::pin(async move {
                let _ = pooled.ready().await;
            }));
        }

        Ok(response)
    }
}

impl<C> Clone for Dispatch<C> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            runtime: self.runtime.clone(),
            #[cfg(feature = "cookies")]
            cookie_store: self.cookie_store.clone(),
        }
    }
}

impl<C> Service<DispatchRequest<Body>> for Dispatch<C>
where
    C: ConnectService,
{
    type Response = Response<Incoming>;
    type Error = DispatchError<Body>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: DispatchRequest<Body>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let (request, checked_out) = this.checkout(request).await?;
            this.send(request, checked_out).await
        })
    }
}

// ===== impl DispatchError =====

impl<B> DispatchError<B> {
    /// Extracts the underlying boxed error, discarding any unsent request.
    #[must_use]
    fn into_error(self) -> BoxError {
        match self {
            Self::CheckoutCanceled { error, .. }
            | Self::Unsent { error, .. }
            | Self::Terminal(error) => error.into(),
        }
    }
}

// ===== impl Http1Upgrade =====

#[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
impl Http1Upgrade {
    /// Rewrites the GET upgrade as extended CONNECT for a sender of `version`, keeping the
    /// other WebSocket fields ([RFC 8441 §5](https://www.rfc-editor.org/rfc/rfc8441#section-5),
    /// [RFC 9220 §3](https://www.rfc-editor.org/rfc/rfc9220#section-3)).
    #[must_use]
    fn into_extended_connect<B>(request: &mut Request<B>, version: Version) -> Self {
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
        Self { headers }
    }

    /// Restores the RFC 6455 GET after an unsent extended CONNECT, removing either marker.
    fn restore<B>(self, request: &mut Request<B>) {
        *request.method_mut() = Method::GET;
        *request.version_mut() = Version::HTTP_11;
        #[cfg(feature = "http2")]
        request.extensions_mut().remove::<http2::ext::Protocol>();
        #[cfg(feature = "http3")]
        request.extensions_mut().remove::<netty::http3::Protocol>();
        *request.headers_mut() = self.headers;
    }
}

/// Explains failures of HTTP/2 used over HTTPS without negotiating `h2` in ALPN.
#[must_use]
fn with_h2_alpn_context(error: Error, unnegotiated_h2: bool) -> Error {
    if unnegotiated_h2 {
        error.with_context(
            "HTTP/2 was used for HTTPS without reported h2 ALPN; \
             the peer may not support HTTP/2",
        )
    } else {
        error
    }
}

/// Fits the request to the checked-out connection and returns whether it uses extended CONNECT.
///
/// Multiplexed connections set their own wire version. HTTP/1 sets HTTP/1.1 only for a
/// `negotiable` request and otherwise requires HTTP/1.0 or HTTP/1.1. Extended CONNECT must
/// match the connection, and a plain CONNECT target gains its default port.
fn reconcile(
    request: &mut Request<Body>,
    pooled: &pool::pooled::Pooled,
    negotiable: bool,
) -> Result<bool, Error> {
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
        return Err(Error::from_kind(ErrorKind::UserUnsupportedVersion)
            .with_connect_info(pooled.connected().clone()));
    }

    if request.method() == Method::CONNECT && !extended {
        connect_target_port(request, multiplexed)?;
    }
    Ok(extended)
}

/// Returns whether the request uses extended CONNECT on this connection.
/// HTTP/2 takes `:protocol` from `http2::ext::Protocol` ([RFC 8441 §4]) and HTTP/3 from
/// `netty::http3::Protocol` ([RFC 9220 §3]); a marker the connection would ignore fails
/// instead of sending a plain CONNECT tunnel.
///
/// [RFC 8441 §4]: https://www.rfc-editor.org/rfc/rfc8441#section-4
/// [RFC 9220 §3]: https://www.rfc-editor.org/rfc/rfc9220#section-3
#[cfg(any(feature = "http2", feature = "http3"))]
fn matched_extended_connect<B>(
    request: &Request<B>,
    pooled: &pool::pooled::Pooled,
) -> Result<bool, Error> {
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
        return Err(Error::from_kind(ErrorKind::UserUnsupportedVersion)
            .with_context("extended CONNECT protocol does not match the connection's HTTP version")
            .with_connect_info(pooled.connected().clone()));
    }
    Ok(matched)
}

/// Rejects extended CONNECT unless the peer enabled it (RFC 8441 §3, RFC 9220 §3).
#[must_use]
#[cfg(any(feature = "http2", feature = "http3"))]
fn extended_connect_disabled(pooled: &pool::pooled::Pooled) -> Error {
    warn!("peer did not enable extended CONNECT");
    Error::from_kind(ErrorKind::UserUnsupportedVersion)
        .with_context("peer did not enable extended CONNECT")
        .with_connect_info(pooled.connected().clone())
}

/// Adds the scheme's default port to a plain CONNECT target that elides it, since
/// CONNECT has no default port and HTTP/1, HTTP/2 and HTTP/3 send the authority as is
/// ([RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6)).
///
/// On HTTP/2 and HTTP/3, a Host header equal to the old authority is updated with it,
/// since Host must not differ from `:authority`
/// ([RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113#section-8.3.1),
/// [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1)).
fn connect_target_port<B>(request: &mut Request<B>, multiplexed: bool) -> Result<(), Error> {
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
        .map_err(|error| Error::new(ErrorKind::SendRequest, error))?;

    if multiplexed
        && request
            .headers()
            .get(HOST)
            .is_some_and(|host| host == authority.as_str())
    {
        let host = HeaderValue::from_str(target.as_str())
            .map_err(|error| Error::new(ErrorKind::SendRequest, error))?;
        request.headers_mut().insert(HOST, host);
    }

    let mut parts = mem::take(request.uri_mut()).into_parts();
    parts.authority = Some(target);
    *request.uri_mut() =
        Uri::from_parts(parts).map_err(|error| Error::new(ErrorKind::SendRequest, error))?;
    Ok(())
}

#[cfg(feature = "cookies")]
fn apply_request_cookies<B>(
    request: &mut Request<B>,
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
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tower::ServiceExt;

    use super::*;

    fn stack<S>(service: S, protocol: Protocol, retry_unsent: bool) -> Stack<S> {
        layer(protocol, ConnectConfig::default(), retry_unsent).layer(service)
    }

    #[test]
    fn entry_checks_reject_requests_and_strip_userinfo_before_keying() {
        let stack = stack((), Protocol::Auto, false);
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
            let request = Request::builder()
                .method(method)
                .version(version)
                .uri(uri)
                .body(())
                .unwrap();
            let Err(error) = stack.prepare(request) else {
                panic!("{kind} must reject the request");
            };
            assert_eq!(error.to_string(), format!("client error ({kind})"));
        }

        let prepare = |uri| stack.prepare(Request::get(uri).body(()).unwrap()).unwrap();
        let plain = prepare("http://localhost/");
        let userinfo = prepare("http://user:pw@localhost/");
        assert_eq!(userinfo.request.uri(), "http://localhost/");
        assert_eq!(userinfo.pool_key, plain.pool_key);
    }

    #[tokio::test]
    async fn unsent_retries_restore_request_state_and_respect_reused_flag() {
        use http_body_util::BodyExt;

        for (enabled, reused, expected_calls) in
            [(true, true, 2), (false, true, 1), (true, false, 1)]
        {
            let calls = Arc::new(AtomicUsize::new(0));
            let attempts = calls.clone();
            let mut key = None;
            let service = tower::service_fn(move |mut request: DispatchRequest<crate::Body>| {
                let result = if attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                    key = Some(request.pool_key.clone());
                    *request.request.uri_mut() = Uri::from_static("/upload?part=1");
                    *request.request.version_mut() = Version::HTTP_2;
                    #[cfg(feature = "cookies")]
                    request
                        .request
                        .headers_mut()
                        .append(COOKIE, HeaderValue::from_static("h2=1"));
                    Err(DispatchError::Unsent {
                        error: Error::new(ErrorKind::Canceled, std::io::Error::other("unsent")),
                        request: Box::new(request),
                        connection_reused: reused,
                    })
                } else {
                    assert_eq!(request.request.uri(), "http://localhost/upload?part=1");
                    assert_eq!(request.request.version(), Version::HTTP_10);
                    #[cfg(feature = "cookies")]
                    assert!(!request.request.headers().contains_key(COOKIE));
                    assert_eq!(key.as_ref(), Some(&request.pool_key));
                    Ok(request.request.into_body())
                };
                future::ready(result)
            });

            let result = stack(service, Protocol::Auto, enabled)
                .oneshot(
                    Request::builder()
                        .version(Version::HTTP_10)
                        .uri("http://localhost/upload?part=1")
                        .body(crate::Body::from("payload"))
                        .unwrap(),
                )
                .await;

            assert_eq!(calls.load(Ordering::Relaxed), expected_calls);
            if expected_calls == 2 {
                let body = result.unwrap().collect().await.unwrap().to_bytes();
                assert_eq!(body, "payload");
            } else {
                let error = result.unwrap_err();
                assert!(error.is::<Error>());
                assert_eq!(error.source().unwrap().to_string(), "unsent");
            }
        }

        #[cfg(feature = "cookies")]
        {
            let calls = Arc::new(AtomicUsize::new(0));
            let attempts = calls.clone();
            let service = tower::service_fn(move |request: DispatchRequest<crate::Body>| {
                let values: Vec<_> = request.request.headers().get_all(COOKIE).iter().collect();
                assert_eq!(values, ["user=1", "other=2"]);
                future::ready(if attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                    Err(DispatchError::Unsent {
                        error: Error::from_kind(ErrorKind::Canceled),
                        request: Box::new(request),
                        connection_reused: true,
                    })
                } else {
                    Ok(())
                })
            });
            stack(service, Protocol::Auto, true)
                .oneshot(
                    Request::builder()
                        .uri("https://localhost/")
                        .header(COOKIE, "user=1")
                        .header(COOKIE, "other=2")
                        .body(crate::Body::default())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(calls.load(Ordering::Relaxed), 2);
        }
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

        let connector = tower::service_fn(|_: Request<ConnectConfig>| {
            let (client, server) = tokio::io::duplex(16384);
            let service = hyper::service::service_fn(|request: Request<hyper::body::Incoming>| {
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
        });
        let store = Arc::new(Recorder::default());
        let dispatch = Dispatch::new(
            pool::Config::default(),
            connector,
            &ConnectConfig::default(),
            Some(store.clone()),
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
        );
        let response = stack(dispatch, Protocol::Auto, true)
            .oneshot(
                Request::connect("http://localhost/")
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
            let mut request = Request::get("https://localhost/chat")
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
