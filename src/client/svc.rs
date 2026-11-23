//! Low-level Tower service for request preparation, pool checkout, and unsent retries.
//!
//! [`Client`] prepares the connection config and pool key once, then checks out a sender
//! and applies the negotiated protocol and cookies. Unsent retries reuse the prepared
//! request without cloning its body.

use std::{
    future::{Future, poll_fn},
    mem,
    pin::pin,
    task::{Context, Poll, ready},
};

use futures_util::future::{self, BoxFuture, Either, Ready};
#[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
use http::{
    HeaderMap,
    header::{CONNECTION, SEC_WEBSOCKET_KEY, UPGRADE},
};
use http::{HeaderValue, Method, Response, Uri, Version, header::HOST, uri::Authority};
use netty::body::Incoming;
use tower::{BoxError, Service, ServiceExt};
#[cfg(feature = "cookies")]
use {
    crate::cookie::{CookieStore, Cookies},
    http::header::COOKIE,
    std::sync::Arc,
};

use super::{
    error::{self, ErrorKind},
    pool,
    proto::Handshakes,
    request::RequestVersion,
};
use crate::{
    Body,
    config::{ConnectConfig, RequestConfig},
    conn::{self, BoxedConnectLayer},
    dns::DynResolver,
    ext::UriExt,
    protocol::Protocol,
    reuse,
    rt::{DynRuntime, Executor},
};

/// Client-wide settings assembled by [`ClientBuilder`](crate::ClientBuilder) to construct
/// the low-level [`Client`] service.
///
/// Bundles transport connector settings, pool policy, default connection options, protocol
/// mode, and optional cookie storage.
pub(super) struct Config {
    /// Transport connector settings (TCP, TLS, QUIC, proxy, and timeouts).
    pub(super) connect: conn::Config,
    /// Connection pool retention, capacity, and reuse-strategy policy.
    pub(super) pool_config: pool::Config,
    /// Client-wide default connection options merged under per-request overrides.
    pub(super) connect_config: ConnectConfig,
    /// Middleware layers wrapped around the base transport connector.
    pub(super) connector_layers: Vec<BoxedConnectLayer>,
    /// Default HTTP protocol mode used when a request does not specify a version.
    pub(super) protocol: Protocol,
    /// Client-wide default cookie store, overridable per request.
    #[cfg(feature = "cookies")]
    pub(super) cookie_store: Option<Arc<dyn CookieStore>>,
}

/// Internal HTTP service beneath [`crate::Client`].
///
/// Prepares requests once, checks out pooled senders, applies cookies and protocol
/// reconciliation, and retries unsent failures without cloning bodies.
#[derive(Clone)]
pub(super) struct Client {
    /// Shared connection pool keyed by compatibility [`reuse::Key`].
    pool: pool::Pool<reuse::Key, conn::ConnectService, DynRuntime>,
    /// Default HTTP protocol mode applied when a request omits a version override.
    protocol: Protocol,
    /// Client-wide connection options attached as the base for every request.
    connect_config: ConnectConfig,
    /// Client-wide default cookie store, overridable via request extensions.
    #[cfg(feature = "cookies")]
    cookie_store: Option<Arc<dyn CookieStore>>,
}

/// Requests a dedicated HTTP/1 connection that bypasses the pool.
///
/// When `extended_connect` is set, dispatch first probes for an established HTTP/2 or HTTP/3
/// connection in the default group whose peer enabled extended CONNECT (RFC 8441, RFC 9220).
#[cfg(feature = "ws")]
#[derive(Clone, Copy)]
pub(super) struct DedicatedConnection {
    /// Probes the default group for an established extended CONNECT sender before dialing HTTP/1.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) extended_connect: bool,
}

/// Prepared HTTP request paired with its connection request and optional pool keys.
///
/// Returned inside [`Error`] only when no request bytes were encoded, so
/// [`retry_unsent`] can retry without cloning the body.
struct Request {
    /// HTTP request sent over the checked-out connection and restored on unsent retry.
    inner: http::Request<Body>,
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

/// Failure returned by a pool checkout or send attempt.
///
/// Distinguishes retryable unsent failures (which return the original [`Request`]
/// intact) from terminal checkout or transport errors.
enum Error {
    /// A shared HTTP/2 or HTTP/3 checkout batch was canceled before connecting.
    CheckoutCanceled {
        /// Underlying connect/cancel error.
        error: error::Error,
        /// Unsent request returned intact for retry.
        request: Box<Request>,
    },
    /// The connection failed before encoding any request bytes.
    Unsent {
        /// Underlying send error surfaced if this attempt is not retried.
        error: error::Error,
        /// Unsent request returned intact for retry.
        request: Box<Request>,
        /// Whether the failed sender came from the pool; only reused connections are retried.
        connection_reused: bool,
    },
    /// A non-retryable checkout or transport failure.
    Terminal(error::Error),
}

/// Original RFC 6455 headers of a WebSocket handshake rewritten for extended CONNECT.
///
/// Restored in order if the request returns unsent so a retry can fall back to HTTP/1.1.
#[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
struct Http1Upgrade {
    /// Original HTTP/1.1 upgrade headers preserved in order for unsent fallback.
    headers: HeaderMap,
}

// ===== impl Config =====

impl Default for Config {
    fn default() -> Self {
        Self {
            connect: conn::Config::default(),
            connect_config: ConnectConfig::default(),
            pool_config: pool::Config::default(),
            connector_layers: Vec::new(),
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
            config.connector_layers,
        )?;
        Ok(Self {
            pool: pool::Pool::new(
                connector,
                runtime.clone(),
                config.pool_config,
                Handshakes::new(runtime, &config.connect_config, true),
            ),
            protocol: config.protocol,
            connect_config: config.connect_config,
            #[cfg(feature = "cookies")]
            cookie_store: config.cookie_store,
        })
    }

    /// Checks out a sender, applies protocol and cookie settings, and sends the request once.
    async fn send_once(
        pool: &pool::Pool<reuse::Key, conn::ConnectService, DynRuntime>,
        mut request: Request,
        #[cfg(feature = "cookies")] cookie_store: Option<&Arc<dyn CookieStore>>,
    ) -> Result<Response<Incoming>, Error> {
        // RFC 8441 §3 and RFC 9220 §3: extended CONNECT only after the peer enabled it. A
        // miss keeps the dedicated HTTP/1.1 upgrade, so no HTTP/2 or HTTP/3 connection opens.
        let established: Option<pool::Pooled> = cfg_select! {
            all(feature = "ws", any(feature = "http2", feature = "http3")) => request
                .extended_connect_key
                .as_ref()
                .and_then(|key| pool.checkout_extended_connect(key)),
            _ => None,
        };

        #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
        let upgrade = established.as_ref().map(|pooled| {
            Http1Upgrade::into_extended_connect(&mut request.inner, pooled.version())
        });

        let mut pooled = match established {
            Some(pooled) => pooled,
            None => match pool
                .checkout(request.pool_key.as_ref(), &request.connect)
                .await
            {
                Ok(pooled) => pooled,
                Err(error) if pool::is_canceled(&*error) => {
                    return Err(Error::CheckoutCanceled {
                        error: error::Error::new(ErrorKind::Connect, error),
                        request: Box::new(request),
                    });
                }
                Err(error) => {
                    return Err(Error::Terminal(error::Error::new(
                        ErrorKind::Connect,
                        error,
                    )));
                }
            },
        };

        // Cookies keep the request URI; only the wire target of a CONNECT changes.
        let is_https = request.inner.uri().is_https();
        #[cfg(feature = "cookies")]
        let uri = request.inner.uri().clone();
        let _extended =
            reconcile(&mut request.inner, &pooled, request.negotiable).map_err(Error::Terminal)?;

        #[cfg(feature = "cookies")]
        let cookie_store = RequestConfig::<Arc<dyn CookieStore>>::get(request.inner.extensions())
            .or(cookie_store)
            .cloned();

        #[cfg(feature = "cookies")]
        if let Some(ref cookie_store) = cookie_store {
            apply_request_cookies(
                &mut request.inner,
                cookie_store.as_ref(),
                &uri,
                pooled.version(),
            );
        }

        let mut response = match pooled.call(request.inner).await {
            Ok(response) => response,
            Err(mut error) => {
                let connection_reused = pooled.is_reused();
                let connect_info = pooled.connected().clone();
                let unnegotiated_h2 = pooled.version() == Version::HTTP_2
                    && is_https
                    && !connect_info.is_negotiated_h2();

                // A returned request was not sent; only protocol rejections are final,
                // since they repeat on the same connection.
                if !error.is_user()
                    && let Some(unsent) = error.take_message()
                {
                    request.inner = unsent;
                    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
                    if let Some(upgrade) = upgrade {
                        upgrade.restore(&mut request.inner);
                    }

                    return Err(Error::Unsent {
                        error: with_h2_alpn_context(
                            error.into_client_error(ErrorKind::Canceled),
                            unnegotiated_h2,
                        )
                        .with_connect_info(connect_info),
                        request: Box::new(request),
                        connection_reused,
                    });
                }

                // The peer's SETTINGS may have arrived while the send was pending.
                #[cfg(any(feature = "http2", feature = "http3"))]
                if _extended && pooled.extended_connect() == Some(false) {
                    return Err(Error::Terminal(extended_connect_disabled(&pooled)));
                }

                return Err(Error::Terminal(
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

        // Multiplexed senders are shared; only busy HTTP/1 senders wait for readiness
        // before dropping so they can return to the pool once the response finishes.
        if pooled.version() != Version::HTTP_11 || !pooled.is_pool_enabled() || pooled.is_ready() {
            drop(pooled);
        } else {
            pool.execute(Box::pin(async move {
                let _ = pooled.ready().await;
            }));
        }

        Ok(response)
    }
}

impl Service<http::Request<Body>> for Client {
    type Response = Response<Incoming>;
    type Error = BoxError;
    type Future = Either<
        BoxFuture<'static, Result<Self::Response, Self::Error>>,
        Ready<Result<Self::Response, Self::Error>>,
    >;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let request = match Request::prepare(request, self.protocol, &self.connect_config) {
            Ok(request) => request,
            Err(error) => return Either::Right(future::err(error.into())),
        };

        let pool = self.pool.clone();
        #[cfg(feature = "cookies")]
        let cookie_store = self.cookie_store.clone();

        Either::Left(Box::pin(async move {
            let pool = &pool;
            #[cfg(feature = "cookies")]
            let cookie_store = cookie_store.as_ref();

            retry_unsent(request, |request| {
                Self::send_once(
                    pool,
                    request,
                    #[cfg(feature = "cookies")]
                    cookie_store,
                )
            })
            .await
        }))
    }
}

// ===== impl Request =====

impl Request {
    /// Validates the request and freezes its pool key and connection config before dispatch.
    ///
    /// Redirect hops and user-level retries pass through here again.
    fn prepare(
        mut request: http::Request<Body>,
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
        let overrides = extensions.remove::<ConnectConfig>();
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

        // Attach client defaults to any request-level connection overrides.
        let config = overrides.unwrap_or_default().with_base(connect_config);
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
                Protocol::Http3 => uri.is_https(),
                _ => false,
            })
        .then(|| connect.reuse_key(client_protocol));

        Ok(Self {
            inner: request,
            connect,
            pool_key,
            negotiable,
            #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
            extended_connect_key,
        })
    }
}

/// Retries a canceled checkout or an unsent request from a reused connection.
///
/// Restores the original URI, wire version, and auto-generated `Cookie` headers before
/// each retry, yielding after a bounded number of attempts per poll.
async fn retry_unsent<T, F>(
    request: Request,
    mut attempt: impl FnMut(Request) -> F,
) -> Result<T, BoxError>
where
    F: Future<Output = Result<T, Error>>,
{
    const MAX_ATTEMPTS_PER_POLL: usize = 2;

    let uri = request.inner.uri().clone();
    let version = request.inner.version();
    #[cfg(feature = "cookies")]
    let had_cookie = request.inner.headers().contains_key(COOKIE);
    let mut future = pin!(attempt(request));

    poll_fn(|cx| {
        // Retry recovery follows hyper-util's legacy client.
        // Poll budgeting follows Hyper's HTTP/1 dispatcher.
        for _ in 0..MAX_ATTEMPTS_PER_POLL {
            let mut request = match ready!(future.as_mut().poll(cx)) {
                Ok(response) => return Poll::Ready(Ok(response)),
                Err(Error::CheckoutCanceled {
                    error: _error,
                    request,
                }) => {
                    trace!("singleton connection batch canceled, trying again (reason={_error:?})");
                    *request
                }
                Err(Error::Unsent {
                    error: _error,
                    request,
                    connection_reused: true,
                }) => {
                    trace!("unstarted request canceled, trying again (reason={_error:?})");
                    *request
                }
                Err(
                    Error::Unsent {
                        error,
                        connection_reused: false,
                        ..
                    }
                    | Error::Terminal(error),
                ) => return Poll::Ready(Err(error.into())),
            };

            *request.inner.uri_mut() = uri.clone();
            *request.inner.version_mut() = version;
            // Regenerate automatic cookies for the next protocol; retain user headers.
            #[cfg(feature = "cookies")]
            if !had_cookie {
                request.inner.headers_mut().remove(COOKIE);
            }
            future.set(attempt(request));
        }

        // The next attempt has not registered a waker; resume it after yielding.
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
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
        Self { headers }
    }

    /// Restores the RFC 6455 GET after an unsent extended CONNECT, removing either marker.
    fn restore<B>(self, request: &mut http::Request<B>) {
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

    use tower::ServiceExt;

    use super::*;
    use crate::conn::{Conn, Unnameable};

    fn client(
        mut config: Config,
        connect: impl Fn(Unnameable) -> Ready<Result<Conn, BoxError>> + Clone + Send + Sync + 'static,
    ) -> Client {
        config
            .connector_layers
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
        let prepare = |request| Request::prepare(request, Protocol::Auto, &connect_config);
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
        let plain = prepare_uri("http://localhost/");
        let userinfo = prepare_uri("http://user:pw@localhost/");
        assert!(plain.pool_key.is_some());
        assert_eq!(userinfo.inner.uri(), "http://localhost/");
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
            let request = prepare(request).unwrap();
            assert!(request.pool_key.is_none());
            #[cfg(feature = "http2")]
            assert_eq!(request.extended_connect_key, plain.pool_key);
        }
    }

    #[tokio::test]
    async fn unsent_retries_restore_request_state_and_respect_reused_flag() {
        use http_body_util::BodyExt;

        let connect_config = ConnectConfig::default();
        let prepare = |request| Request::prepare(request, Protocol::Auto, &connect_config).unwrap();

        for reused in [true, false] {
            let mut calls = 0;
            let mut key = None;
            let attempt = |mut request: Request| {
                calls += 1;
                let result = if calls == 1 {
                    assert!(request.pool_key.is_some());
                    key.clone_from(&request.pool_key);
                    *request.inner.uri_mut() = Uri::from_static("/upload?part=1");
                    *request.inner.version_mut() = Version::HTTP_2;
                    #[cfg(feature = "cookies")]
                    request
                        .inner
                        .headers_mut()
                        .append(COOKIE, HeaderValue::from_static("h2=1"));
                    Err(Error::Unsent {
                        error: error::Error::new(
                            ErrorKind::Canceled,
                            std::io::Error::other("unsent"),
                        ),
                        request: Box::new(request),
                        connection_reused: reused,
                    })
                } else {
                    assert_eq!(request.inner.uri(), "http://localhost/upload?part=1");
                    assert_eq!(request.inner.version(), Version::HTTP_10);
                    #[cfg(feature = "cookies")]
                    assert!(!request.inner.headers().contains_key(COOKIE));
                    assert_eq!(key, request.pool_key);
                    if calls == 2 {
                        Err(Error::CheckoutCanceled {
                            error: error::Error::from_kind(ErrorKind::Connect),
                            request: Box::new(request),
                        })
                    } else {
                        Ok(request.inner.into_body())
                    }
                };
                future::ready(result)
            };
            let request = prepare(
                http::Request::builder()
                    .version(Version::HTTP_10)
                    .uri("http://localhost/upload?part=1")
                    .body(Body::from("payload"))
                    .unwrap(),
            );
            let result = {
                let mut retry = pin!(retry_unsent(request, attempt));
                if reused {
                    assert!(futures_util::poll!(retry.as_mut()).is_pending());
                    let Poll::Ready(result) = futures_util::poll!(retry.as_mut()) else {
                        panic!("the third attempt must finish on the next poll");
                    };
                    result
                } else {
                    retry.await
                }
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
            let request = prepare(
                http::Request::builder()
                    .uri("https://localhost/")
                    .header(COOKIE, "user=1")
                    .header(COOKIE, "other=2")
                    .body(Body::default())
                    .unwrap(),
            );
            retry_unsent(request, |request| {
                let values: Vec<_> = request.inner.headers().get_all(COOKIE).iter().collect();
                assert_eq!(values, ["user=1", "other=2"]);
                calls += 1;
                future::ready(if calls == 1 {
                    Err(Error::Unsent {
                        error: error::Error::from_kind(ErrorKind::Canceled),
                        request: Box::new(request),
                        connection_reused: true,
                    })
                } else {
                    Ok(())
                })
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
