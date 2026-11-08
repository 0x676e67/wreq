//! Terminal request service: one pool checkout and protocol send per attempt.
//!
//! [`Dispatch`] checks out a sender, fits the request to it, and sends it. A request the
//! protocol returns before encoding goes back in [`DispatchError`] for an unsent retry.

use std::{
    mem,
    task::{Context, Poll},
};

use futures_util::future::BoxFuture;
#[cfg(any(feature = "http2", feature = "http3"))]
use http::{
    HeaderMap,
    header::{CONNECTION, SEC_WEBSOCKET_KEY, UPGRADE},
};
use http::{HeaderValue, Method, Request, Response, Uri, Version, header::HOST, uri::Authority};
use netty::body::Incoming;
use tower::{BoxError, Service, ServiceExt};
#[cfg(feature = "cookies")]
use {
    crate::{
        config::RequestConfig,
        cookie::{CookieStore, Cookies},
    },
    http::header::COOKIE,
    std::sync::Arc,
};

use super::DispatchRequest;
use crate::{
    Body,
    client::{
        error::{Error, ErrorKind},
        pool::{self, TransportConnector},
    },
    conn::config::ConfigSet,
    ext::UriExt,
    rt::DynRuntime,
};

/// Performs one connection-pool checkout and protocol send attempt.
///
/// Each call checks out a compatible sender, fits the request to it, applies cookies,
/// dispatches the request, and attaches connection metadata. HTTP/2 and HTTP/3 release their
/// local checkout after response headers. HTTP/1 returns immediately only when
/// its sender is ready again; otherwise a pool-owned task waits before returning
/// it. Errors preserve an unsent request when the protocol dispatcher can prove
/// encoding never began.
pub struct Dispatch<C> {
    pool: pool::Pool<C>,
    #[cfg(feature = "cookies")]
    cookie_store: RequestConfig<Arc<dyn CookieStore>>,
    runtime: DynRuntime,
}

/// Failure from one pool checkout and send attempt.
pub enum DispatchError<B> {
    CheckoutCanceled {
        error: Error,
        request: Box<DispatchRequest<B>>,
    },
    Unsent {
        error: Error,
        request: Box<DispatchRequest<B>>,
        connection_reused: bool,
    },
    Terminal(Error),
}

/// Original RFC 6455 header fields of a WebSocket handshake riding extended CONNECT.
/// They are restored in order if the request returns unsent, so a retry can use HTTP/1.1.
#[cfg(any(feature = "http2", feature = "http3"))]
struct Http1Upgrade {
    headers: HeaderMap,
}

/// Sender checked out for one attempt.
/// A struct rather than a tuple, since the upgrade field exists only with HTTP/2 or HTTP/3.
struct CheckedOut {
    pooled: pool::Pooled,
    /// WebSocket upgrade rewritten for an extended CONNECT sender, restored if unsent.
    #[cfg(any(feature = "http2", feature = "http3"))]
    upgrade: Option<Http1Upgrade>,
}

// ===== impl Dispatch =====

impl<C> Dispatch<C>
where
    C: TransportConnector,
{
    /// Creates the terminal request service and its shared connection pool.
    /// Handshakes start from the client's `config_set`; with `set_host`, HTTP/1
    /// generates a missing `Host` field.
    pub(crate) fn new(
        pool_config: pool::Config,
        connector: C,
        config_set: &ConfigSet,
        set_host: bool,
        #[cfg(feature = "cookies")] cookie_store: Option<Arc<dyn CookieStore>>,
        runtime: DynRuntime,
    ) -> Self {
        Self {
            pool: pool::Pool::new(
                pool_config,
                connector,
                runtime.clone(),
                config_set,
                set_host,
            ),
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
        let reused: Option<pool::Pooled> = cfg_select! {
            any(feature = "http2", feature = "http3") => request
                .extended_connect_key
                .as_ref()
                .and_then(|key| self.pool.checkout_extended_connect(key)),
            _ => None,
        };
        #[cfg(any(feature = "http2", feature = "http3"))]
        let mut request = request;
        #[cfg(any(feature = "http2", feature = "http3"))]
        let upgrade = reused.as_ref().map(|pooled| {
            Http1Upgrade::into_extended_connect(&mut request.request, pooled.version())
        });

        let pooled = match reused {
            Some(pooled) => pooled,
            None => match self
                .pool
                .checkout(request.req.clone(), request.dedicated)
                .await
            {
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
            #[cfg(any(feature = "http2", feature = "http3"))]
            upgrade,
        };
        Ok((request, checked_out))
    }

    /// Sends the fitted request, then attaches cookies and connection metadata to the response.
    /// A request returned before encoding comes back unsent, with its upgrade restored.
    async fn send(
        &self,
        mut request: DispatchRequest<Body>,
        checked_out: CheckedOut,
        #[cfg_attr(
            not(any(feature = "http2", feature = "http3")),
            expect(unused_variables, reason = "HTTP/1 has no extended CONNECT")
        )]
        extended: bool,
        #[cfg(feature = "cookies")] uri: Uri,
    ) -> Result<Response<Incoming>, DispatchError<Body>> {
        let CheckedOut {
            mut pooled,
            #[cfg(any(feature = "http2", feature = "http3"))]
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
                    && request.req.uri().is_https()
                    && !connect_info.is_negotiated_h2();
                // A returned request was not sent; only protocol rejections are final,
                // since they repeat on the same connection.
                if let Some(unsent) = (!error.is_user()).then(|| error.take_message()).flatten() {
                    request.request = unsent;
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    if let Some(upgrade) = upgrade {
                        upgrade.restore(&mut request.request);
                    }
                    let error = error.into_client_error(ErrorKind::Canceled);
                    return Err(DispatchError::Unsent {
                        error: with_h2_alpn_context(error, unnegotiated_h2)
                            .with_connect_info(connect_info),
                        request: Box::new(request),
                        connection_reused,
                    });
                }
                #[cfg(any(feature = "http2", feature = "http3"))]
                if extended && pooled.extended_connect() == Some(false) {
                    return Err(DispatchError::Terminal(extended_connect_disabled(&pooled)));
                }
                let error = error.into_client_error(ErrorKind::SendRequest);
                return Err(DispatchError::Terminal(
                    with_h2_alpn_context(error, unnegotiated_h2).with_connect_info(connect_info),
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
    C: TransportConnector,
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
            let (mut request, checked_out) = this.checkout(request).await?;
            // Cookies keep the request URI; only the wire target of a CONNECT changes.
            #[cfg(feature = "cookies")]
            let uri = request.request.uri().clone();
            let extended = reconcile(
                &mut request.request,
                &checked_out.pooled,
                request.negotiable,
            )
            .map_err(DispatchError::Terminal)?;
            this.send(
                request,
                checked_out,
                extended,
                #[cfg(feature = "cookies")]
                uri,
            )
            .await
        })
    }
}

// ===== impl DispatchError =====

impl<B> DispatchError<B> {
    pub(super) fn into_error(self) -> BoxError {
        match self {
            Self::CheckoutCanceled { error, .. }
            | Self::Unsent { error, .. }
            | Self::Terminal(error) => error.into(),
        }
    }
}

// ===== impl Http1Upgrade =====

#[cfg(any(feature = "http2", feature = "http3"))]
impl Http1Upgrade {
    /// Rewrites the GET upgrade as extended CONNECT for a sender of `version`, keeping the
    /// other WebSocket fields ([RFC 8441 §5](https://www.rfc-editor.org/rfc/rfc8441#section-5),
    /// [RFC 9220 §3](https://www.rfc-editor.org/rfc/rfc9220#section-3)).
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
    pooled: &pool::Pooled,
    negotiable: bool,
) -> Result<bool, Error> {
    #[cfg(any(feature = "http2", feature = "http3"))]
    let extended = matched_extended_connect(request, pooled)?;
    #[cfg(any(feature = "http2", feature = "http3"))]
    if extended && pooled.extended_connect() == Some(false) {
        return Err(extended_connect_disabled(pooled));
    }
    #[cfg(not(any(feature = "http2", feature = "http3")))]
    let extended = false;

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
fn matched_extended_connect<B>(request: &Request<B>, pooled: &pool::Pooled) -> Result<bool, Error> {
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
#[cfg(any(feature = "http2", feature = "http3"))]
fn extended_connect_disabled(pooled: &pool::Pooled) -> Error {
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

    use futures_util::future;

    #[cfg(feature = "cookies")]
    use super::super::tests::http1_dispatch;
    #[cfg(any(feature = "http2", feature = "http3"))]
    use super::super::{DedicatedConnection, RequestVersion};
    use super::{super::tests::stack, *};
    #[cfg(any(feature = "http2", feature = "http3"))]
    use crate::config::RequestConfig;
    use crate::{
        Protocol,
        conn::{Conn, request::ConnectRequest},
    };

    #[tokio::test]
    async fn protocol_options_partition_connections_and_preserve_reuse() {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Full};

        for protocol in [
            Protocol::Http1,
            #[cfg(feature = "http2")]
            Protocol::Http2,
        ] {
            let h2 = cfg_select! {
                feature = "http2" => protocol == Protocol::Http2,
                _ => false,
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let accepted = calls.clone();
            let connector = tower::service_fn(move |conn_req: ConnectRequest| {
                let id = accepted.fetch_add(1, Ordering::Relaxed);
                assert_eq!(conn_req.uri(), "http://localhost/");
                assert!(
                    conn_req
                        .config_set()
                        .get::<crate::http1::Http1Options>()
                        .is_some()
                );
                #[cfg(feature = "http2")]
                assert!(
                    conn_req
                        .config_set()
                        .get::<crate::http2::Http2Options>()
                        .is_some()
                );
                let (client, server) = tokio::io::duplex(16384);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |request: http::Request<hyper::body::Incoming>| async move {
                            let mut response =
                                Response::new(Full::new(Bytes::from(id.to_string())));
                            if request.uri().path() == "/limits" {
                                for i in 0..40 {
                                    response.headers_mut().insert(
                                        http::HeaderName::from_bytes(format!("x-{i}").as_bytes())
                                            .unwrap(),
                                        http::HeaderValue::from_static("1"),
                                    );
                                }
                            }
                            Ok::<_, std::convert::Infallible>(response)
                        },
                    );
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(server), service)
                    .await;
                });
                future::ready(Ok::<_, BoxError>(Conn::test(client)))
            });
            let mut stack = stack(
                Dispatch::new(
                    pool::Config::default(),
                    connector,
                    &ConfigSet::default(),
                    true,
                    #[cfg(feature = "cookies")]
                    None,
                    DynRuntime::new(crate::rt::tokio::TokioRuntime),
                ),
                protocol,
                true,
            );
            for (attempt, (strict, id)) in [
                (false, "0"),
                (true, "1"),
                (true, "1"),
                (false, "0"),
                (true, "1"),
            ]
            .into_iter()
            .enumerate()
            {
                let limits = attempt == 4 && protocol == Protocol::Http1;
                let mut request = Request::builder()
                    .version(if h2 {
                        Version::HTTP_2
                    } else {
                        Version::HTTP_11
                    })
                    .uri(if limits {
                        "http://localhost/limits"
                    } else {
                        "http://localhost/"
                    })
                    .body(crate::Body::default())
                    .unwrap();
                let mut config_set = ConfigSet::default();
                config_set.insert(
                    crate::http1::Http1Options::builder()
                        .max_headers(if strict && protocol == Protocol::Http1 {
                            32
                        } else {
                            64
                        })
                        .build(),
                );
                #[cfg(feature = "http2")]
                config_set.insert(
                    crate::http2::Http2Options::builder()
                        .header_table_size(if strict && h2 { 8192 } else { 4096 })
                        .build(),
                );
                request.extensions_mut().insert(config_set);
                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    stack.ready().await.unwrap().call(request),
                )
                .await
                .unwrap();
                if limits {
                    assert!(
                        response.is_err(),
                        "the selected HTTP/1 override must reject 40 headers"
                    );
                    continue;
                }
                let response = response.unwrap();
                assert_eq!(
                    response.version(),
                    if protocol == Protocol::Http1 {
                        Version::HTTP_11
                    } else {
                        Version::HTTP_2
                    }
                );
                assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), id);
            }
            assert_eq!(calls.load(Ordering::Relaxed), 2);
        }
    }

    #[cfg(feature = "cookies")]
    #[tokio::test]
    async fn cookies_keep_the_request_uri_of_a_connect_target() {
        use http_body_util::BodyExt;

        /// Records the URIs that dispatch reads and stores cookies for.
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

        let store = Arc::new(Recorder::default());
        let dispatch = http1_dispatch(
            |request| {
                let target = format!("{} {:?}", request.uri(), request.headers()[COOKIE]);
                let mut response = Response::new(target);
                *response.status_mut() = http::StatusCode::FORBIDDEN;
                response
                    .headers_mut()
                    .insert(http::header::SET_COOKIE, HeaderValue::from_static("b=2"));
                response
            },
            Some(store.clone()),
        );
        let response = stack(dispatch, Protocol::Auto, true)
            .oneshot(
                Request::connect("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            )
            .await
            .unwrap();
        // The wire target names the default port; both cookie calls see the request URI.
        let target = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(target, "localhost:80 \"a=1\"");
        assert_eq!(
            *store.0.lock(),
            ["get http://localhost/", "set http://localhost/"]
        );
    }

    #[tokio::test]
    #[cfg(any(feature = "http2", feature = "http3"))]
    async fn websocket_route_probes_default_group_and_restores_upgrade() {
        let request = |uri, websocket: Option<bool>| {
            let mut request = Request::builder().uri(uri).body(()).unwrap();
            let extensions = request.extensions_mut();
            extensions
                .get_or_insert_default::<ConfigSet>()
                .insert(crate::Group::new("seven"));
            if let Some(extended_connect) = websocket {
                *RequestConfig::<RequestVersion>::get_mut(extensions) = Some(Version::HTTP_11);
                extensions.insert(DedicatedConnection { extended_connect });
            }
            request
        };
        let https = "https://localhost/chat";
        for (client, uri, extended_connect, probes) in [
            (Protocol::Auto, https, true, cfg!(feature = "http2")),
            #[cfg(feature = "http2")]
            (Protocol::Http2, https, true, true),
            (Protocol::Auto, https, false, false),
            (Protocol::Http1, https, true, false),
            #[cfg(feature = "http3")]
            (Protocol::Http3, https, true, true),
            // HTTP/3 has no cleartext group to probe.
            #[cfg(feature = "http3")]
            (Protocol::Http3, "http://localhost/chat", true, false),
        ] {
            let stack = stack(
                tower::service_fn(|request: DispatchRequest<()>| {
                    future::ready(Ok::<_, DispatchError<()>>(request))
                }),
                client,
                true,
            );
            let websocket = stack
                .clone()
                .oneshot(request(uri, Some(extended_connect)))
                .await
                .unwrap();
            assert!(websocket.dedicated);
            assert_eq!(websocket.req.resolved_protocol(), Protocol::Http1);
            if probes {
                // The probe targets the group ordinary requests use; those never probe.
                let plain = stack.oneshot(request(uri, None)).await.unwrap();
                assert!(plain.extended_connect_key.is_none());
                assert_eq!(websocket.extended_connect_key, Some(plain.req.key()));
            } else {
                assert!(websocket.extended_connect_key.is_none());
            }
        }

        // Versions whose `:protocol` marker a request carries.
        let markers = |request: &Request<()>| {
            let extensions = request.extensions();
            let mut versions = Vec::new();
            #[cfg(feature = "http2")]
            if extensions.get::<http2::ext::Protocol>().is_some() {
                versions.push(Version::HTTP_2);
            }
            #[cfg(feature = "http3")]
            if extensions.get::<netty::http3::Protocol>()
                == Some(&netty::http3::Protocol::WEBSOCKET)
            {
                versions.push(Version::HTTP_3);
            }
            versions
        };
        // Each version rewrites with its own marker and restores the original GET.
        let round_trip = |version| {
            let mut request = Request::get(https)
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
            assert_eq!(markers(&request), [version]);
            let names: Vec<_> = request.headers().keys().map(|name| name.as_str()).collect();
            assert_eq!(
                names,
                ["sec-websocket-version", "origin", "sec-websocket-protocol"]
            );

            upgrade.restore(&mut request);
            assert_eq!(request.method(), Method::GET);
            assert_eq!(request.version(), Version::HTTP_11);
            assert!(markers(&request).is_empty());
            assert!(request.headers().iter().eq(original.iter()));
        };
        #[cfg(feature = "http2")]
        round_trip(Version::HTTP_2);
        #[cfg(feature = "http3")]
        round_trip(Version::HTTP_3);
    }
}
