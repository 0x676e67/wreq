//! Tower services used by the low-level client request path.
//!
//! Configuration runs once before internal retries. Each attempt keeps its
//! checkout through dispatch, handing a busy HTTP/1 sender to a readiness task.
//! Only requests returned before encoding can be retried; bodies are never
//! reconstructed.

use std::{
    future::Future,
    mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use futures_util::future::{self, BoxFuture, Either, Ready};
use http::{Request, Response, Uri, Version, uri::PathAndQuery};
use http_body::Body;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{
    BoxError, Layer, Service, ServiceBuilder, ServiceExt,
    util::{MapErr, Oneshot},
};
use wreq_proto::{body::Incoming, conn, rt::Executor as _};
#[cfg(feature = "cookies")]
use {
    crate::cookie::{CookieStore, Cookies},
    http::header::COOKIE,
};

use super::{
    error::{Error, ErrorKind},
    layer::config::RequestOptions,
    pool::{self, ConnectionConfig},
};
use crate::{
    HttpVersion,
    config::RequestConfig,
    conn::{Connection, descriptor::ConnectionDescriptor},
    ext::UriExt,
    rt::{Executor, Timer},
};

/// Immutable behavior installed while the low-level service stack is built.
/// Each option moves into the layer that owns it during client construction.
/// This value holds no pool state or request body.
#[derive(Clone)]
pub struct Config {
    pub retry_unsent: bool,
    pub set_host: bool,
    pub version: HttpVersion,
    #[cfg(feature = "cookies")]
    pub cookie_store: Option<Arc<dyn CookieStore>>,
}

/// Configures requests and wraps dispatch with unsent retries and error mapping.
/// Base protocol builders are shared; request-local options are captured once
/// before any attempt, without cloning the body.
pub struct Stack<S, B> {
    #[allow(
        clippy::type_complexity,
        reason = "Keep the concrete Tower stack local without another alias"
    )]
    inner: MapErr<RetryUnsent<S>, fn(DispatchError<B>) -> BoxError>,
    proto: Arc<(conn::http1::Builder, conn::http2::Builder<Executor>)>,
    version: HttpVersion,
}

/// A request paired with the connection configuration shared by its attempts.
/// Configuration is captured before checkout and retained across unsent retries.
/// Dispatch returns this value only when the original body has not been sent.
pub struct PoolRequest<B> {
    request: Request<B>,
    connection: Arc<ConnectionConfig>,
}

/// Retries canceled checkouts and unsent requests on reused connections.
/// Only the original request returned by dispatch is eligible; failures after
/// encoding remain the responsibility of the public retry policy.
#[derive(Clone)]
pub struct RetryUnsent<S> {
    inner: S,
    enabled: bool,
}

pin_project! {
    /// Drives internal retries without cloning the request body.
    /// The first call consumes the caller's readiness reservation; subsequent
    /// attempts use `Oneshot` to pair readiness and dispatch on the same service.
    pub struct RetryUnsentFuture<S, B>
    where
        S: Service<PoolRequest<B>>,
    {
        #[pin]
        future: Either<S::Future, Oneshot<S, PoolRequest<B>>>,
        service: S,
        original_uri: Uri,
        had_cookie: bool,
        enabled: bool,
    }
}

/// Performs one connection-pool checkout and protocol send attempt.
///
/// Each call checks out a compatible sender, applies cookies, dispatches the
/// request, and attaches connection metadata. HTTP/2 releases its local
/// checkout after response headers. HTTP/1 returns immediately only when its
/// sender is ready again; otherwise a pool-owned task waits before returning
/// it. Errors preserve an unsent request when the protocol dispatcher can prove
/// encoding never began.
pub struct Dispatch<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    pool: pool::Pool<C, B>,
    version: HttpVersion,
    #[cfg(feature = "cookies")]
    cookie_store: RequestConfig<Arc<dyn CookieStore>>,
    exec: Executor,
}

/// Failure from one pool checkout and send attempt.
pub enum DispatchError<B> {
    CheckoutCanceled {
        error: Error,
        request: Box<PoolRequest<B>>,
    },
    Unsent {
        error: Error,
        request: Box<PoolRequest<B>>,
        connection_reused: bool,
    },
    Terminal(Error),
}

/// Creates the configuration and unsent-retry layers for a dispatch service.
///
/// Configuration runs once and shares its protocol builders across service
/// clones. Tower maps terminal dispatch errors only after retry classification,
/// preserving ownership of any request returned before encoding.
pub fn layer<S, B>(
    h1_builder: conn::http1::Builder,
    h2_builder: conn::http2::Builder<Executor>,
    retry_unsent: bool,
    version: HttpVersion,
) -> impl Layer<S, Service = Stack<S, B>> + Clone {
    // Both builders share one lifetime. One Arc avoids a second allocation and
    // separate reference-count updates on stack clones and pooled requests.
    let proto = Arc::new((h1_builder, h2_builder));

    ServiceBuilder::new()
        .layer_fn(move |inner| Stack {
            inner,
            proto: proto.clone(),
            version,
        })
        .map_err(DispatchError::into_error as fn(DispatchError<B>) -> BoxError)
        .layer_fn(move |inner| RetryUnsent {
            inner,
            enabled: retry_unsent,
        })
        .into_inner()
}

// ===== impl Stack =====

impl<S: Clone, B> Clone for Stack<S, B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            proto: self.proto.clone(),
            version: self.version,
        }
    }
}

impl<S, B> Service<Request<B>> for Stack<S, B>
where
    S: Service<PoolRequest<B>, Error = DispatchError<B>> + Clone,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Either<
        <MapErr<RetryUnsent<S>, fn(DispatchError<B>) -> BoxError> as Service<PoolRequest<B>>>::Future,
        Ready<Result<Self::Response, Self::Error>>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        // Select connections by origin without changing the request's wire target.
        let mut parts = request.uri().clone().into_parts();
        parts.path_and_query = Some(PathAndQuery::from_static("/"));
        let uri = match Uri::from_parts(parts) {
            Ok(uri) => uri,
            Err(source) => {
                return Either::Right(future::err(
                    Error::new(ErrorKind::UserAbsoluteUriRequired, source).into(),
                ));
            }
        };

        let RequestOptions {
            group,
            proxy,
            version,
            tls_options,
            http1_options,
            http2_options,
            socket_bind_options,
        } = RequestConfig::<RequestOptions>::remove(request.extensions_mut()).unwrap_or_default();

        // curl's ordinary H2 mode allows HTTPS negotiation; prior knowledge
        // remains explicit: https://curl.se/libcurl/c/CURLOPT_HTTP_VERSION.html
        // Extended CONNECT cannot become an H1 tunnel:
        // https://www.rfc-editor.org/rfc/rfc8441.html#section-4
        let version = match version {
            Some(Version::HTTP_10 | Version::HTTP_11) => Some(HttpVersion::Http1),
            Some(Version::HTTP_2)
                if uri.is_https()
                    && self.version != HttpVersion::Http2
                    && request.extensions().get::<http2::ext::Protocol>().is_none() =>
            {
                Some(HttpVersion::Auto)
            }
            Some(Version::HTTP_2) => Some(HttpVersion::Http2),
            Some(_) => {
                return Either::Right(future::err(
                    Error::from_kind(ErrorKind::UserUnsupportedVersion).into(),
                ));
            }
            None => None,
        };
        let descriptor =
            ConnectionDescriptor::new(uri, group, proxy, version, tls_options, socket_bind_options);

        Either::Left(self.inner.call(PoolRequest {
            request,
            connection: Arc::new(ConnectionConfig {
                descriptor,
                proto: self.proto.clone(),
                http1_options,
                http2_options,
            }),
        }))
    }
}

// ===== impl RetryUnsent =====

impl<S, B> Service<PoolRequest<B>> for RetryUnsent<S>
where
    S: Service<PoolRequest<B>, Error = DispatchError<B>> + Clone,
{
    type Response = S::Response;
    type Error = DispatchError<B>;
    type Future = RetryUnsentFuture<S, B>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: PoolRequest<B>) -> Self::Future {
        let original_uri = request.request.uri().clone();
        let had_cookie = cfg!(feature = "cookies")
            && request.request.headers().contains_key(http::header::COOKIE);
        let replacement = self.inner.clone();
        let mut service = mem::replace(&mut self.inner, replacement);
        let future = service.call(request);

        RetryUnsentFuture {
            future: Either::Left(future),
            service,
            original_uri,
            had_cookie,
            enabled: self.enabled,
        }
    }
}

// ===== impl RetryUnsentFuture =====

impl<S, B> Future for RetryUnsentFuture<S, B>
where
    S: Service<PoolRequest<B>, Error = DispatchError<B>> + Clone,
{
    type Output = Result<S::Response, DispatchError<B>>;

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
                Err(error) => return Poll::Ready(Err(error)),
            };

            *request.request.uri_mut() = this.original_uri.clone();
            // Regenerate automatic cookies for the next protocol; retain user headers.
            #[cfg(feature = "cookies")]
            if !*this.had_cookie {
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

// ===== impl DispatchError =====

impl<B> DispatchError<B> {
    fn into_error(self) -> BoxError {
        match self {
            Self::CheckoutCanceled { error, .. }
            | Self::Unsent { error, .. }
            | Self::Terminal(error) => error.into(),
        }
    }
}

// ===== impl Dispatch =====

impl<C, B> Dispatch<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Creates the terminal request service and its shared connection pool.
    pub fn new(
        pool_config: pool::Config,
        connector: C,
        config: Config,
        exec: Executor,
        timer: Timer,
    ) -> Self {
        Self {
            pool: pool::Pool::new(pool_config, connector, exec.clone(), timer, config.set_host),
            version: config.version,
            #[cfg(feature = "cookies")]
            cookie_store: RequestConfig::new(config.cookie_store),
            exec,
        }
    }
}

impl<C, B> Clone for Dispatch<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            version: self.version,
            exec: self.exec.clone(),
            #[cfg(feature = "cookies")]
            cookie_store: self.cookie_store.clone(),
        }
    }
}

impl<C, B> Service<PoolRequest<B>> for Dispatch<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Incoming>;
    type Error = DispatchError<B>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: PoolRequest<B>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let PoolRequest {
                mut request,
                connection,
            } = request;

            let version = connection.descriptor.version().unwrap_or(this.version);

            let mut pooled = match this.pool.checkout(connection.clone(), version).await {
                Ok(pooled) => pooled,
                Err(error) if pool::is_canceled(&*error) => {
                    return Err(DispatchError::CheckoutCanceled {
                        error: Error::new(ErrorKind::Connect, error),
                        request: Box::new(PoolRequest {
                            request,
                            connection,
                        }),
                    });
                }
                Err(error) => {
                    return Err(DispatchError::Terminal(Error::new(
                        ErrorKind::Connect,
                        error,
                    )));
                }
            };

            if connection.descriptor.version() == Some(HttpVersion::Auto) {
                // Resolve the wire version on every attempt: an unsent retry may
                // select a different protocol, but retains the original preference.
                *request.version_mut() = if pooled.is_http2() {
                    Version::HTTP_2
                } else {
                    Version::HTTP_11
                };
            } else if pooled.is_http1() && request.version() == Version::HTTP_2 {
                warn!("Connection is HTTP/1, but request requires HTTP/2");
                return Err(DispatchError::Terminal(
                    Error::from_kind(ErrorKind::UserUnsupportedVersion)
                        .with_connect_info(pooled.conn_info().clone()),
                ));
            }

            #[cfg(feature = "cookies")]
            let uri = request.uri().clone();
            #[cfg(feature = "cookies")]
            let cookie_store = this.cookie_store.fetch(request.extensions()).cloned();

            #[cfg(feature = "cookies")]
            if let Some(ref cookie_store) = cookie_store {
                let headers = request.headers_mut();
                if !headers.contains_key(COOKIE) {
                    let version = if pooled.is_http2() {
                        Version::HTTP_2
                    } else {
                        Version::HTTP_11
                    };

                    match cookie_store.cookies(&uri, version) {
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
            }

            let mut response = match pooled.call(request).await {
                Ok(response) => response,
                Err(mut error) => {
                    let connection_reused = pooled.is_reused();
                    let connect_info = pooled.conn_info().clone();
                    return if let Some(request) = error.take_message() {
                        Err(DispatchError::Unsent {
                            error: error
                                .into_client_error(ErrorKind::Canceled)
                                .with_connect_info(connect_info),
                            request: Box::new(PoolRequest {
                                request,
                                connection,
                            }),
                            connection_reused,
                        })
                    } else {
                        let mut error = error.into_client_error(ErrorKind::SendRequest);
                        if pooled.is_http2()
                            && connection.descriptor.uri().is_https()
                            && !connect_info.is_negotiated_h2()
                        {
                            error = error.with_context(
                                "HTTP/2 was used for HTTPS without reported h2 ALPN; \
                                 the peer may not support HTTP/2",
                            );
                        }
                        Err(DispatchError::Terminal(
                            error.with_connect_info(connect_info),
                        ))
                    };
                }
            };

            #[cfg(feature = "cookies")]
            if let Some(cookie_store) = cookie_store {
                let mut cookies = response
                    .headers()
                    .get_all(http::header::SET_COOKIE)
                    .iter()
                    .peekable();
                if cookies.peek().is_some() {
                    cookie_store.set_cookies(&mut cookies, &uri);
                }
            }

            pooled.conn_info().set_extras(response.extensions_mut());
            response.extensions_mut().insert(pooled.conn_info().clone());

            if pooled.is_http2() || !pooled.is_pool_enabled() || pooled.is_ready() {
                drop(pooled);
            } else {
                this.exec.execute(async move {
                    let _ = pooled.ready().await;
                });
            }

            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[cfg(feature = "cookies")]
    #[tokio::test]
    async fn unsent_retries_regenerate_automatic_cookies() {
        for explicit in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let attempts = calls.clone();
            let service = tower::service_fn(move |mut request: PoolRequest<Vec<u8>>| {
                let headers = request.request.headers_mut();
                let values: Vec<_> = headers.get_all(COOKIE).iter().collect();
                if explicit {
                    assert_eq!(values, ["user=1", "other=2"]);
                } else {
                    assert!(values.is_empty(), "automatic cookies must be refreshed");
                }

                if attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                    if !explicit {
                        headers.append(COOKIE, http::HeaderValue::from_static("h2=1"));
                        headers.append(COOKIE, http::HeaderValue::from_static("other=2"));
                    }
                    future::ready(Err(DispatchError::Unsent {
                        error: Error::from_kind(ErrorKind::Canceled),
                        request: Box::new(request),
                        connection_reused: true,
                    }))
                } else {
                    future::ready(Ok(()))
                }
            });
            let mut request = Request::builder().uri("https://localhost/");
            if explicit {
                request = request.header(COOKIE, "user=1").header(COOKIE, "other=2");
            }
            ServiceBuilder::new()
                .layer(layer(
                    conn::http1::Builder::default(),
                    conn::http2::Builder::new(Executor::default()),
                    true,
                    HttpVersion::Auto,
                ))
                .service(service)
                .oneshot(request.body(Vec::new()).unwrap())
                .await
                .unwrap();
            assert_eq!(calls.load(Ordering::Relaxed), 2);
        }
    }

    #[tokio::test]
    async fn protocol_selection_preserves_wire_versions_and_pool_groups() {
        let mut keys = Vec::new();
        for (wire, client, extended, expected) in [
            (
                Some(Version::HTTP_10),
                HttpVersion::Auto,
                false,
                Some(HttpVersion::Http1),
            ),
            (
                Some(Version::HTTP_11),
                HttpVersion::Auto,
                false,
                Some(HttpVersion::Http1),
            ),
            (
                Some(Version::HTTP_2),
                HttpVersion::Auto,
                false,
                Some(HttpVersion::Auto),
            ),
            (None, HttpVersion::Auto, false, None),
            (
                Some(Version::HTTP_2),
                HttpVersion::Http2,
                false,
                Some(HttpVersion::Http2),
            ),
            (
                Some(Version::HTTP_2),
                HttpVersion::Auto,
                true,
                Some(HttpVersion::Http2),
            ),
            (
                Some(Version::HTTP_11),
                HttpVersion::Http2,
                false,
                Some(HttpVersion::Http1),
            ),
            (
                Some(Version::HTTP_2),
                HttpVersion::Http1,
                false,
                Some(HttpVersion::Auto),
            ),
        ] {
            let mut request = Request::builder()
                .uri("https://localhost/upload?part=1")
                .version(wire.unwrap_or(Version::HTTP_11))
                .body(())
                .unwrap();
            request
                .extensions_mut()
                .insert(RequestConfig::<RequestOptions>::new(Some(RequestOptions {
                    version: wire,
                    ..RequestOptions::default()
                })));
            if extended {
                *request.method_mut() = http::Method::CONNECT;
                request
                    .extensions_mut()
                    .insert(http2::ext::Protocol::from_static("websocket"));
            }
            let service = tower::service_fn(|request: PoolRequest<()>| {
                future::ready(Ok::<_, DispatchError<()>>(request))
            });
            let request = ServiceBuilder::new()
                .layer(layer(
                    conn::http1::Builder::default(),
                    conn::http2::Builder::new(Executor::default()),
                    true,
                    client,
                ))
                .service(service)
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(request.connection.descriptor.version(), expected);
            assert_eq!(request.request.version(), wire.unwrap_or(Version::HTTP_11));
            keys.push(request.connection.descriptor.id());
        }
        assert_eq!(
            keys[0], keys[1],
            "HTTP/1.0 and HTTP/1.1 select one protocol pool"
        );
        assert_eq!(keys[1], keys[6], "explicit H1 overrides the client mode");
        assert_ne!(
            keys[1], keys[2],
            "fixed H1 and negotiated requests remain isolated"
        );
        assert_ne!(
            keys[2], keys[3],
            "explicit negotiation differs from client inheritance"
        );
        assert_ne!(
            keys[2], keys[4],
            "negotiated and fixed H2 must not share a pool entry"
        );
        assert_eq!(keys[4], keys[5], "extended CONNECT requires fixed H2");
        assert_eq!(keys[2], keys[7], "request negotiation overrides fixed H1");
    }

    #[tokio::test]
    async fn unsent_retries_keep_request_state_and_error_sources() {
        for (enabled, reused, unsent, expected_calls) in [
            (true, true, false, 1),
            (true, true, true, 2),
            (false, true, true, 1),
            (true, false, true, 1),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let attempts = calls.clone();
            let mut connection = None;
            let service = tower::service_fn(move |mut request: PoolRequest<Vec<u8>>| {
                assert_eq!(request.request.uri(), "http://localhost/upload?part=1");
                assert_eq!(request.request.body(), b"payload");
                assert_eq!(request.connection.descriptor.uri(), "http://localhost/");

                let result = if attempts.fetch_add(1, Ordering::Relaxed) == 0 && unsent {
                    connection = Some(request.connection.clone());
                    *request.request.uri_mut() = Uri::from_static("/upload?part=1");
                    Err(DispatchError::Unsent {
                        error: Error::new(ErrorKind::Canceled, std::io::Error::other("unsent")),
                        request: Box::new(request),
                        connection_reused: reused,
                    })
                } else {
                    if let Some(connection) = &connection {
                        assert!(Arc::ptr_eq(connection, &request.connection));
                    }
                    Ok(())
                };
                future::ready(result)
            });

            let result = ServiceBuilder::new()
                .layer(layer(
                    conn::http1::Builder::default(),
                    conn::http2::Builder::new(Executor::default()),
                    enabled,
                    HttpVersion::Auto,
                ))
                .service(service)
                .oneshot(
                    Request::builder()
                        .uri("http://localhost/upload?part=1")
                        .body(b"payload".to_vec())
                        .unwrap(),
                );
            let mut task = tokio_test::task::spawn(result);
            let Poll::Ready(result) = task.poll() else {
                panic!("a successful or terminal result should finish without yielding");
            };
            assert!(!task.is_woken());

            assert_eq!(calls.load(Ordering::Relaxed), expected_calls);
            if !unsent || expected_calls == 2 {
                result.unwrap();
            } else {
                let error = result.unwrap_err();
                assert!(error.is::<Error>());
                assert_eq!(error.source().unwrap().to_string(), "unsent");
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let gate = Arc::new(tokio::sync::Notify::new());
        let ready = gate.clone();
        let service = tower::service_fn(move |request: PoolRequest<Vec<u8>>| {
            let first = attempts.fetch_add(1, Ordering::Relaxed) == 0;
            let ready = ready.clone();
            async move {
                if first {
                    Err(DispatchError::CheckoutCanceled {
                        error: Error::from_kind(ErrorKind::Canceled),
                        request: Box::new(request),
                    })
                } else {
                    ready.notified().await;
                    Ok(())
                }
            }
        });
        let mut task = tokio_test::task::spawn(
            ServiceBuilder::new()
                .layer(layer(
                    conn::http1::Builder::default(),
                    conn::http2::Builder::new(Executor::default()),
                    true,
                    HttpVersion::Auto,
                ))
                .service(service)
                .oneshot(
                    Request::builder()
                        .uri("http://localhost/")
                        .body(Vec::new())
                        .unwrap(),
                ),
        );
        assert!(task.poll().is_pending());
        assert!(!task.is_woken(), "a pending retry owns its wakeup");
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        gate.notify_one();
        assert!(task.is_woken());
        assert!(matches!(task.poll(), Poll::Ready(Ok(()))));

        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let service = tower::service_fn(move |request: PoolRequest<Vec<u8>>| {
            attempts.fetch_add(1, Ordering::Relaxed);
            future::ready(Err::<(), _>(DispatchError::CheckoutCanceled {
                error: Error::from_kind(ErrorKind::Canceled),
                request: Box::new(request),
            }))
        });
        let mut task = tokio_test::task::spawn(
            ServiceBuilder::new()
                .layer(layer(
                    conn::http1::Builder::default(),
                    conn::http2::Builder::new(Executor::default()),
                    true,
                    HttpVersion::Auto,
                ))
                .service(service)
                .oneshot(
                    Request::builder()
                        .uri("http://localhost/")
                        .body(Vec::new())
                        .unwrap(),
                ),
        );
        for expected in [2, 4] {
            assert!(task.poll().is_pending());
            assert!(task.is_woken());
            assert_eq!(calls.load(Ordering::Relaxed), expected);
        }
    }
}
