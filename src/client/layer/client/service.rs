//! Request middleware used by the low-level client.
//!
//! [`ConfigureRequest`] consumes request-local transport options,
//! [`RetryUnsent`] retries only requests returned before encoding, and
//! [`PoolService`] performs one checkout and dispatch attempt. Connection-bound
//! HTTP/1 preparation is composed from [`SetHost`] and [`Http1RequestTarget`].
//!
//! HTTP/1 request-target forms are defined by RFC 9112 section 3.2:
//! <https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2>

use std::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures_util::future::{self, BoxFuture, Either, Ready};
use http::{
    HeaderValue, Method, Request, Response, Uri, Version,
    header::{HOST, PROXY_AUTHORIZATION},
};
use http_body::Body;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Service, util::Oneshot};
use wreq_proto::{body::Incoming, conn as proto, rt::Executor as _};
#[cfg(feature = "cookies")]
use {
    crate::cookie::{CookieStore, Cookies},
    http::header::COOKIE,
    std::sync::Arc,
};

use super::{Error, ErrorKind, connection_origin, pool, pool::Ver};
use crate::{
    client::layer::config::RequestOptions,
    config::RequestConfig,
    conn::{Connected, Connection, descriptor::ConnectionDescriptor},
    rt::{Executor, Timer},
};

/// Request and connection settings prepared for one low-level send operation.
///
/// The request body stays owned by this value until protocol dispatch begins.
/// This lets a canceled pool checkout or an encoding-before-send failure return
/// the same request to [`RetryUnsent`] without cloning its body.
pub(crate) struct PoolRequest<B> {
    /// User request after request-local options have been removed.
    request: Request<B>,

    /// Connection identity and transport options shared by retries.
    descriptor: ConnectionDescriptor,

    /// HTTP/1 handshake configuration for this logical request.
    h1_builder: proto::http1::Builder,

    /// HTTP/2 handshake configuration for this logical request.
    h2_builder: proto::http2::Builder<Executor>,
}

/// Applies request-local connection and protocol configuration.
///
/// This is the first service in the low-level client stack. It strips the URI
/// to a connection origin, consumes private request options, and forwards a
/// [`PoolRequest`] while leaving the request body untouched.
#[derive(Clone)]
pub(crate) struct ConfigureRequest<S> {
    /// Service receiving the prepared pool request.
    inner: S,

    /// Base HTTP/1 configuration cloned for each logical request.
    h1_builder: proto::http1::Builder,

    /// Base HTTP/2 configuration cloned for each logical request.
    h2_builder: proto::http2::Builder<Executor>,
}

/// Retries requests returned before protocol encoding begins.
///
/// The middleware also retries a canceled singleton creation batch. It never
/// recreates a body: only the exact request returned by the inner service is
/// sent again. Protocol errors after encoding remain terminal here and are
/// left to the public retry policy.
#[derive(Clone)]
pub(crate) struct RetryUnsent<S> {
    /// Service performing one pool checkout and send attempt.
    inner: S,

    /// Whether internal cancellation retries are enabled.
    enabled: bool,
}

/// Performs one connection-pool checkout and protocol send attempt.
///
/// Each call checks out a compatible sender, applies cookies, dispatches the
/// request, and attaches connection metadata. HTTP/2 releases its local
/// checkout after response headers. HTTP/1 returns immediately only when its
/// sender is ready again; otherwise a pool-owned task waits before returning
/// it. Errors preserve an unsent request when the protocol dispatcher can prove
/// encoding never began.
pub(crate) struct PoolService<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Shared connection pool and protocol sender factory.
    pool: pool::Pool<C, B>,

    /// Default protocol selection when the request does not force a version.
    version: Ver,

    /// Runtime used to return a busy HTTP/1 sender in the background.
    exec: Executor,

    #[cfg(feature = "cookies")]
    /// Optional cookie store selected through request extensions.
    cookie_store: RequestConfig<Arc<dyn CookieStore>>,
}

/// Failure from one pool checkout and send attempt.
#[allow(clippy::large_enum_variant)]
pub(crate) enum AttemptError<B> {
    /// A singleton creation generation disappeared before checkout completed.
    CheckoutCanceled {
        /// Client error reported when internal retries are disabled.
        error: Error,

        /// Request that never reached protocol dispatch.
        request: PoolRequest<B>,
    },
    /// Protocol dispatch returned a request before encoding began.
    Unsent {
        /// Dispatch failure associated with the returned request.
        error: Error,

        /// Exact request and connection settings available for retry.
        request: PoolRequest<B>,

        /// Whether the failed sender came from existing pool state.
        connection_reused: bool,
    },
    /// Failure that cannot be retried by the internal middleware.
    Terminal(Error),
}

pin_project! {
    /// Response future for [`RetryUnsent`].
    ///
    /// The first attempt uses the readiness already obtained by the caller.
    /// Later attempts use [`Oneshot`] so every retry observes the inner
    /// service's readiness contract before it is called again.
    pub(crate) struct RetryFuture<S, B>
    where
        S: Service<PoolRequest<B>>,
    {
        #[pin]
        // Current first-attempt or readiness-aware retry future.
        future: Either<S::Future, Oneshot<S, PoolRequest<B>>>,

        // One-attempt service cloned for later retries.
        service: S,

        // Absolute URI restored after connection-bound request preparation.
        original_uri: Uri,

        // Whether canceled or proven-unsent requests may be retried.
        enabled: bool,
    }
}

// ===== impl ConfigureRequest =====

impl<S> ConfigureRequest<S> {
    /// Wraps a pool request service with request-local configuration handling.
    pub(super) fn new(
        inner: S,
        h1_builder: proto::http1::Builder,
        h2_builder: proto::http2::Builder<Executor>,
    ) -> Self {
        Self {
            inner,
            h1_builder,
            h2_builder,
        }
    }
}

impl<S, B> Service<Request<B>> for ConfigureRequest<S>
where
    S: Service<PoolRequest<B>, Error = BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let uri = match connection_origin(request.uri()) {
            Ok(uri) => uri,
            Err(error) => return Either::Right(future::err(error.into())),
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

        let h1_builder = http1_options
            .map(|options| self.h1_builder.clone().options(options))
            .unwrap_or_else(|| self.h1_builder.clone());
        let h2_builder = http2_options
            .map(|options| self.h2_builder.clone().options(options))
            .unwrap_or_else(|| self.h2_builder.clone());
        let descriptor =
            ConnectionDescriptor::new(uri, group, proxy, version, tls_options, socket_bind_options);

        Either::Left(self.inner.call(PoolRequest {
            request,
            descriptor,
            h1_builder,
            h2_builder,
        }))
    }
}

// ===== impl RetryUnsent =====

impl<S> RetryUnsent<S> {
    /// Wraps one-attempt request service with internal cancellation retries.
    pub(super) fn new(inner: S, enabled: bool) -> Self {
        Self { inner, enabled }
    }
}

impl<S, B, R> Service<PoolRequest<B>> for RetryUnsent<S>
where
    S: Service<PoolRequest<B>, Response = R, Error = AttemptError<B>> + Clone,
{
    type Response = R;
    type Error = BoxError;
    type Future = RetryFuture<S, B>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(|error| match error {
            AttemptError::CheckoutCanceled { error, .. }
            | AttemptError::Unsent { error, .. }
            | AttemptError::Terminal(error) => error.into(),
        })
    }

    fn call(&mut self, request: PoolRequest<B>) -> Self::Future {
        let original_uri = request.request.uri().clone();
        let replacement = self.inner.clone();
        let mut service = mem::replace(&mut self.inner, replacement);
        let future = service.call(request);

        RetryFuture {
            future: Either::Left(future),
            service,
            original_uri,
            enabled: self.enabled,
        }
    }
}

// ===== impl RetryFuture =====

impl<S, B, R> Future for RetryFuture<S, B>
where
    S: Service<PoolRequest<B>, Response = R, Error = AttemptError<B>> + Clone,
{
    type Output = Result<R, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let result = ready!(this.future.as_mut().poll(cx));

        let mut request = match result {
            Ok(response) => return Poll::Ready(Ok(response)),
            Err(AttemptError::CheckoutCanceled {
                error: _error,
                request,
            }) if *this.enabled => {
                trace!("singleton connection batch canceled, trying again (reason={_error:?})");
                request
            }
            Err(AttemptError::Unsent {
                error: _error,
                request,
                connection_reused: true,
            }) if *this.enabled => {
                trace!("unstarted request canceled, trying again (reason={_error:?})");
                request
            }
            Err(AttemptError::CheckoutCanceled { error, .. })
            | Err(AttemptError::Unsent { error, .. })
            | Err(AttemptError::Terminal(error)) => return Poll::Ready(Err(error.into())),
        };

        *request.request.uri_mut() = this.original_uri.clone();
        this.future
            .set(Either::Right(Oneshot::new(this.service.clone(), request)));
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ===== impl PoolService =====

impl<C, B> PoolService<C, B>
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
    pub(super) fn new(
        pool_config: pool::Config,
        connector: C,
        version: Ver,
        exec: Executor,
        timer: Timer,
        set_host: bool,
        #[cfg(feature = "cookies")] cookie_store: Option<Arc<dyn CookieStore>>,
    ) -> Self {
        let pool = pool::Pool::new(pool_config, connector, exec.clone(), timer, set_host);

        Self {
            pool,
            version,
            exec,
            #[cfg(feature = "cookies")]
            cookie_store: RequestConfig::new(cookie_store),
        }
    }
}

impl<C, B> Clone for PoolService<C, B>
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

impl<C, B> Service<PoolRequest<B>> for PoolService<C, B>
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
    type Error = AttemptError<B>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: PoolRequest<B>) -> Self::Future {
        let service = self.clone();
        Box::pin(service.send(request))
    }
}

impl<C, B> PoolService<C, B>
where
    C: Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Executes one pool checkout and request dispatch attempt.
    async fn send(self, request: PoolRequest<B>) -> Result<Response<Incoming>, AttemptError<B>> {
        let PoolRequest {
            request,
            descriptor,
            h1_builder,
            h2_builder,
        } = request;
        #[cfg(feature = "cookies")]
        let mut request = request;
        let version = match descriptor.version() {
            Some(Version::HTTP_10 | Version::HTTP_11) => Ver::Http1,
            Some(Version::HTTP_2) => Ver::Http2,
            _ => self.version,
        };
        let checkout = self
            .pool
            .checkout(
                descriptor.clone(),
                version,
                h1_builder.clone(),
                h2_builder.clone(),
            )
            .await;
        let mut pooled = match checkout {
            Ok(pooled) => pooled,
            Err(error) if pool::is_canceled(&*error) => {
                return Err(AttemptError::CheckoutCanceled {
                    error: Error::new(ErrorKind::Connect, error),
                    request: PoolRequest {
                        request,
                        descriptor,
                        h1_builder,
                        h2_builder,
                    },
                });
            }
            Err(error) => {
                return Err(AttemptError::Terminal(Error::new(
                    ErrorKind::Connect,
                    error,
                )));
            }
        };

        if pooled.is_http1() && request.version() == Version::HTTP_2 {
            warn!("Connection is HTTP/1, but request requires HTTP/2");
            return Err(AttemptError::Terminal(
                Error::from_kind(ErrorKind::UserUnsupportedVersion)
                    .with_connect_info(pooled.conn_info().clone()),
            ));
        }

        #[cfg(feature = "cookies")]
        let uri = request.uri().clone();
        #[cfg(feature = "cookies")]
        let cookie_store = self.cookie_store.fetch(request.extensions()).cloned();

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

        let mut response = match pooled.try_send_request(request).await {
            Ok(response) => response,
            Err(mut error) => {
                let connection_reused = pooled.is_reused();
                let connect_info = pooled.conn_info().clone();
                return if let Some(request) = error.take_message() {
                    Err(AttemptError::Unsent {
                        error: error
                            .into_client_error(ErrorKind::Canceled)
                            .with_connect_info(connect_info),
                        request: PoolRequest {
                            request,
                            descriptor,
                            h1_builder,
                            h2_builder,
                        },
                        connection_reused,
                    })
                } else {
                    Err(AttemptError::Terminal(
                        error
                            .into_client_error(ErrorKind::SendRequest)
                            .with_connect_info(connect_info),
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
            let on_idle = std::future::poll_fn(move |cx| pooled.poll_ready(cx));
            self.exec.execute(async move {
                let _ = on_idle.await;
            });
        }

        Ok(response)
    }
}

/// Ensures an HTTP request has a `Host` field before protocol encoding.
///
/// The middleware can be disabled for callers that manage `Host` themselves.
/// It reads the absolute request URI before an inner target middleware converts
/// that URI to HTTP/1 origin-form or authority-form.
#[derive(Clone)]
pub struct SetHost<S> {
    /// Protocol service receiving the request after `Host` handling.
    inner: S,

    /// Whether a missing `Host` field should be generated.
    enabled: bool,
}

/// Applies the HTTP/1 request-target form for one established connection.
///
/// Direct requests use origin-form, `CONNECT` uses authority-form, and forward
/// proxy requests retain absolute-form. Proxy authorization and configured
/// proxy headers are applied in the same step because they depend on the
/// selected connection.
#[derive(Clone)]
pub struct Http1RequestTarget<S> {
    /// Protocol sender receiving the prepared request.
    inner: S,

    /// Metadata supplied by the selected connector.
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

impl<S> Http1RequestTarget<S> {
    /// Wraps a request service with connection-specific target handling.
    pub fn new(inner: S, connected: Connected) -> Self {
        Self { inner, connected }
    }

    /// Borrows the wrapped protocol service.
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S, B> Service<Request<B>> for Http1RequestTarget<S>
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
            Ok(()) => Either::Left(self.inner.call(req)),
            Err(error) => Either::Right(future::err(error.into())),
        }
    }
}

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
    if let Some(path) = uri.path_and_query() {
        if path != "/" {
            warn!("HTTP/1.1 CONNECT request stripping path: {:?}", path);
        }
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
