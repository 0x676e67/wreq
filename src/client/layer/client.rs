//! Much of this codebase is adapted and refined from [hyper](https://github.com/hyperium/hyper-util),

mod conn;
mod error;
mod pool;
mod service;

use std::{
    num::NonZeroUsize,
    task::{self, Poll},
    time::Duration,
};

use futures_util::future::{self, Either, Ready};
use http::{
    Method, Request, Response, Uri, Version,
    uri::{PathAndQuery, Scheme},
};
use http_body::Body;
use pool::Ver;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Service, ServiceBuilder};
use wreq_proto::{body::Incoming, conn as proto, http1::Http1Options, http2::Http2Options};
#[cfg(feature = "cookies")]
use {crate::config::RequestConfig, crate::cookie::CookieStore, std::sync::Arc};

pub use self::error::Error;
use self::error::ErrorKind;
use crate::{
    conn::{Connection, descriptor::ConnectionDescriptor},
    pool::{PoolLimits, PoolStrategy},
    rt::{Executor, Timer},
};

/// Low-level request configuration, retry, and pool dispatch stack.
type ClientService<C, B> =
    service::ConfigureRequest<service::RetryUnsent<service::PoolService<C, B>>>;

/// Validates and sends low-level HTTP requests through the client service stack.
///
/// This is the caller-facing Tower service used beneath `Client`. It validates
/// request versions and absolute URIs before request-local configuration,
/// internal cancellation retries, connection checkout, and protocol dispatch.
/// Clones share all connection-pool state and never clone request bodies.
#[must_use]
pub(crate) struct HttpClient<C, B>
where
    C: tower::Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Composed service stack shared by client clones.
    inner: ClientService<C, B>,
}

/// Request behavior shared by the client service stack.
#[derive(Clone)]
struct Config {
    /// Whether requests canceled before encoding may be retried.
    retry_canceled_requests: bool,

    /// Whether HTTP/1 should generate a missing `Host` field.
    set_host: bool,

    /// Preferred protocol when a request does not require one.
    ver: Ver,

    #[cfg(feature = "cookies")]
    /// Optional cookie store installed on the dispatch service.
    cookie_store: Option<Arc<dyn CookieStore>>,
}

// ===== impl HttpClient =====

impl<C, B> Service<Request<B>> for HttpClient<C, B>
where
    C: tower::Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Incoming>;
    type Error = BoxError;
    type Future = Either<
        <ClientService<C, B> as Service<Request<B>>>::Future,
        Ready<Result<Self::Response, Self::Error>>,
    >;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let is_http_connect = req.method() == Method::CONNECT;
        match req.version() {
            Version::HTTP_10 if is_http_connect => {
                warn!("CONNECT is not allowed for HTTP/1.0");
                let error = Error::from_kind(ErrorKind::UserUnsupportedRequestMethod);
                return Either::Right(future::err(error.into()));
            }
            Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2 => {}
            _unsupported => {
                warn!("Request has unsupported version: {:?}", _unsupported);
                let error = Error::from_kind(ErrorKind::UserUnsupportedVersion);
                return Either::Right(future::err(error.into()));
            }
        }

        match normalize_uri(&mut req, is_http_connect) {
            Ok(()) => Either::Left(self.inner.call(req)),
            Err(error) => Either::Right(future::err(error.into())),
        }
    }
}

// Deriving this implementation would unnecessarily require `B: Clone`.
impl<C, B> Clone for HttpClient<C, B>
where
    C: tower::Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Unpin + Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// A builder to configure a new [`HttpClient`].
#[derive(Clone)]
pub struct Builder {
    /// Request retry and protocol-selection behavior.
    config: Config,

    /// Runtime used by protocol drivers and pool maintenance.
    exec: Executor,

    /// Base HTTP/1 handshake configuration.
    h1_builder: proto::http1::Builder,

    /// Base HTTP/2 handshake configuration.
    h2_builder: proto::http2::Builder<Executor>,

    /// Connection-pool policy and capacity limits.
    pool_config: pool::Config,

    /// Clock used by connection-pool maintenance.
    pool_timer: Timer,
}

// ===== impl Builder =====

impl Builder {
    /// Construct a new Builder.
    pub fn new(exec: Executor) -> Self {
        Self {
            config: Config {
                retry_canceled_requests: true,
                set_host: true,
                ver: Ver::Auto,
                #[cfg(feature = "cookies")]
                cookie_store: None,
            },
            exec: exec.clone(),
            h1_builder: proto::http1::Builder::default(),
            h2_builder: proto::http2::Builder::new(exec),
            pool_config: pool::Config {
                idle_timeout: Some(Duration::from_secs(90)),
                max_idle_per_host: usize::MAX,
                max_pool_size: None,
                ..pool::Config::default()
            },
            pool_timer: Timer::default(),
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

    /// Sets the maximum number of connection groups retained by the pool.
    ///
    /// Default is `None` (no limit).
    #[inline]
    pub fn pool_max_size(mut self, max_size: impl Into<Option<NonZeroUsize>>) -> Self {
        self.pool_config.max_pool_size = max_size.into();
        self
    }

    /// Sets the connection acquisition strategy.
    #[inline]
    pub fn pool_strategy(mut self, strategy: PoolStrategy) -> Self {
        self.pool_config.strategy = strategy;
        self
    }

    /// Sets connection limits for the pool.
    #[inline]
    pub fn pool_limits(mut self, limits: PoolLimits) -> Self {
        self.pool_config.limits = limits;
        self
    }

    /// Set whether the connection **must** use HTTP/1.
    #[inline]
    pub fn http1_only(mut self, val: bool) -> Self {
        if val {
            self.config.ver = Ver::Http1;
        } else if self.config.ver == Ver::Http1 {
            self.config.ver = Ver::Auto;
        }
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
        if val {
            self.config.ver = Ver::Http2;
        } else if self.config.ver == Ver::Http2 {
            self.config.ver = Ver::Auto;
        }
        self
    }

    /// Provide a timer to be used for http2
    ///
    /// See the documentation of [`http2::client::Builder::timer`] for more
    /// details.
    ///
    /// [`http2::client::Builder::timer`]: https://docs.rs/http2/latest/http2/client/struct.Builder.html#method.timer
    #[inline]
    pub fn http2_timer(mut self, timer: Timer) -> Self {
        self.h2_builder = self.h2_builder.timer(timer);
        self
    }

    /// Provide a configuration for HTTP/1.
    #[inline]
    pub fn http1_options<O>(mut self, opts: O) -> Self
    where
        O: Into<Option<Http1Options>>,
    {
        if let Some(opts) = opts.into() {
            self.h1_builder = self.h1_builder.options(opts);
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
            self.h2_builder = self.h2_builder.options(opts);
        }
        self
    }

    /// Provide a timer to be used for timeouts and intervals in connection pools.
    #[inline]
    pub fn pool_timer(mut self, timer: Timer) -> Self {
        self.pool_timer = timer;
        self
    }

    /// Provide a cookie store for automatic cookie management.
    #[inline]
    #[cfg(feature = "cookies")]
    pub fn cookie_store(mut self, cookie_store: Option<Arc<dyn CookieStore>>) -> Self {
        self.config.cookie_store = cookie_store;
        self
    }

    /// Combine the configuration of this builder with a connector to create a `HttpClient`.
    pub fn build<C, B>(self, connector: C) -> HttpClient<C, B>
    where
        C: tower::Service<ConnectionDescriptor> + Clone + Send + Sync + 'static,
        C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
        C::Error: Into<BoxError>,
        C::Future: Unpin + Send + 'static,
        B: Body + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
    {
        let Config {
            retry_canceled_requests,
            set_host,
            ver,
            #[cfg(feature = "cookies")]
            cookie_store,
        } = self.config;
        let exec = self.exec.clone();
        let timer = self.pool_timer.clone();
        let pool = pool::Pool::new(self.pool_config, connector, exec.clone(), timer, set_host);
        let service = service::PoolService::new(pool, ver, exec);
        #[cfg(feature = "cookies")]
        let service = service.with_cookie_store(RequestConfig::new(cookie_store));
        let h1_builder = self.h1_builder;
        let h2_builder = self.h2_builder;
        let service = ServiceBuilder::new()
            .layer_fn(move |inner| {
                service::ConfigureRequest::new(inner, h1_builder.clone(), h2_builder.clone())
            })
            .layer_fn(move |inner| service::RetryUnsent::new(inner, retry_canceled_requests))
            .service(service);
        HttpClient { inner: service }
    }
}

/// Validates an absolute request URI and normalizes authority-form `CONNECT`.
fn normalize_uri<B>(req: &mut Request<B>, is_http_connect: bool) -> Result<(), Error> {
    match (req.uri().scheme(), req.uri().authority()) {
        (Some(_), Some(_)) => Ok(()),
        (None, Some(authority)) if is_http_connect => {
            let scheme = match authority.port_u16() {
                Some(443) => Scheme::HTTPS,
                _ => Scheme::HTTP,
            };
            set_scheme(req.uri_mut(), scheme)
        }
        _ => {
            debug!(
                "Client requires absolute-form URIs, received: {:?}",
                req.uri()
            );
            Err(Error::from_kind(ErrorKind::UserAbsoluteUriRequired))
        }
    }
}

/// Clones a validated request URI and strips it to its connection origin.
fn connection_origin(uri: &Uri) -> Result<Uri, Error> {
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(PathAndQuery::from_static("/"));
    Uri::from_parts(parts).map_err(|error| Error::new(ErrorKind::UserAbsoluteUriRequired, error))
}

/// Adds a scheme to an authority-form URI while preserving its authority.
fn set_scheme(uri: &mut Uri, scheme: Scheme) -> Result<(), Error> {
    let old = std::mem::take(uri);
    let mut parts: ::http::uri::Parts = old.into();
    parts.scheme = Some(scheme);
    parts.path_and_query = Some(PathAndQuery::from_static("/"));
    *uri = Uri::from_parts(parts)
        .map_err(|error| Error::new(ErrorKind::UserAbsoluteUriRequired, error))?;
    Ok(())
}
