//! Connection checkout and one protocol dispatch attempt.

use std::task::{Context, Poll};

use futures_util::future::BoxFuture;
use http::{Response, Version};
use http_body::Body;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Service, ServiceExt};
use wreq_proto::{body::Incoming, rt::Executor as _};
#[cfg(feature = "cookies")]
use {
    crate::config::RequestConfig,
    crate::cookie::{CookieStore, Cookies},
    http::header::COOKIE,
    std::sync::Arc,
};

use super::ConfiguredRequest;
use crate::{
    client::{
        error::{Error, ErrorKind},
        pool::{self, Ver},
    },
    conn::{Connection, descriptor::ConnectionDescriptor},
    rt::{Executor, Timer},
};

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
    version: Ver,
    exec: Executor,
    #[cfg(feature = "cookies")]
    cookie_store: RequestConfig<Arc<dyn CookieStore>>,
}

/// Failure from one pool checkout and send attempt.
pub enum AttemptError<B> {
    /// A singleton creation generation disappeared before checkout completed.
    CheckoutCanceled {
        error: Error,
        request: Box<ConfiguredRequest<B>>,
    },
    /// Protocol dispatch returned a request before encoding began.
    Unsent {
        error: Error,
        request: Box<ConfiguredRequest<B>>,
        connection_reused: bool,
    },
    /// Failure that cannot be retried by the internal middleware.
    Terminal(Error),
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

impl<C, B> Service<ConfiguredRequest<B>> for Dispatch<C, B>
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

    fn call(&mut self, request: ConfiguredRequest<B>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let ConfiguredRequest {
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
                _ => this.version,
            };
            let checkout = this
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
                        request: Box::new(ConfiguredRequest {
                            request,
                            descriptor,
                            h1_builder,
                            h2_builder,
                        }),
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
                        Err(AttemptError::Unsent {
                            error: error
                                .into_client_error(ErrorKind::Canceled)
                                .with_connect_info(connect_info),
                            request: Box::new(ConfiguredRequest {
                                request,
                                descriptor,
                                h1_builder,
                                h2_builder,
                            }),
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
                this.exec.execute(async move {
                    let _ = pooled.ready().await;
                });
            }

            Ok(response)
        })
    }
}
