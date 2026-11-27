//! Low-level Tower service for request preparation, pool checkout, and unsent retries.
//!
//! [`Client`] prepares the connection config and pool key once, then checks out a sender
//! and applies the negotiated protocol and cookies. Unsent retries reuse the prepared
//! request without cloning its body.

mod dispatch;
mod prepare;
mod retry;
#[cfg(test)]
mod tests;

#[cfg(feature = "cookies")]
use std::sync::Arc;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::Response;
use netty::body::Incoming;
use tower::{BoxError, Service};

use self::{dispatch::Dispatch, prepare::Prepared, retry::Retry};
use super::{error, pool, proto};
#[cfg(feature = "cookies")]
use crate::cookie::CookieStore;
use crate::{
    Body,
    config::{ConnectConfig, RequestConfig},
    conn,
    dns::DynResolver,
    protocol::Protocol,
    reuse,
    rt::DynRuntime,
};

/// Client-wide settings assembled by [`ClientBuilder`](crate::ClientBuilder) to construct
/// the low-level [`Client`] service.
#[derive(Default)]
pub(super) struct Config {
    pub(super) protocol: Protocol,
    pub(super) config: ConnectConfig,
    pub(super) conn_config: conn::Config,
    pub(super) pool_config: pool::Config,
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

// ===== impl Client =====

impl Client {
    /// Builds the shared connector, pool, and HTTP request service.
    pub(super) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        Config {
            protocol,
            conn_config,
            pool_config,
            config,
            #[cfg(feature = "cookies")]
            cookie_store,
        }: Config,
    ) -> crate::Result<Self> {
        Ok(Self {
            pool: pool::Pool::new(
                conn::Connect::new(runtime.clone(), resolver, conn_config, &config)?,
                runtime.clone(),
                pool_config,
                proto::Builder::new(runtime, &config, true),
            ),
            protocol,
            config: RequestConfig::new(config),
            #[cfg(feature = "cookies")]
            cookie_store: RequestConfig::new(cookie_store),
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
