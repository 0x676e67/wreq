//! HTTP/1 handshake, request preparation, sender, and pooled connection lifecycle.
//!
//! [`Connection`] generates `Host` from the absolute URI before converting the
//! request target for a direct connection, forward proxy, or `CONNECT` tunnel.
//! HTTP/1 request-target forms are defined by RFC 9112 section 3.2:
//! <https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2>

use std::{
    sync::Arc,
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures_util::future::BoxFuture;
use http::{
    HeaderValue, Method, Request, Uri,
    header::{HOST, PROXY_AUTHORIZATION},
};
use http_body::Body;
use netty::{conn, http1::Http1Options};
use tokio::sync::oneshot;
use tower::{BoxError, Layer, Service};

use super::{Established, configure};
use crate::{
    client::error::{Error, ErrorKind},
    conn::Connected,
    rt::{DynRuntime, Timer as _},
};

/// Prepares and sends requests over one reusable HTTP/1 connection.
///
/// HTTP/1 permits one active checkout. Dispatch returns this sender only after
/// it becomes ready again; a busy sender is held by a readiness task.
pub struct Connection<B = crate::Body> {
    tx: conn::http1::SendRequest<B>,
    connected: Connected,
    set_host: bool,
    idle_at: Instant,
    runtime: DynRuntime,
}

/// Layers HTTP/1 handshaking over a transport-producing service.
///
/// The resulting service waits for the physical connector, performs the
/// handshake with its entry's builder, and returns a cacheable [`Connection`].
pub struct ConnectLayer<'a> {
    builder: &'a Arc<conn::http1::Builder>,
    options: Option<&'a Http1Options>,
    runtime: &'a DynRuntime,
    set_host: bool,
}

/// Connects a transport and performs an HTTP/1 handshake.
#[derive(Clone)]
pub struct Connect<S> {
    inner: S,
    builder: Arc<conn::http1::Builder>,
    set_host: bool,
    runtime: DynRuntime,
}

// ===== impl ConnectLayer =====

impl<'a> ConnectLayer<'a> {
    /// Borrows the builder and per-entry overrides until the service is assembled.
    #[must_use]
    pub fn new(
        runtime: &'a DynRuntime,
        builder: &'a Arc<conn::http1::Builder>,
        options: Option<&'a Http1Options>,
        set_host: bool,
    ) -> Self {
        Self {
            runtime,
            builder,
            options,
            set_host,
        }
    }
}

impl<S> Layer<S> for ConnectLayer<'_> {
    type Service = Connect<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Connect {
            inner,
            builder: configure(self.builder, self.options, conn::http1::Builder::options),
            runtime: self.runtime.clone(),
            set_host: self.set_host,
        }
    }
}

// ===== impl Connect =====

impl<S, Dst> Service<Dst> for Connect<S>
where
    S: Service<Dst, Response = Established, Error = BoxError, Future: Send + 'static>,
{
    type Response = Connection;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, target: Dst) -> Self::Future {
        let future = self.inner.call(target);
        let builder = self.builder.clone();
        let runtime = self.runtime.clone();
        let set_host = self.set_host;
        Box::pin(async move {
            let Established { io, connected, .. } = future.await?;
            let (mut tx, connection) = Arc::unwrap_or_clone(builder).handshake(io).await?;
            let (error_tx, error_rx) = oneshot::channel();
            runtime.execute(Box::pin(async move {
                if let Err(error) = connection.with_upgrades().await {
                    debug!("client connection error: {error:?}");
                    let _ = error_tx.send(error);
                }
            }));

            // Wait for the sender to become ready, preserving the driver's error if it closed.
            match tx.ready().await {
                Ok(()) => drop(error_rx),
                Err(error) if error.is_closed() => match error_rx.await {
                    Ok(connection_error) => return Err(connection_error.into()),
                    Err(_) => return Err(error.into()),
                },
                Err(error) => return Err(error.into()),
            }

            Ok(Connection {
                tx,
                connected,
                set_host,
                idle_at: runtime.now(),
                runtime,
            })
        })
    }
}

// ===== impl Connection =====

impl<B> Connection<B> {
    /// Returns metadata for the underlying transport.
    #[must_use]
    pub fn connected(&self) -> &Connected {
        &self.connected
    }

    /// Returns whether the protocol sender is immediately ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.tx.is_ready()
    }

    /// Records when the exclusive sender becomes idle.
    #[inline(always)]
    pub fn mark_idle(&mut self) {
        self.idle_at = self.runtime.now();
    }

    /// Returns whether the exclusive sender can safely re-enter the cache.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.connected().poisoned() && self.is_ready()
    }

    /// Returns whether the sender is healthy and within its idle timeout.
    #[must_use]
    pub fn is_reusable(&self, expiry: Option<(Instant, Duration)>) -> bool {
        self.is_open()
            && expiry
                .is_none_or(|(now, timeout)| now.saturating_duration_since(self.idle_at) <= timeout)
    }

    /// Polls the HTTP/1 sender until it can accept another request.
    #[inline(always)]
    pub fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        self.tx.poll_ready(cx).map_err(Error::closed)
    }

    /// Prepares the HTTP/1 wire headers and target, then dispatches `req` without boxing.
    pub(in crate::client) fn send_request(
        &mut self,
        mut req: Request<B>,
    ) -> Result<conn::ResponseFuture<B>, Error>
    where
        B: Body + Send + 'static,
    {
        // Host must be derived before the absolute URI becomes a wire target.
        if self.set_host
            && !req.headers().contains_key(HOST)
            && let Some(host) = generate_host_header(req.uri())
        {
            req.headers_mut().insert(HOST, host);
        }

        // Adjust the request URI based on the connection type and HTTP method.
        if req.method() == Method::CONNECT {
            authority_form(req.uri_mut())?;
        } else if self.connected.is_proxied() {
            if let Some(auth) = self.connected.proxy_auth() {
                req.headers_mut()
                    .entry(PROXY_AUTHORIZATION)
                    .or_insert_with(|| auth.clone());
            }
            if let Some(headers) = self.connected.proxy_headers() {
                crate::util::replace_headers(req.headers_mut(), headers.clone());
            }
        } else {
            origin_form(req.uri_mut())?;
        }

        Ok(self.tx.try_send_request(req))
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
    if let Some(path) = uri.path_and_query()
        && path != "/"
    {
        warn!("HTTP/1.1 CONNECT request stripping path: {:?}", path);
    }

    let Some(authority) = uri.authority() else {
        return Err(Error::from_kind(ErrorKind::UserAbsoluteUriRequired));
    };

    let mut parts = ::http::uri::Parts::default();
    parts.authority = Some(authority.clone());
    *uri = Uri::from_parts(parts).map_err(|error| Error::new(ErrorKind::SendRequest, error))?;
    Ok(())
}

/// Creates a `Host` value from the URI authority without an intermediate string.
fn generate_host_header(uri: &Uri) -> Option<HeaderValue> {
    let host = uri.host()?;
    let port = match (uri.port().map(|port| port.as_u16()), is_scheme_secure(uri)) {
        (Some(443), true) | (Some(80), false) => None,
        _ => uri.port(),
    };

    let value = if port.is_some() {
        let authority = uri.authority()?.as_str();
        authority
            .rsplit_once('@')
            .map_or(authority, |(_, host_and_port)| host_and_port)
    } else {
        host
    };

    HeaderValue::from_str(value).ok()
}

/// Returns whether the URI scheme uses a secure transport by default.
fn is_scheme_secure(uri: &Uri) -> bool {
    matches!(uri.scheme_str(), Some("https" | "wss"))
}
