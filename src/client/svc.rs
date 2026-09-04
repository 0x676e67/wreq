//! Tower services used by the low-level client request path.
//!
//! [`configure::Configure`] consumes request-local transport options,
//! [`retry::RetryUnsent`] retries only requests returned before encoding, and
//! [`dispatch::Dispatch`] performs one checkout and dispatch attempt.
//! Connection-bound HTTP/1 preparation is composed from [`SetHost`] and
//! [`Http1RequestTarget`].
//!
//! HTTP/1 request-target forms are defined by RFC 9112 section 3.2:
//! <https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2>

use std::task::{Context, Poll};

use futures_util::future::{self, Either, Ready};
use http::{
    HeaderValue, Method, Request, Uri,
    header::{HOST, PROXY_AUTHORIZATION},
};
use tower::Service;

use super::error::{Error, ErrorKind};
use crate::{
    conn::{Connected, descriptor::ConnectionDescriptor},
    rt::Executor,
};

pub(super) mod configure;
pub(super) mod dispatch;
pub(super) mod retry;

/// A request with the connection and protocol settings needed for dispatch.
///
/// The request body stays owned by this value until protocol dispatch begins.
/// This lets a canceled pool checkout or an encoding-before-send failure return
/// the same request to [`retry::RetryUnsent`] without cloning its body.
pub struct ConfiguredRequest<B> {
    request: Request<B>,
    descriptor: ConnectionDescriptor,
    h1_builder: wreq_proto::conn::http1::Builder,
    h2_builder: wreq_proto::conn::http2::Builder<Executor>,
}

/// Ensures an HTTP request has a `Host` field before protocol encoding.
///
/// The middleware can be disabled for callers that manage `Host` themselves.
/// It reads the absolute request URI before an inner target middleware converts
/// that URI to HTTP/1 origin-form or authority-form.
#[derive(Clone)]
pub struct SetHost<S> {
    inner: S,
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
    inner: S,
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
    if let Some(path) = uri.path_and_query()
        && path != "/"
    {
        warn!("HTTP/1.1 CONNECT request stripping path: {:?}", path);
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
