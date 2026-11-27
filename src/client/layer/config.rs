use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::{self, Either, Ready};
use http::{HeaderMap, Request, Response};
use tower::{Layer, Service};

use crate::{
    Error,
    config::{RequestConfig, impl_request_config_value},
    ext::UriExt,
    header::OrigHeaderMap,
};

/// Marker key for the per-request toggle controlling whether client default headers apply.
///
/// Stored in [`http::Extensions`] via [`RequestConfig<DefaultHeaders>`] with value type `bool`.
#[derive(Clone, Copy)]
pub(crate) struct DefaultHeaders;

/// Shared configuration applied by [`ConfigService`] to every outgoing request.
///
/// Holds the `https_only` flag, client default headers, and [`RequestConfig`] defaults for
/// original header preservation and default-header injection.
struct Config {
    https_only: bool,
    headers: HeaderMap,
    orig_headers: RequestConfig<OrigHeaderMap>,
    default_headers: RequestConfig<DefaultHeaders>,
}

/// Tower [`Layer`] that wraps an HTTP service in [`ConfigService`].
///
/// Shares the immutable [`Config`] across every wrapped service instance.
pub struct ConfigServiceLayer {
    config: Arc<Config>,
}

/// Middleware service that validates URI schemes and applies client default headers.
///
/// Also forwards any configured [`OrigHeaderMap`] into request extensions for wire-level
/// header casing and ordering preservation.
#[derive(Clone)]
pub struct ConfigService<S> {
    inner: S,
    config: Arc<Config>,
}

// ===== impl DefaultHeaders =====

impl_request_config_value!(DefaultHeaders, bool);

// ===== impl ConfigServiceLayer =====

impl ConfigServiceLayer {
    /// Creates a new [`ConfigServiceLayer`].
    #[must_use]
    pub fn new(https_only: bool, headers: HeaderMap, orig_headers: OrigHeaderMap) -> Self {
        let orig_headers = (!orig_headers.is_empty()).then_some(orig_headers);
        ConfigServiceLayer {
            config: Arc::new(Config {
                https_only,
                headers,
                orig_headers: RequestConfig::new(orig_headers),
                default_headers: RequestConfig::new(true),
            }),
        }
    }
}

impl<S> Layer<S> for ConfigServiceLayer {
    type Service = ConfigService<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        ConfigService {
            inner,
            config: self.config.clone(),
        }
    }
}

// ===== impl ConfigService =====

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for ConfigService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Error: From<Error>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let uri = req.uri();

        // check if the request URI scheme is valid.
        if !(uri.is_http() || uri.is_https()) || (self.config.https_only && !uri.is_https()) {
            return Either::Right(future::err(Error::uri_bad_scheme(uri.clone()).into()));
        }

        // check if the request ignores the default headers.
        if self
            .config
            .default_headers
            .fetch(req.extensions())
            .copied()
            .unwrap_or_default()
        {
            // insert default headers in the request headers
            // without overwriting already appended headers.
            let mut dest = self.config.headers.clone();
            crate::util::replace_headers(&mut dest, std::mem::take(req.headers_mut()));
            std::mem::swap(req.headers_mut(), &mut dest);
        }

        // store the original headers in request extensions
        if let Some(orig_headers) = self.config.orig_headers.take(req.extensions_mut()) {
            netty::ext::on_preserve_header(&mut req, orig_headers);
        }

        Either::Left(self.inner.call(req))
    }
}
