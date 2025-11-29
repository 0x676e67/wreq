use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::{self, Either, Ready};
use http::{HeaderMap, HeaderValue, Request, Response, header::PROXY_AUTHORIZATION};
use tower::{Layer, Service};

use crate::{
    Error,
    client::layer::config::RequestDefaultHeaders,
    core::{
        client::options::RequestOptions,
        ext::{RequestConfig, RequestLayerOptions, RequestOrigHeaderMap},
    },
    ext::UriExt,
    header::OrigHeaderMap,
    proxy::Matcher as ProxyMatcher,
};

/// Configuration for the [`ConfigService`].
struct Config {
    https_only: bool,
    headers: HeaderMap,
    orig_headers: RequestConfig<RequestOrigHeaderMap>,
    default_headers: RequestConfig<RequestDefaultHeaders>,
    proxies: Arc<Vec<ProxyMatcher>>,
    proxies_maybe_http_auth: bool,
    proxies_maybe_http_custom_headers: bool,
}

/// Middleware layer to use [`ConfigService`].
pub struct ConfigServiceLayer {
    config: Arc<Config>,
}

/// Middleware service to use [`Config`].
#[derive(Clone)]
pub struct ConfigService<S> {
    inner: S,
    config: Arc<Config>,
}

// ===== impl ConfigServiceLayer =====

impl ConfigServiceLayer {
    /// Creates a new [`ConfigServiceLayer`].
    pub(super) fn new(
        https_only: bool,
        headers: HeaderMap,
        orig_headers: OrigHeaderMap,
        proxies: Arc<Vec<ProxyMatcher>>,
    ) -> Self {
        let org_headers = (!orig_headers.is_empty()).then_some(orig_headers);
        let proxies_maybe_http_auth = proxies.iter().any(ProxyMatcher::maybe_has_http_auth);
        let proxies_maybe_http_custom_headers = proxies
            .iter()
            .any(ProxyMatcher::maybe_has_http_custom_headers);

        ConfigServiceLayer {
            config: Arc::new(Config {
                https_only,
                headers,
                orig_headers: RequestConfig::new(org_headers),
                default_headers: RequestConfig::new(Some(true)),
                proxies,
                proxies_maybe_http_auth,
                proxies_maybe_http_custom_headers,
            }),
        }
    }
}

impl<S> Layer<S> for ConfigServiceLayer {
    type Service = ConfigService<S>;

    #[inline]
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

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let uri = req.uri().clone();

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
        self.config.orig_headers.store(req.extensions_mut());

        // determine the proxy matcher to use
        let (http_auth_header, http_custom_headers) =
            RequestConfig::<RequestLayerOptions>::get(req.extensions())
                .and_then(RequestOptions::proxy_matcher)
                .map(|proxy| http_non_tunnel(&uri, proxy))
                .or_else(|| {
                    // skip if no proxy could possibly have HTTP auth or custom headers
                    if !(self.config.proxies_maybe_http_auth
                        || self.config.proxies_maybe_http_custom_headers)
                    {
                        return None;
                    }

                    // check all proxies for HTTP auth or custom headers
                    self.config.proxies.iter().find_map(|proxy| {
                        match http_non_tunnel(&uri, proxy) {
                            (None, None) => None,
                            result => Some(result),
                        }
                    })
                })
                .unwrap_or_default();

        // insert proxy auth header if not already present
        if let Some(header) = http_auth_header {
            req.headers_mut()
                .entry(PROXY_AUTHORIZATION)
                .or_insert(header);
        }

        // insert proxy custom headers
        if let Some(headers) = http_custom_headers {
            crate::util::replace_headers(req.headers_mut(), headers);
        }

        Either::Left(self.inner.call(req))
    }
}

// helper to get proxy auth header and custom headers for non-tunnel HTTP requests
fn http_non_tunnel(
    uri: &http::Uri,
    proxy: &ProxyMatcher,
) -> (Option<HeaderValue>, Option<HeaderMap>) {
    let auth_header = proxy.http_non_tunnel_basic_auth(uri);
    let custom_headers = proxy.http_non_tunnel_custom_headers(uri);
    (auth_header, custom_headers)
}
