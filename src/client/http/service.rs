use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::{self, Either, Ready};
use http::{
    HeaderMap, Request, Response,
    header::{Entry, PROXY_AUTHORIZATION},
};
use tower::{Layer, Service};

use crate::{
    Error,
    client::layer::config::RequestDefaultHeaders,
    core::ext::{RequestConfig, RequestOrigHeaderMap},
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
        let uri = req.uri().clone();

        // check if the request URI scheme is valid.
        if (!uri.is_http() && !uri.is_https()) || (self.config.https_only && !uri.is_https()) {
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
            let headers = req.headers_mut();
            for (name, value) in &self.config.headers {
                match headers.entry(name) {
                    // If the header already exists, append the new value to it.
                    Entry::Occupied(mut entry) => {
                        entry.append(value.clone());
                    }
                    // If the header does not exist, insert it.
                    Entry::Vacant(entry) => {
                        entry.insert(value.clone());
                    }
                }
            }
        }

        // store the original headers in request extensions
        self.config.orig_headers.store(req.extensions_mut());

        // Skip if the destination is not plain HTTP.
        // For HTTPS, the proxy headers should be part of the CONNECT tunnel instead.
        if !uri.is_http() {
            return Either::Left(self.inner.call(req));
        }

        // Determine whether we need to apply proxy auth and/or custom headers.
        let need_auth = self.config.proxies_maybe_http_auth
            && !req.headers_mut().contains_key(PROXY_AUTHORIZATION);
        let need_custom_headers = self.config.proxies_maybe_http_custom_headers;

        // If no headers need to be applied, return early.
        if !need_auth && !need_custom_headers {
            return Either::Left(self.inner.call(req));
        }

        // flag to track if we've inserted the headers we need.
        let mut inserted_auth = false;
        let mut inserted_custom = false;

        for proxy in self.config.proxies.iter() {
            // Insert basic auth header from the first applicable proxy.
            if need_auth && !inserted_auth {
                if let Some(auth_header) = proxy.http_non_tunnel_basic_auth(req.uri()) {
                    req.headers_mut().insert(PROXY_AUTHORIZATION, auth_header);
                    inserted_auth = true;
                }
            }

            // Insert custom headers from the first applicable proxy.
            if need_custom_headers && !inserted_custom {
                if let Some(custom_headers) = proxy.http_non_tunnel_custom_headers(req.uri()) {
                    for (key, value) in custom_headers.iter() {
                        req.headers_mut().insert(key.clone(), value.clone());
                    }
                    inserted_custom = true;
                }
            }

            // Stop iterating if both kinds of headers have been inserted.
            if inserted_auth && inserted_custom {
                break;
            }
        }

        Either::Left(self.inner.call(req))
    }
}
