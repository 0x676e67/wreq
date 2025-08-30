use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::{self, Either, MapErr, Ready, TryFutureExt};
use http::{
    HeaderMap, Request, Response,
    header::{Entry, PROXY_AUTHORIZATION},
};
use tower::Service;

use super::{Body, connect::Connector};
use crate::{
    client::layer::config::RequestDefaultHeaders,
    core::{
        client::{Error, HttpClient, ResponseFuture, body::Incoming},
        ext::{RequestConfig, RequestOrigHeaderMap},
    },
    error::BoxError,
    ext::UriExt,
    header::OrigHeaderMap,
    proxy::Matcher as ProxyMatcher,
};

/// A Tower service HTTP client.
#[derive(Clone)]
pub struct ClientService {
    client: HttpClient<Connector, Body>,
    config: Arc<Config>,
}

/// Configuration for the [`ClientService`].
struct Config {
    headers: HeaderMap,
    orig_headers: RequestConfig<RequestOrigHeaderMap>,
    default_headers: RequestConfig<RequestDefaultHeaders>,
    https_only: bool,
    proxies: Arc<Vec<ProxyMatcher>>,
    proxies_maybe_http_auth: bool,
    proxies_maybe_http_custom_headers: bool,
}

impl ClientService {
    /// Creates a new [`ClientService`].
    pub(super) fn new(
        client: HttpClient<Connector, Body>,
        headers: HeaderMap,
        orig_headers: OrigHeaderMap,
        https_only: bool,
        proxies: Arc<Vec<ProxyMatcher>>,
    ) -> Self {
        let proxies_maybe_http_auth = proxies.iter().any(ProxyMatcher::maybe_has_http_auth);
        let proxies_maybe_http_custom_headers = proxies
            .iter()
            .any(ProxyMatcher::maybe_has_http_custom_headers);
        let org_headers = (!orig_headers.is_empty()).then_some(orig_headers);

        ClientService {
            client,
            config: Arc::new(Config {
                headers,
                orig_headers: RequestConfig::new(org_headers),
                default_headers: RequestConfig::new(Some(true)),
                https_only,
                proxies,
                proxies_maybe_http_auth,
                proxies_maybe_http_custom_headers,
            }),
        }
    }

    #[inline]
    fn ensure_proxy_headers(&self, req: &mut Request<Body>) {
        // Skip if the destination is not plain HTTP.
        // For HTTPS, the proxy headers should be part of the CONNECT tunnel instead.
        if !req.uri().is_http() {
            return;
        }

        // Determine whether we need to apply proxy auth and/or custom headers.
        let need_auth = self.config.proxies_maybe_http_auth
            && !req.headers_mut().contains_key(PROXY_AUTHORIZATION);
        let need_custom_headers = self.config.proxies_maybe_http_custom_headers;

        // If no headers need to be applied, return early.
        if !need_auth && !need_custom_headers {
            return;
        }

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
    }
}

impl Service<Request<Body>> for ClientService {
    type Error = BoxError;

    type Response = Response<Incoming>;

    type Future = Either<
        MapErr<ResponseFuture, fn(Error) -> Self::Error>,
        Ready<Result<Self::Response, Self::Error>>,
    >;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.client.poll_ready(cx).map_err(From::from)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let uri = req.uri();

        // check if the request URI scheme is valid.
        if (!uri.is_http() && !uri.is_https()) || (self.config.https_only && !uri.is_https()) {
            let err = BoxError::from(crate::Error::uri_bad_scheme(uri.clone()));
            return Either::Right(future::err(err));
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
        // set proxy headers if needed
        self.ensure_proxy_headers(&mut req);

        Either::Left(self.client.call(req).map_err(From::from))
    }
}
