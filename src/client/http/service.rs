use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::{self, Either, MapErr, Ready, TryFutureExt};
use http::{HeaderMap, Request, Response, header::PROXY_AUTHORIZATION, uri::Scheme};
use tower::Service;

use super::{Body, connect::Connector};
use crate::{
    client::layer::config::RequestSkipDefaultHeaders,
    core::{
        client::{Error, HttpClient, ResponseFuture, body::Incoming},
        ext::{RequestConfig, RequestOrigHeaderMap},
    },
    error::BoxError,
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
    skip_default_headers: RequestConfig<RequestSkipDefaultHeaders>,
    https_only: bool,
    proxies: Arc<Vec<ProxyMatcher>>,
    proxies_maybe_http_auth: bool,
    proxies_maybe_http_custom_headers: bool,
}

impl ClientService {
    /// Creates a new [`ClientService`] with the provided HTTP client and configuration.
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
                skip_default_headers: RequestConfig::default(),
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
        if req.uri().scheme() != Some(&Scheme::HTTP) {
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
        let scheme = req.uri().scheme();

        // Validate scheme (http/https), enforce https if required
        if (scheme != Some(&Scheme::HTTP) && scheme != Some(&Scheme::HTTPS))
            || (self.config.https_only && scheme != Some(&Scheme::HTTPS))
        {
            return Either::Right(future::err(crate::Error::url_bad_scheme2().into()));
        }

        // Optionally insert default headers
        let skip = self
            .config
            .skip_default_headers
            .fetch(req.extensions())
            .copied()
            == Some(true);

        if !skip {
            let headers = req.headers_mut();
            for name in self.config.headers.keys() {
                if !headers.contains_key(name) {
                    for value in self.config.headers.get_all(name) {
                        headers.append(name, value.clone());
                    }
                }
            }
        }

        // Apply original headers and proxy headers
        self.config.orig_headers.store(req.extensions_mut());
        self.ensure_proxy_headers(&mut req);

        Either::Left(self.client.call(req).map_err(From::from))
    }
}
