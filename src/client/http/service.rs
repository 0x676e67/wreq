use std::{
    sync::Arc,
    task::{Context, Poll},
};

use http::{HeaderMap, Request, Response, header::PROXY_AUTHORIZATION, uri::Scheme};
use tower::Service;

use super::{Body, future::CorePending};
use crate::{
    client::layer::config::RequestSkipDefaultHeaders,
    connect::Connector,
    core::{
        body::Incoming,
        client::HttpClient,
        ext::{RequestConfig, RequestOriginalHeaders},
    },
    error::{BoxError, Error},
    into_url::IntoUrlSealed,
    proxy::Matcher as ProxyMatcher,
};

#[derive(Clone)]
pub struct ClientService {
    pub(super) client: HttpClient<Connector, Body>,
    pub(super) config: Arc<ClientConfig>,
}

pub(super) struct ClientConfig {
    pub(super) default_headers: HeaderMap,
    pub(super) skip_default_headers: RequestConfig<RequestSkipDefaultHeaders>,
    pub(super) original_headers: RequestConfig<RequestOriginalHeaders>,
    pub(super) https_only: bool,
    pub(super) proxies: Arc<Vec<ProxyMatcher>>,
    pub(super) proxies_maybe_http_auth: bool,
    pub(super) proxies_maybe_http_custom_headers: bool,
}

impl ClientService {
    #[inline]
    fn apply_proxy_headers(&self, req: &mut Request<Body>) {
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
    type Future = CorePending;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.client.poll_ready(cx).map_err(From::from)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let scheme = req.uri().scheme();

        // Check for invalid schemes
        if (scheme != Some(&Scheme::HTTP) && scheme != Some(&Scheme::HTTPS))
            || (self.config.https_only && scheme != Some(&Scheme::HTTPS))
        {
            let error = match IntoUrlSealed::into_url(req.uri().to_string()) {
                Ok(url) => Error::url_bad_scheme(url),
                Err(err) => Error::builder(err),
            };

            return CorePending::Error { error: Some(error) };
        }

        // Only skip setting default headers if skip_default_headers is explicitly Some(true).
        let skip = self
            .config
            .skip_default_headers
            .fetch(req.extensions())
            .copied()
            == Some(true);

        if !skip {
            let headers = req.headers_mut();
            // Insert default headers if they are not already present in the request.
            for name in self.config.default_headers.keys() {
                if !headers.contains_key(name) {
                    for value in self.config.default_headers.get_all(name) {
                        headers.append(name, value.clone());
                    }
                }
            }
        }

        // Apply original headers if they are set in the request extensions.
        self.config.original_headers.store(req.extensions_mut());

        // Apply proxy headers if the request is routed through a proxy.
        self.apply_proxy_headers(&mut req);

        CorePending::Request {
            fut: self.client.call(req),
        }
    }
}
