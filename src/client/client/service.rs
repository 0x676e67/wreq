use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::{HeaderMap, Request, Uri, header::PROXY_AUTHORIZATION, uri::Scheme};
use tower::Service;

use super::Body;
use crate::{
    OriginalHeaders,
    config::RequestSkipDefaultHeaders,
    connect::Connector,
    core::{
        body::Incoming,
        client::Client,
        ext::{RequestConfig, RequestOriginalHeaders},
    },
    error::{BoxError, Error},
    proxy::Matcher as ProxyMatcher,
};

#[derive(Clone)]
pub struct ClientService {
    client: Client<Connector, Body>,
    inner: Arc<ClientConfig>,
}

struct ClientConfig {
    default_headers: HeaderMap,
    skip_default_headers: RequestConfig<RequestSkipDefaultHeaders>,
    original_headers: RequestConfig<RequestOriginalHeaders>,
    proxies: Arc<Vec<ProxyMatcher>>,
    proxies_maybe_http_auth: bool,
    proxies_maybe_http_custom_headers: bool,
}

impl ClientService {
    pub fn new(
        client: Client<Connector, Body>,
        default_headers: HeaderMap,
        original_headers: Option<OriginalHeaders>,
        proxies: Arc<Vec<ProxyMatcher>>,
        proxies_maybe_http_auth: bool,
        proxies_maybe_http_custom_headers: bool,
    ) -> Self {
        Self {
            client,
            inner: Arc::new(ClientConfig {
                default_headers,
                skip_default_headers: RequestConfig::default(),
                original_headers: RequestConfig::new(original_headers),
                proxies,
                proxies_maybe_http_auth,
                proxies_maybe_http_custom_headers,
            }),
        }
    }

    fn apply_proxy_headers(&self, dst: Uri, headers: &mut HeaderMap) {
        // Skip if the destination is not plain HTTP.
        // For HTTPS, the proxy headers should be part of the CONNECT tunnel instead.
        if dst.scheme() != Some(&Scheme::HTTP) {
            return;
        }

        // Determine whether we need to apply proxy auth and/or custom headers.
        let need_auth =
            self.inner.proxies_maybe_http_auth && !headers.contains_key(PROXY_AUTHORIZATION);
        let need_custom_headers = self.inner.proxies_maybe_http_custom_headers;

        // If no headers need to be applied, return early.
        if !need_auth && !need_custom_headers {
            return;
        }

        let mut inserted_auth = false;
        let mut inserted_custom = false;

        for proxy in self.inner.proxies.iter() {
            // Insert basic auth header from the first applicable proxy.
            if need_auth && !inserted_auth {
                if let Some(auth_header) = proxy.http_non_tunnel_basic_auth(&dst) {
                    headers.insert(PROXY_AUTHORIZATION, auth_header);
                    inserted_auth = true;
                }
            }

            // Insert custom headers from the first applicable proxy.
            if need_custom_headers && !inserted_custom {
                if let Some(custom_headers) = proxy.http_non_tunnel_custom_headers(&dst) {
                    for (key, value) in custom_headers.iter() {
                        headers.insert(key.clone(), value.clone());
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
    type Response = http::Response<Incoming>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.client
            .poll_ready(cx)
            .map_err(Error::request)
            .map_err(From::from)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // Only skip setting default headers if skip_default_headers is explicitly Some(true).
        let skip = self
            .inner
            .skip_default_headers
            .fetch(req.extensions())
            .copied()
            == Some(true);

        if !skip {
            let headers = req.headers_mut();
            // Insert default headers if they are not already present in the request.
            for name in self.inner.default_headers.keys() {
                if !headers.contains_key(name) {
                    for value in self.inner.default_headers.get_all(name) {
                        headers.append(name, value.clone());
                    }
                }
            }
        }

        let clone = self.client.clone();
        let mut inner = std::mem::replace(&mut self.client, clone);

        // Apply proxy headers if the request is routed through a proxy.
        self.apply_proxy_headers(req.uri().clone(), req.headers_mut());

        // Apply original headers if they are set in the request extensions.
        self.inner.original_headers.replace_to(req.extensions_mut());

        Box::pin(async move {
            inner
                .call(req)
                .await
                .map_err(Error::request)
                .map_err(From::from)
        })
    }
}
