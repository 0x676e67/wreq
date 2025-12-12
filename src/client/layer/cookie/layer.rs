use std::{
    sync::Arc,
    task::{Context, Poll},
};

use http::{Request, Response, Uri, header::COOKIE};
use tower::{Layer, Service};

use super::future::ResponseFuture;
use crate::{
    client::{ext::RequestConfig, layer::config::RequestCookieStore},
    cookie::{CookieStore, Cookies},
};

/// Layer to apply [`CookieService`] middleware.
#[derive(Clone)]
pub struct CookieServiceLayer {
    store: RequestConfig<RequestCookieStore>,
}

impl CookieServiceLayer {
    /// Create a new [`CookieServiceLayer`].
    #[inline(always)]
    pub const fn new(store: Option<Arc<dyn CookieStore + 'static>>) -> Self {
        Self {
            store: RequestConfig::new(store),
        }
    }
}

impl<S> Layer<S> for CookieServiceLayer {
    type Service = CookieService<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        CookieService {
            inner,
            store: self.store.clone(),
        }
    }
}

/// Middleware to use [`CookieStore`].
#[derive(Clone)]
pub struct CookieService<S> {
    inner: S,
    store: RequestConfig<RequestCookieStore>,
}

impl<S> CookieService<S> {
    fn inject_cookies<B>(
        &self,
        req: &mut Request<B>,
        store: Arc<dyn CookieStore>,
    ) -> (Arc<dyn CookieStore>, Uri) {
        let uri = req.uri().clone();
        let headers = req.headers_mut();

        // Only inject cookies if request doesn't already have them
        if !headers.contains_key(COOKIE) {
            match store.cookies(&uri) {
                Cookies::Compressed(value) => {
                    headers.insert(COOKIE, value);
                }
                Cookies::Uncompressed(values) => {
                    for value in values {
                        headers.append(COOKIE, value);
                    }
                }
                Cookies::Empty => (),
            }
        }

        (store, uri)
    }
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for CookieService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        match self
            .store
            .fetch(req.extensions())
            .cloned()
            .map(|store| self.inject_cookies(&mut req, store))
        {
            Some((store, uri)) => ResponseFuture::Managed {
                future: self.inner.call(req),
                store,
                uri,
            },
            None => ResponseFuture::Direct {
                future: self.inner.call(req),
            },
        }
    }
}
