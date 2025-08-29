use std::{
    sync::Arc,
    task::{Context, Poll},
};

use http::{Request, Response, Uri, header::COOKIE};
use tower::{Layer, Service};

use super::future::ResponseFuture;
use crate::cookie::CookieStore;

/// Layer to apply [`CookieService`] middleware.
#[derive(Clone)]
pub struct CookieServiceLayer {
    cookie_store: Option<Arc<dyn CookieStore>>,
}

impl CookieServiceLayer {
    /// Create a new [`CookieServiceLayer`].
    #[inline(always)]
    pub const fn new(cookie_store: Option<Arc<dyn CookieStore + 'static>>) -> Self {
        Self { cookie_store }
    }
}

impl<S> Layer<S> for CookieServiceLayer {
    type Service = CookieService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CookieService {
            inner,
            cookie_store: self.cookie_store.clone(),
        }
    }
}

/// Middleware to use [`CookieStore`].
#[derive(Clone)]
pub struct CookieService<S> {
    inner: S,
    cookie_store: Option<Arc<dyn CookieStore>>,
}

impl<S> CookieService<S> {
    fn inject_cookies_if_needed<B>(
        &self,
        req: &mut Request<B>,
        cookie_store: &Arc<dyn CookieStore>,
    ) -> Option<Uri> {
        let uri = req.uri().clone();

        // // Skip if request already has cookies
        if req.headers().get(COOKIE).is_some() {
            return Some(uri);
        }

        // Only inject cookies if request doesn't already have them
        let headers = req.headers_mut();
        for header in cookie_store.cookies(&uri) {
            headers.append(COOKIE, header);
        }

        Some(uri)
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
        // Check if cookie store is configured
        let Some(cookie_store) = &self.cookie_store else {
            return ResponseFuture::Direct {
                future: self.inner.call(req),
            };
        };

        // Try to inject cookies and get URI for response processing
        match self.inject_cookies_if_needed(&mut req, cookie_store) {
            Some(uri) => ResponseFuture::Managed {
                future: self.inner.call(req),
                cookie_store: cookie_store.clone(),
                uri,
            },
            None => ResponseFuture::Direct {
                future: self.inner.call(req),
            },
        }
    }
}
