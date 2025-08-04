use std::{
    sync::Arc,
    task::{Context, Poll},
};

use http::{Request, Response, header::COOKIE};
use tower::{Layer, Service};

use super::future::ResponseFuture;
use crate::cookie::CookieStore;

/// Layer to apply [`CookieManager`] middleware.
#[derive(Clone)]
pub struct CookieManagerLayer {
    cookie_store: Option<Arc<dyn CookieStore>>,
}

impl CookieManagerLayer {
    /// Create a new cookie manager layer.
    pub const fn new(cookie_store: Option<Arc<dyn CookieStore + 'static>>) -> Self {
        Self { cookie_store }
    }
}

impl<S> Layer<S> for CookieManagerLayer {
    type Service = CookieManager<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CookieManager {
            inner,
            cookie_store: self.cookie_store.clone(),
        }
    }
}

/// Middleware to use [`CookieStore`].
#[derive(Clone)]
pub struct CookieManager<S> {
    inner: S,
    cookie_store: Option<Arc<dyn CookieStore>>,
}

impl<S> CookieManager<S> {
    fn inject_cookies_if_needed<B>(
        &self,
        req: &mut Request<B>,
        cookie_store: &Arc<dyn CookieStore>,
    ) -> Option<url::Url> {
        // // Skip if request already has cookies
        if req.headers().get(COOKIE).is_some() {
            return None;
        }

        // Parse URL first - we need it for both injection and response processing
        let url = url::Url::parse(&req.uri().to_string()).ok()?;

        // Only inject cookies if request doesn't already have them
        if let Some(cookies) = cookie_store.cookies(&url) {
            let headers = req.headers_mut();
            for header in cookies {
                headers.append(COOKIE, header);
            }
        }

        Some(url)
    }
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for CookieManager<S>
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

        // Try to inject cookies and get URL for response processing
        match self.inject_cookies_if_needed(&mut req, cookie_store) {
            Some(url) => ResponseFuture::Managed {
                future: self.inner.call(req),
                cookie_store: cookie_store.clone(),
                url,
            },
            None => ResponseFuture::Direct {
                future: self.inner.call(req),
            },
        }
    }
}
