use std::{
    sync::Arc,
    task::{Context, Poll},
};

use http::{Request, Response, header::COOKIE};
use tower::Layer;
use tower_service::Service;

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
        // Try to extract the request URL.
        let mut url = None;

        // If a cookie store is present, inject cookies for this URL if not already set.
        if let Some(ref cookie_store) = self.cookie_store {
            if req.headers().get(COOKIE).is_none() {
                url = url::Url::parse(&req.uri().to_string()).ok();

                if let Some(ref url) = url {
                    let headers = req.headers_mut();
                    if let Some(cookie_headers) = cookie_store.cookies(url) {
                        for header in cookie_headers {
                            headers.append(COOKIE, header);
                        }
                    }
                }
            }
        }

        ResponseFuture {
            future: self.inner.call(req),
            cookie_store: self.cookie_store.clone(),
            url,
        }
    }
}
