//! Middleware to use [`CookieStore`].

mod future;
mod layer;

use crate::cookie::CookieStore;
use http::{Request, Response, header::COOKIE};
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tower_service::Service;

pub use self::{future::ResponseFuture, layer::CookieManagerLayer};

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

    #[inline]
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
