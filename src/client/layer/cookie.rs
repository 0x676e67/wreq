//! Middleware to use Cookie.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use http::{Request, Response, Uri, header::COOKIE};
use pin_project_lite::pin_project;
use tower::{Layer, Service};

use crate::{
    config::RequestConfig,
    cookie::{CookieStore, Cookies},
};

pin_project! {
    /// Response future for [`CookieService`].
    #[project = ResponseFutureProj]
    pub enum ResponseFuture<Fut> {
        Managed {
            #[pin]
            fut: Fut,
            uri: Uri,
            store: Arc<dyn CookieStore>,
        },
        Plain {
            #[pin]
            fut: Fut,
        },
    }
}

/// Layer to apply [`CookieService`] middleware.
#[derive(Clone)]
pub struct CookieServiceLayer {
    store: RequestConfig<Arc<dyn CookieStore>>,
}

/// Middleware to use [`CookieStore`].
#[derive(Clone)]
pub struct CookieService<S> {
    inner: S,
    store: RequestConfig<Arc<dyn CookieStore>>,
}

// ===== impl ResponseFuture =====

impl<F, ResBody, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            ResponseFutureProj::Managed { fut, uri, store } => {
                let res = ready!(fut.poll(cx)?);
                let mut cookies = res
                    .headers()
                    .get_all(http::header::SET_COOKIE)
                    .iter()
                    .peekable();
                if cookies.peek().is_some() {
                    store.set_cookies(&mut cookies, uri);
                }

                Poll::Ready(Ok(res))
            }
            ResponseFutureProj::Plain { fut: mut future } => future.as_mut().poll(cx),
        }
    }
}

// ===== impl CookieServiceLayer =====

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

// ===== impl CookieService =====

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
                uri,
                store,
                fut: self.inner.call(req),
            },
            None => ResponseFuture::Plain {
                fut: self.inner.call(req),
            },
        }
    }
}
