//! [`Future`] types.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::Response;
use pin_project_lite::pin_project;

use super::CookieStore;

pin_project! {
    /// Response future for [`CookieManager`].
    pub struct ResponseFuture<F> {
        #[pin]
        pub(crate) future: F,
        pub(crate) cookie_store: Option<Arc<dyn CookieStore>>,
        pub(crate) url: Option<url::Url>,
    }
}

impl<F, ResBody, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let res = std::task::ready!(this.future.poll(cx)?);

        // If a cookie store is set, extract any `Set-Cookie` headers from the response
        // and store them for the URL. Use `peekable` to avoid unnecessary writes
        // when there are no cookies.
        if let Some(cookie_store) = this.cookie_store {
            if let Some(url) = this.url {
                let mut cookies = res
                    .headers()
                    .get_all(http::header::SET_COOKIE)
                    .iter()
                    .peekable();
                if cookies.peek().is_some() {
                    cookie_store.set_cookies(&mut cookies, url);
                }
            }
        }

        Poll::Ready(Ok(res))
    }
}
