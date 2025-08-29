//! [`Future`] types.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use http::{Response, Uri};
use pin_project_lite::pin_project;

use crate::cookie::CookieStore;

pin_project! {
    /// Response future for [`CookieService`].
    #[project=ResponseFutureProj]
    pub enum ResponseFuture<F> {
        Managed {
            #[pin]
            future: F,
            cookie_store: Arc<dyn CookieStore>,
            uri: Uri,
        },
        Direct {
            #[pin]
            future: F,
        },
    }
}

impl<F, ResBody, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            ResponseFutureProj::Managed {
                future,
                cookie_store,
                uri,
            } => {
                let res = ready!(future.poll(cx)?);
                let mut cookies = res
                    .headers()
                    .get_all(http::header::SET_COOKIE)
                    .iter()
                    .peekable();
                if cookies.peek().is_some() {
                    cookie_store.set_cookies(&mut cookies, uri);
                }

                Poll::Ready(Ok(res))
            }
            ResponseFutureProj::Direct { mut future } => future.as_mut().poll(cx),
        }
    }
}
