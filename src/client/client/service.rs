use http::Request;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tower::Service;

use super::Body;
#[cfg(feature = "cookies")]
use crate::cookie;
use crate::{
    connect::Connector,
    core::{body::Incoming, client::Client},
    error::{self, BoxError},
};

#[derive(Clone)]
pub struct ClientService {
    #[cfg(feature = "cookies")]
    cookie_store: Option<std::sync::Arc<dyn cookie::CookieStore>>,
    client: Client<Connector, Body>,
}

impl ClientService {
    pub fn new(
        client: Client<Connector, Body>,
        #[cfg(feature = "cookies")] cookie_store: Option<
            std::sync::Arc<dyn cookie::CookieStore + 'static>,
        >,
    ) -> Self {
        Self {
            #[cfg(feature = "cookies")]
            cookie_store,
            client,
        }
    }
}

impl Service<Request<Body>> for ClientService {
    type Error = BoxError;
    type Response = http::Response<Incoming>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.client.poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(r) => Poll::Ready(r.map_err(error::request).map_err(From::from)),
        }
    }

    #[cfg(not(feature = "cookies"))]
    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let clone = self.client.clone();
        let mut inner = std::mem::replace(&mut self.client, clone);
        Box::pin(async move {
            inner
                .call(req)
                .await
                .map_err(error::request)
                .map_err(From::from)
        })
    }

    #[cfg(feature = "cookies")]
    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let clone = self.client.clone();
        let mut inner = std::mem::replace(&mut self.client, clone);
        let url = url::Url::parse(&req.uri().to_string()).expect("invalid URL");

        if let Some(cookie_store) = self.cookie_store.as_ref() {
            if req.headers().get(crate::header::COOKIE).is_none() {
                let headers = req.headers_mut();
                crate::util::add_cookie_header(cookie_store, &url, headers);
            }
        }

        let cookie_store = self.cookie_store.clone();
        Box::pin(async move {
            let res = inner
                .call(req)
                .await
                .map_err(error::request)
                .map_err(From::from);

            if let Some(ref cookie_store) = cookie_store {
                if let Ok(res) = &res {
                    let mut cookies =
                        cookie::extract_response_cookie_headers(res.headers()).peekable();
                    if cookies.peek().is_some() {
                        cookie_store.set_cookies(&mut cookies, &url);
                    }
                }
            }

            res
        })
    }
}
