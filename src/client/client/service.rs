use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::Request;
use tower::Service;

use super::Body;
use crate::{
    OriginalHeaders,
    connect::Connector,
    core::{
        body::Incoming,
        client::Client,
        ext::{RequestConfig, RequestOriginalHeaders},
    },
    error::{BoxError, Error},
};

#[derive(Clone)]
pub struct ClientService {
    client: Client<Connector, Body>,
    original_headers: Arc<RequestConfig<RequestOriginalHeaders>>,
}

impl ClientService {
    pub fn new(client: Client<Connector, Body>, original_headers: Option<OriginalHeaders>) -> Self {
        Self {
            client,
            original_headers: Arc::new(RequestConfig::new(original_headers)),
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
        let clone = self.client.clone();
        let mut inner = std::mem::replace(&mut self.client, clone);
        self.original_headers.replace_to(req.extensions_mut());
        Box::pin(async move {
            inner
                .call(req)
                .await
                .map_err(Error::request)
                .map_err(From::from)
        })
    }
}
