use http::Request;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tower::Service;

use super::Body;
use crate::{
    connect::Connector,
    core::{body::Incoming, client::Client},
    error::{self, BoxError},
};

#[derive(Clone)]
pub struct ClientService {
    client: Client<Connector, Body>,
}

impl ClientService {
    #[inline(always)]
    pub fn new(client: Client<Connector, Body>) -> Self {
        Self { client }
    }
}

impl Service<Request<Body>> for ClientService {
    type Error = BoxError;
    type Response = http::Response<Incoming>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.client
            .poll_ready(cx)
            .map_err(error::request)
            .map_err(From::from)
    }

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
}
