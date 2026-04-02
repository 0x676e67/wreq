pub(crate) mod connect;
mod dns;
pub(crate) mod pool;

use bytes::Bytes;
use http::{Request, Response};
use std::future::{self, Future};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tower::{BoxError, Service};

use self::connect::H3Connector;
use self::pool::{Key, Pool, PoolClient};
use crate::client::body::Body;

#[derive(Clone)]
pub(crate) struct H3Client {
    pool: Pool,
    connector: H3Connector,
}

impl H3Client {
    pub(crate) fn new(connector: H3Connector, pool_timeout: Option<Duration>) -> Self {
        H3Client {
            pool: Pool::new(pool_timeout),
            connector,
        }
    }

    async fn get_pooled_client(&mut self, key: Key) -> Result<PoolClient, BoxError> {
        if let Some(client) = self.pool.try_pool(&key) {
            trace!("getting client from pool with key {key:?}");
            return Ok(client);
        }

        trace!("did not find connection {key:?} in pool so connecting...");

        let dest = pool::domain_as_uri(key.clone());

        let lock = match self.pool.connecting(&key) {
            pool::Connecting::InProgress(waiter) => {
                trace!("connecting to {key:?} is already in progress, subscribing...");

                match waiter.receive().await {
                    Some(client) => return Ok(client),
                    None => return Err("failed to establish connection for HTTP/3 request".into()),
                }
            }
            pool::Connecting::Acquired(lock) => lock,
        };
        trace!("connecting to {key:?}...");
        let (driver, tx) = self.connector.connect(dest).await?;
        trace!("saving new pooled connection to {key:?}");
        Ok(self.pool.new_connection(lock, driver, tx))
    }

    async fn send_request(
        mut self,
        key: Key,
        req: Request<Body>,
    ) -> Result<Response<pool::Incoming>, BoxError> {
        let mut pooled = self.get_pooled_client(key).await?;
        let pseudo_order = self.connector.pseudo_header_order();
        pooled.send_request(req, pseudo_order).await
    }

    pub(crate) fn request(&self, mut req: Request<Body>) -> H3ResponseFuture {
        let pool_key = match pool::extract_domain(req.uri_mut()) {
            Ok(s) => s,
            Err(e) => {
                return H3ResponseFuture {
                    inner: Box::pin(future::ready(Err(e))),
                }
            }
        };
        H3ResponseFuture {
            inner: Box::pin(self.clone().send_request(pool_key, req)),
        }
    }
}

impl Service<Request<Body>> for H3Client {
    type Response = Response<pool::Incoming>;
    type Error = BoxError;
    type Future = H3ResponseFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        self.request(req)
    }
}

pub(crate) struct H3ResponseFuture {
    inner: Pin<Box<dyn Future<Output = Result<Response<pool::Incoming>, BoxError>> + Send>>,
}

impl Future for H3ResponseFuture {
    type Output = Result<Response<pool::Incoming>, BoxError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}
