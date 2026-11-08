//! HTTP/3 connection service for the pool's shared singleton.

use std::{
    sync::Arc,
    task::{self, Poll},
};

use futures_util::future::BoxFuture;
use netty::{conn, rt::quic::Compat};
use tower::{BoxError, Service, ServiceExt};

use super::mux::{Connection, Sender};
use crate::{
    Body,
    client::pool::{PoolTarget, TransportConnector},
    conn::Conn,
    rt::DynRuntime,
};

/// Establishes HTTP/3 connections for the pool's shared singleton.
/// Handshakes use the entry's builder and do not wait for the peer, so, as for HTTP/2,
/// the connector's deadline is the only connect timeout.
#[derive(Clone)]
pub struct Connect<C> {
    connector: C,
    builder: Arc<conn::http3::Builder<DynRuntime>>,
    runtime: DynRuntime,
}

// ===== impl Connect =====

impl<C> Connect<C> {
    /// Creates the HTTP/3 connection service.
    pub fn new(
        connector: C,
        builder: Arc<conn::http3::Builder<DynRuntime>>,
        runtime: DynRuntime,
    ) -> Self {
        Self {
            connector,
            builder,
            runtime,
        }
    }
}

impl<C> Service<PoolTarget> for Connect<C>
where
    C: TransportConnector,
{
    type Response = Connection;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: PoolTarget) -> Self::Future {
        let mut connector = self.connector.clone();
        let builder = self.builder.clone();
        let runtime = self.runtime.clone();

        Box::pin(async move {
            connector.ready().await?;
            let Conn {
                transport,
                connected,
            } = connector.call(target.req).await?;
            let (quic, endpoint) = transport.into_quic()?;
            let quic = Compat::new(http3_quic::Connection::new(quic));
            let (mut tx, connection) = Arc::unwrap_or_clone(builder)
                .handshake::<_, Body>(quic)
                .await?;
            runtime.execute(Box::pin(async move {
                let _endpoint = endpoint;
                if let Err(_error) = connection.await {
                    debug!("client connection error: {_error}");
                }
            }));
            tx.ready().await?;

            Ok(Connection::new(Sender::Http3(tx), connected, runtime))
        })
    }
}
