//! HTTP/3 connection service for the pool's shared singleton.

use std::{
    sync::Arc,
    task::{self, Poll},
};

use futures_util::future::BoxFuture;
use http::Request;
use netty::{conn, http3::Http3Options, rt::quic::Compat};
use tower::{BoxError, Layer, Service, ServiceExt};

use super::{
    configure,
    mux::{Connection, Sender},
};
use crate::{
    Body,
    client::pool::{Checkout, PoolTarget},
    config::connect::ConnectConfig,
    conn::Conn,
    rt::DynRuntime,
};

/// Layers HTTP/3 handshaking over a QUIC connector.
pub struct ConnectLayer<'a> {
    builder: &'a Arc<conn::http3::Builder<DynRuntime>>,
    options: Option<&'a Http3Options>,
    runtime: &'a DynRuntime,
}

/// Establishes HTTP/3 connections for the pool's shared singleton.
/// Handshakes use the entry's builder and do not wait for the peer, so, as for HTTP/2,
/// the connector's deadline is the only connect timeout.
#[derive(Clone)]
pub struct Connect<C> {
    connector: C,
    builder: Arc<conn::http3::Builder<DynRuntime>>,
    runtime: DynRuntime,
}

// ===== impl ConnectLayer =====

impl<'a> ConnectLayer<'a> {
    /// Borrows the builder and per-entry overrides until the service is assembled.
    #[must_use]
    pub fn new(
        builder: &'a Arc<conn::http3::Builder<DynRuntime>>,
        options: Option<&'a Http3Options>,
        runtime: &'a DynRuntime,
    ) -> Self {
        Self {
            builder,
            options,
            runtime,
        }
    }
}

impl<C> Layer<C> for ConnectLayer<'_> {
    type Service = Connect<C>;

    fn layer(&self, connector: C) -> Self::Service {
        Connect {
            connector,
            builder: configure(self.builder, self.options, conn::http3::Builder::options),
            runtime: self.runtime.clone(),
        }
    }
}

// ===== impl Connect =====

impl<C> Service<Checkout<PoolTarget>> for Connect<C>
where
    C: Service<Request<ConnectConfig>, Response = Conn, Error = BoxError, Future: Send + 'static>
        + Clone
        + Send
        + 'static,
{
    type Response = Connection;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline(always)]
    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, checkout: Checkout<PoolTarget>) -> Self::Future {
        let mut connector = self.connector.clone();
        let builder = self.builder.clone();
        let runtime = self.runtime.clone();

        Box::pin(async move {
            connector.ready().await?;
            let Conn {
                transport,
                connected,
            } = connector.call(checkout.target.into_request()).await?;
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
