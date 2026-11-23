//! HTTP/3 connection service for the pool's shared singleton.

use std::{
    sync::Arc,
    task::{self, Poll},
};

use futures_util::future::BoxFuture;
use netty::{conn, http3::Http3Options, rt::quic::Compat};
use tower::{BoxError, Layer, Service};

use super::{
    configure,
    mux::{Connection, Sender},
};
use crate::{Body, conn::Conn, rt::DynRuntime};

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
pub struct Connect<S> {
    inner: S,
    builder: Arc<conn::http3::Builder<DynRuntime>>,
    runtime: DynRuntime,
}

// ===== impl ConnectLayer =====

impl<'a> ConnectLayer<'a> {
    /// Borrows the builder and per-entry overrides until the service is assembled.
    #[must_use]
    pub fn new(
        runtime: &'a DynRuntime,
        builder: &'a Arc<conn::http3::Builder<DynRuntime>>,
        options: Option<&'a Http3Options>,
    ) -> Self {
        Self {
            runtime,
            builder,
            options,
        }
    }
}

impl<S> Layer<S> for ConnectLayer<'_> {
    type Service = Connect<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Connect {
            inner,
            builder: configure(self.builder, self.options, conn::http3::Builder::options),
            runtime: self.runtime.clone(),
        }
    }
}

// ===== impl Connect =====

impl<S, Dst> Service<Dst> for Connect<S>
where
    S: Service<Dst, Response = Conn, Error = BoxError, Future: Send + 'static>,
{
    type Response = Connection;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, dst: Dst) -> Self::Future {
        let future = self.inner.call(dst);
        let builder = self.builder.clone();
        let runtime = self.runtime.clone();

        Box::pin(async move {
            let Conn {
                transport,
                connected,
            } = future.await?;

            // Convert the transport into a QUIC connection and endpoint.
            let (quic, endpoint) = transport.into_quic()?;
            let quic = Compat::new(http3_quic::Connection::new(quic));
            let (mut tx, connection) = Arc::unwrap_or_clone(builder)
                .handshake::<_, Body>(quic)
                .await?;

            // Spawn a task to drive the QUIC connection in the background.
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
