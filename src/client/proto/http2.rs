//! HTTP/2 handshake layer for pooled connections.

use std::{
    sync::Arc,
    task::{self, Poll},
};

use futures_util::future::BoxFuture;
use netty::{conn, http2::Http2Options};
use tower::{BoxError, Layer, Service};

use super::{
    Established, configure,
    mux::{Connection, Sender},
};
use crate::rt::DynRuntime;

/// Layers HTTP/2 handshaking over an established-transport service.
///
/// Fixed HTTP/2 wraps the connector directly; automatic mode supplies a
/// transport selected by negotiation. Both handshake with their entry's builder
/// and return a cloneable sender for the pool's singleton service.
pub struct ConnectLayer<'a> {
    builder: &'a Arc<conn::http2::Builder<DynRuntime>>,
    options: Option<&'a Http2Options>,
    runtime: &'a DynRuntime,
}

/// Performs an HTTP/2 handshake for a transport-producing service.
///
/// The inner service either connects directly or yields a negotiated transport.
/// This service consumes it once, starts the protocol driver, and returns the
/// shared sender stored by the singleton pool.
#[derive(Clone)]
pub struct Connect<S> {
    service: S,
    builder: Arc<conn::http2::Builder<DynRuntime>>,
    runtime: DynRuntime,
}

// ===== impl ConnectLayer =====

impl<'a> ConnectLayer<'a> {
    /// Borrows the builder and per-entry overrides until the service is assembled.
    #[must_use]
    pub fn new(
        builder: &'a Arc<conn::http2::Builder<DynRuntime>>,
        options: Option<&'a Http2Options>,
        runtime: &'a DynRuntime,
    ) -> Self {
        Self {
            builder,
            options,
            runtime,
        }
    }
}

impl<S> Layer<S> for ConnectLayer<'_> {
    type Service = Connect<S>;

    fn layer(&self, service: S) -> Self::Service {
        Connect {
            service,
            builder: configure(self.builder, self.options, conn::http2::Builder::options),
            runtime: self.runtime.clone(),
        }
    }
}

// ===== impl Connect =====

impl<S, Dst> Service<Dst> for Connect<S>
where
    S: Service<Dst, Response = Established, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Connection;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, target: Dst) -> Self::Future {
        let future = self.service.call(target);
        let builder = self.builder.clone();
        let runtime = self.runtime.clone();
        Box::pin(async move {
            // Await the underlying service to establish the transport.
            let Established { io, connected, .. } = future.await?;
            let (mut tx, connection) = Arc::unwrap_or_clone(builder).handshake(io).await?;

            // Spawn a task to drive the HTTP/2 connection in the background.
            runtime.execute(Box::pin(async move {
                if let Err(_error) = connection.await {
                    debug!("client connection error: {_error}");
                }
            }));
            tx.ready().await?;

            Ok(Connection::new(Sender::Http2(tx), connected, runtime))
        })
    }
}
