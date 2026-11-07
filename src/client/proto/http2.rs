//! HTTP/2 handshake layer for pooled connections.

use std::{
    future::Future,
    task::{self, Poll},
};

use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Layer, Service};

use super::{
    Established,
    mux::{Connection, Sender},
};
use crate::rt::DynRuntime;

/// Layers HTTP/2 handshaking over an established-transport service.
///
/// Fixed HTTP/2 wraps the connector directly; automatic mode supplies a
/// transport selected by negotiation. Both return a cloneable sender for the
/// pool's singleton service.
#[derive(Clone)]
pub struct ConnectLayer {
    runtime: DynRuntime,
}

/// Performs an HTTP/2 handshake for a transport-producing service.
///
/// The inner service either connects directly or yields a negotiated transport.
/// This service consumes it once, starts the protocol driver, and returns the
/// shared sender stored by the singleton pool.
#[derive(Clone)]
pub struct Connect<S> {
    service: S,
    runtime: DynRuntime,
}

// ===== impl ConnectLayer =====

impl ConnectLayer {
    /// Creates an HTTP/2 handshake layer for pooled connections.
    pub fn new(runtime: DynRuntime) -> Self {
        Self { runtime }
    }
}

impl<S> Layer<S> for ConnectLayer {
    type Service = Connect<S>;

    fn layer(&self, service: S) -> Self::Service {
        Connect {
            service,
            runtime: self.runtime.clone(),
        }
    }
}

// ===== impl Connect =====

impl<S, T, Dst> Service<Dst> for Connect<S>
where
    S: Service<Dst, Response = Established<T>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Response = Connection;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, target: Dst) -> Self::Future {
        let future = self.service.call(target);
        let runtime = self.runtime.clone();
        Box::pin(handshake(future, runtime))
    }
}

/// Awaits a transport and returns a handshaken HTTP/2 sender.
/// Starts the connection driver before waiting for sender readiness.
async fn handshake<F, T>(established: F, runtime: DynRuntime) -> Result<Connection, BoxError>
where
    F: Future<Output = Result<Established<T>, BoxError>>,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Established {
        io,
        connected,
        config,
        ..
    } = established.await?;

    let builder = config.proto.http2_for(&config.req);
    drop(config);

    let (mut tx, connection) = builder.handshake(io).await?;
    runtime.execute(Box::pin(async move {
        if let Err(_error) = connection.await {
            debug!("client connection error: {_error}");
        }
    }));
    tx.ready().await?;

    Ok(Connection::new(Sender::Http2(tx), connected, runtime))
}
