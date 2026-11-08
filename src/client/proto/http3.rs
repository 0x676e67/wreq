//! HTTP/3 connection service for the pool's shared singleton.

use std::{
    pin::pin,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use futures_util::future::{self, BoxFuture, Either};
use netty::{conn, rt::quic::Compat};
use tower::{BoxError, Service, ServiceExt};

use super::mux::{Connection, Sender};
use crate::{
    Body,
    client::pool::{PoolTarget, TransportConnector},
    conn::Conn,
    error::TimedOut,
    rt::{DynRuntime, Timer as _},
};

/// Establishes HTTP/3 connections for the pool's shared singleton.
/// Handshakes use the entry's builder; one connect timeout covers the QUIC connection
/// and the HTTP/3 handshake.
#[derive(Clone)]
pub struct Connect<C> {
    connector: C,
    builder: Arc<conn::http3::Builder<DynRuntime>>,
    runtime: DynRuntime,
    timeout: Option<Duration>,
}

// ===== impl Connect =====

impl<C> Connect<C> {
    /// Creates the HTTP/3 connection service; `timeout` bounds the QUIC connection and handshake.
    pub fn new(
        connector: C,
        builder: Arc<conn::http3::Builder<DynRuntime>>,
        runtime: DynRuntime,
        timeout: Option<Duration>,
    ) -> Self {
        Self {
            connector,
            builder,
            runtime,
            timeout,
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
        let timeout = self.timeout;

        Box::pin(async move {
            // As for the connector's own timeout, readiness waits such as concurrency admission
            // come before the deadline.
            connector.ready().await?;

            // A peer that withholds stream credit stalls the handshake after the QUIC connection
            // is up, so the deadline also covers opening the control and QPACK streams.
            let handshake = async {
                let Conn {
                    transport,
                    connected,
                } = connector.call(target.req).await?;
                let (quic, endpoint) = transport.into_quic()?;
                let quic = Compat::new(http3_quic::Connection::new(quic));
                let (tx, connection) = Arc::unwrap_or_clone(builder)
                    .handshake::<_, Body>(quic)
                    .await?;
                Ok::<_, BoxError>((tx, connection, endpoint, connected))
            };

            let (mut tx, connection, endpoint, connected) =
                match timeout.map(|timeout| runtime.sleep(timeout)) {
                    Some(deadline) => match future::select(pin!(handshake), deadline).await {
                        Either::Left((result, _)) => result?,
                        Either::Right(((), _)) => return Err(Box::new(TimedOut) as _),
                    },
                    None => handshake.await?,
                };

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
