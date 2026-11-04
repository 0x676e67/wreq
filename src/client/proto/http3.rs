//! HTTP/3 handshake, sender, and pooled connection lifecycle.

use std::{
    marker::PhantomData,
    sync::Arc,
    task::{self, Poll},
    time::{Duration, Instant},
};

use futures_util::{
    TryFutureExt,
    future::{BoxFuture, Either},
};
use http::{Request, Response};
use http_body::Body;
use netty::{body::Incoming, conn, rt::quic::Compat};
use tower::{BoxError, Service, ServiceExt};

use super::{ConnectionState, SendError, is_expired};
use crate::{
    client::pool::PoolTarget,
    conn::{Conn, Connected, request::ConnectRequest},
    rt::{RuntimeHandle, Timer as _},
};

/// Shared request sender for one HTTP/3 connection.
pub struct Connection<B> {
    tx: conn::http3::SendRequest<B>,
    state: Arc<ConnectionState>,
    conn_info: Connected,
    runtime: RuntimeHandle,
}

/// Establishes HTTP/3 connections for the pool's shared singleton.
pub struct Connect<C, B> {
    connector: C,
    runtime: RuntimeHandle,
    _body: PhantomData<fn(B)>,
}

impl<C, B> Connect<C, B> {
    pub fn new(connector: C, runtime: RuntimeHandle) -> Self {
        Self {
            connector,
            runtime,
            _body: PhantomData,
        }
    }
}

impl<C: Clone, B> Clone for Connect<C, B> {
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
            runtime: self.runtime.clone(),
            _body: PhantomData,
        }
    }
}

impl<C, B> Service<PoolTarget> for Connect<C, B>
where
    C: Service<ConnectRequest, Response = Conn, Error = BoxError> + Clone + Send + Sync + 'static,
    C::Future: Send + 'static,
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Connection<B>;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: PoolTarget) -> Self::Future {
        let connector = self.connector.clone();
        let runtime = self.runtime.clone();
        let builder = target
            .connection
            .req
            .config_override::<netty::http3::Http3Options>()
            .map_or_else(
                || target.connection.proto.http3.clone(),
                |options| {
                    target
                        .connection
                        .proto
                        .http3
                        .clone()
                        .options(options.clone())
                },
            );

        Box::pin(async move {
            let Conn {
                inner,
                connected: conn_info,
            } = connector.oneshot(target.connection.req).await?;
            let Either::Right((quic, endpoint)) = inner else {
                return Err("QUIC connection returned a stream".into());
            };
            let transport = Compat::new(http3_quic::Connection::new(quic));
            let (mut tx, driver) = builder.handshake::<_, B>(transport).await?;
            runtime.execute(Box::pin(async move {
                let _endpoint = endpoint;
                if let Err(_error) = driver.await {
                    debug!("client connection error: {_error}");
                }
            }));
            tx.ready().await?;
            Ok(Connection {
                tx,
                state: Arc::new(ConnectionState::new(runtime.now())),
                conn_info,
                runtime,
            })
        })
    }
}

impl<B> Clone for Connection<B> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            state: self.state.clone(),
            conn_info: self.conn_info.clone(),
            runtime: self.runtime.clone(),
        }
    }
}

impl<B> Connection<B> {
    pub fn conn_info(&self) -> &Connected {
        &self.conn_info
    }

    pub fn is_ready(&self) -> bool {
        self.tx.is_ready()
    }

    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Returns whether the peer enabled extended CONNECT, or `None` before its SETTINGS.
    pub fn extended_connect(&self) -> Option<bool> {
        self.tx.is_extended_connect_protocol_enabled()
    }

    pub fn begin_checkout(&self) {
        self.state.acquire();
    }

    pub fn finish_checkout(&self) {
        let _ = self.state.release(self.runtime.now());
    }

    pub fn is_reusable(&self, now: Instant, timeout: Option<Duration>) -> bool {
        !self.conn_info.poisoned()
            && !self.tx.is_closed()
            && (!self.state.is_idle() || !is_expired(self.state.idle_at(), now, timeout))
    }
}

impl<B> Service<Request<B>> for Connection<B>
where
    B: Body + Send + 'static,
{
    type Response = Response<Incoming>;
    type Error = SendError<B>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        let ready = self
            .tx
            .poll_ready(cx)
            .map_err(|error| SendError::Request(crate::client::error::Error::closed(error)));
        if matches!(ready, Poll::Ready(Err(_))) {
            self.conn_info.poison();
        }
        ready
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        Box::pin(
            self.tx
                .try_send_request(request)
                .map_err(SendError::protocol),
        )
    }
}
