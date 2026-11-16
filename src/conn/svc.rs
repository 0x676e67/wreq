//! The connector's terminal service: the stream and QUIC paths behind [`TransportConnector`],
//! which selects each request's route and dispatches it down the path its protocol runs over, and
//! the [`Transport`] a path returns.

use std::{
    sync::Arc,
    task::{Context, Poll, ready},
};

use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Service, ServiceBuilder};
#[cfg(feature = "http3")]
use {super::quic::QuicConnector, crate::protocol::TransportKind, futures_util::future::Either};

use super::{
    Conn,
    dialer::Dialer,
    layer::verbose::{self, Verbose},
    request::ConnectAttempt,
    route::Route,
    stream::StreamConnector,
};
use crate::{config::connect::ConnectConfig, proxy::Matcher, tls};

/// Connects every transport behind one service. Each request resolves its route from the client's
/// proxy rules and goes to the stream or QUIC path its protocol runs over; how a path is
/// composed stays private. Clones share each path's state and proxy rules.
#[derive(Clone)]
pub(crate) struct TransportConnector {
    proxies: Arc<Vec<Matcher>>,
    stream: Verbose<StreamConnector>,
    #[cfg(feature = "http3")]
    quic: QuicConnector,
}

/// Transport carried by a [`Conn`]: a byte stream for HTTP/1 and HTTP/2, or QUIC for HTTP/3.
/// A QUIC endpoint remains owned until it can move into the HTTP/3 driver.
pub(crate) enum Transport {
    /// A TCP or Unix stream after any proxy handshake and TLS.
    Stream(Box<dyn Io>),
    /// A QUIC connection and the endpoint that drives it.
    #[cfg(feature = "http3")]
    Quic {
        connection: ::quic::Connection,
        endpoint: ::quic::Endpoint,
    },
}

/// The byte stream HTTP/1 and HTTP/2 run over: the dialed socket beneath any TLS, proxy tunnel
/// or I/O tracing. Socket controls stay with [`rt::Connection`](crate::rt::Connection), and
/// addresses are read into [`Connected`](super::Connected) before the stream is boxed.
pub(crate) trait Io: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

impl<T> Io for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

// ===== impl TransportConnector =====

impl TransportConnector {
    /// Compiles client TLS and composes both paths over `dialer` with the client's proxy rules.
    /// QUIC endpoints remain lazy until a connection future is polled.
    pub(crate) fn new(
        dialer: Dialer,
        tls: tls::Config,
        proxies: Vec<Matcher>,
        verbose: bool,
        config: &ConnectConfig,
    ) -> crate::Result<Self> {
        Ok(Self {
            proxies: Arc::new(proxies),
            #[cfg(feature = "http3")]
            quic: QuicConnector::new(dialer.clone(), tls.clone().quic(config)?)?,
            stream: ServiceBuilder::new()
                .option_layer(verbose::layer(verbose))
                .service(StreamConnector::new(dialer, tls.stream(config)?)),
        })
    }
}

impl Service<ConnectAttempt> for TransportConnector {
    type Response = Conn;
    type Error = BoxError;
    #[cfg(feature = "http3")]
    type Future = Either<
        <Verbose<StreamConnector> as Service<(ConnectAttempt, Route)>>::Future,
        <QuicConnector as Service<(ConnectAttempt, Route)>>::Future,
    >;
    #[cfg(not(feature = "http3"))]
    type Future = <Verbose<StreamConnector> as Service<(ConnectAttempt, Route)>>::Future;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.stream.poll_ready(cx))?;
        #[cfg(feature = "http3")]
        ready!(self.quic.poll_ready(cx))?;
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, attempt: ConnectAttempt) -> Self::Future {
        let route = Route::select(attempt.request(), &self.proxies);
        cfg_select! {
            feature = "http3" => match attempt.request().protocol().transport() {
                TransportKind::Stream => Either::Left(self.stream.call((attempt, route))),
                TransportKind::Quic => Either::Right(self.quic.call((attempt, route))),
            },
            _ => self.stream.call((attempt, route)),
        }
    }
}

// ===== impl Transport =====

impl Transport {
    /// Takes the byte stream for an HTTP/1 or HTTP/2 handshake.
    /// Fails only if a connector layer returned a QUIC connection for a stream protocol.
    pub(crate) fn into_stream(self) -> Result<Box<dyn Io>, BoxError> {
        match self {
            Self::Stream(io) => Ok(io),
            #[cfg(feature = "http3")]
            Self::Quic { .. } => Err("stream connection returned QUIC".into()),
        }
    }

    /// Takes the QUIC connection and its endpoint for an HTTP/3 handshake.
    /// Fails only if a connector layer returned a stream for HTTP/3.
    #[cfg(feature = "http3")]
    pub(crate) fn into_quic(self) -> Result<(::quic::Connection, ::quic::Endpoint), BoxError> {
        match self {
            Self::Quic {
                connection,
                endpoint,
            } => Ok((connection, endpoint)),
            Self::Stream(_) => Err("QUIC connection returned a stream".into()),
        }
    }
}
