//! The connector's terminal service: the stream and QUIC paths behind [`TransportConnector`],
//! which sends each request down the path its protocol runs over, and the [`Transport`] a path
//! returns.

use std::{
    sync::Arc,
    task::{Context, Poll, ready},
    time::Instant,
};

use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Service, ServiceBuilder};
#[cfg(feature = "http3")]
use {super::quic::QuicRouter, crate::protocol::TransportKind, futures_util::future::Either};

use super::{
    Conn,
    dialer::Dialer,
    layer::{
        tls::{Tls, TlsLayer},
        verbose::{self, Verbose},
    },
    request::ConnectRequest,
    stream::StreamRouter,
};
use crate::{config::connect::ConfigSet, proxy::Matcher, tls};

/// The stream path: its routes, then target TLS and optional I/O tracing.
type StreamConnector = Verbose<Tls<StreamRouter>>;

/// Connects every transport behind one service. Each request goes to the stream or QUIC path
/// its protocol runs over; how a path is composed stays private. Clones share each path's
/// state.
#[derive(Clone)]
pub(crate) struct TransportConnector {
    stream: StreamConnector,
    #[cfg(feature = "http3")]
    quic: QuicRouter,
}

/// What [`TransportConnector`] connects: a request and the instant its connect timeout expires.
/// The deadline layer builds it once per call, so a proxy dial beneath stops at that instant
/// itself and its route reports the timeout as a proxy failure.
pub(crate) struct TransportRequest {
    pub(super) request: ConnectRequest,
    pub(super) deadline: Option<Instant>,
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
        config_set: &ConfigSet,
    ) -> crate::Result<Self> {
        let proxies = Arc::new(proxies);

        #[cfg(feature = "http3")]
        let quic = QuicRouter::new(
            dialer.clone(),
            tls.clone().quic(config_set)?,
            proxies.clone(),
        )?;
        let stream = ServiceBuilder::new()
            .option_layer(verbose::layer(verbose))
            .layer(TlsLayer::new(tls.stream(config_set)?))
            .service(StreamRouter::new(dialer, proxies));

        Ok(Self {
            stream,
            #[cfg(feature = "http3")]
            quic,
        })
    }
}

impl Service<TransportRequest> for TransportConnector {
    type Response = Conn;
    type Error = BoxError;
    #[cfg(feature = "http3")]
    type Future = Either<
        <StreamConnector as Service<TransportRequest>>::Future,
        <QuicRouter as Service<TransportRequest>>::Future,
    >;
    #[cfg(not(feature = "http3"))]
    type Future = <StreamConnector as Service<TransportRequest>>::Future;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.stream.poll_ready(cx))?;
        #[cfg(feature = "http3")]
        ready!(self.quic.poll_ready(cx))?;
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: TransportRequest) -> Self::Future {
        cfg_select! {
            feature = "http3" => match req.request.resolved_protocol().transport() {
                TransportKind::Stream => Either::Left(self.stream.call(req)),
                TransportKind::Quic => Either::Right(self.quic.call(req)),
            },
            _ => self.stream.call(req),
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
