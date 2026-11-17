//! [`Connect`] dispatches each connection request to the stream or QUIC service.

use std::{
    sync::Arc,
    task::{Context, Poll, ready},
};

#[cfg(feature = "http3")]
use futures_util::future::Either;
use http::Request;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Service, ServiceBuilder};

use super::{
    Config, Conn,
    dialer::Dialer,
    layer::verbose::{self, Verbose},
    stream,
};
#[cfg(feature = "http3")]
use super::{ConnectRequestExt, quic};
#[cfg(feature = "http3")]
use crate::protocol::Protocol;
use crate::{config::connect::ConnectConfig, dns::DynResolver, rt::DynRuntime};

/// Dispatches connection requests to the stream or QUIC transport service.
/// Clones share the state of both transport connection services.
#[derive(Clone)]
pub(crate) struct Connect {
    stream: Verbose<stream::Connect>,
    #[cfg(feature = "http3")]
    quic: quic::Connect,
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

// ===== impl Connect =====

impl Connect {
    /// Builds the available transports with the client's proxy rules and bindings.
    pub(super) fn new(
        runtime: &DynRuntime,
        resolver: DynResolver,
        Config {
            tcp,
            tls,
            proxies,
            happy_eyeballs_timeout,
            verbose,
        }: Config,
        config: &ConnectConfig,
    ) -> crate::Result<Self> {
        let tcp_nodelay = tcp.nodelay;
        let proxies = Arc::new(proxies);
        let dialer = Dialer::new(
            runtime.clone(),
            resolver.clone(),
            tcp,
            config.clone(),
            happy_eyeballs_timeout,
        );

        #[cfg(feature = "http3")]
        let quic = quic::Connect::new(
            runtime.clone(),
            resolver.clone(),
            proxies.clone(),
            happy_eyeballs_timeout,
            tls.clone().quic(config)?,
            #[cfg(feature = "socks")]
            dialer.clone(),
        )?;

        let stream = stream::Connect::new(
            dialer,
            proxies,
            tls.stream(config)?,
            tcp_nodelay,
            #[cfg(feature = "socks")]
            resolver,
        );

        Ok(Self {
            #[cfg(feature = "http3")]
            quic,
            stream: ServiceBuilder::new()
                .option_layer(verbose::layer(verbose))
                .service(stream),
        })
    }
}

impl Service<Request<ConnectConfig>> for Connect {
    type Response = Conn;
    type Error = BoxError;
    type Future = cfg_select! {
        feature = "http3" => {
            Either<
                <Verbose<stream::Connect> as Service<Request<ConnectConfig>>>::Future,
                <quic::Connect as Service<Request<ConnectConfig>>>::Future,
            >
        }
        _ => { <Verbose<stream::Connect> as Service<Request<ConnectConfig>>>::Future }
    };

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.stream.poll_ready(cx))?;
        #[cfg(feature = "http3")]
        ready!(self.quic.poll_ready(cx))?;
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<ConnectConfig>) -> Self::Future {
        cfg_select! {
            feature = "http3" => {
                if request.protocol() == Protocol::Http3 {
                    Either::Right(self.quic.call(request))
                } else {
                    Either::Left(self.stream.call(request))
                }
            }
            _ => self.stream.call(request),
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
