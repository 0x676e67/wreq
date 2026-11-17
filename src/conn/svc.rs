//! [`Connect`] selects a route and sends the attempt to the stream or QUIC service.

use std::{
    sync::Arc,
    task::{Context, Poll, ready},
};

use futures_util::future::{self, Either, Ready};
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{BoxError, Service, ServiceBuilder};

use super::{
    Config, Conn, ConnectAttempt, ConnectRequestExt,
    dialer::Dialer,
    layer::verbose::{self, Verbose},
    stream,
};
#[cfg(feature = "http3")]
use super::{dialer::SocketBindings, quic};
use crate::{
    config::connect::{Cached, ConnectConfig},
    dns::DynResolver,
    ext::UriExt,
    protocol::TransportKind,
    proxy::Matcher,
    rt::DynRuntime,
};

type StreamFuture = <Verbose<stream::Connect> as Service<ConnectAttempt<stream::Route>>>::Future;
#[cfg(feature = "http3")]
type RoutedFuture =
    Either<StreamFuture, <quic::Connect as Service<ConnectAttempt<quic::Route>>>::Future>;
#[cfg(not(feature = "http3"))]
type RoutedFuture = StreamFuture;

/// Selects a route using the client's proxy rules and the request's transport.
/// Clones share the proxy rules and the state of both connection services.
#[derive(Clone)]
pub(crate) struct Connect {
    proxies: Arc<Vec<Matcher>>,
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
    /// Builds the available transports with the client's proxy rules.
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
        let dialer = Dialer::new(
            runtime.clone(),
            resolver.clone(),
            tcp,
            happy_eyeballs_timeout,
        );

        #[cfg(feature = "http3")]
        let quic = quic::Connect::new(
            runtime.clone(),
            resolver.clone(),
            SocketBindings::from_config(config.into()),
            happy_eyeballs_timeout,
            tls.clone().quic(config)?,
            #[cfg(feature = "socks")]
            dialer.clone(),
        )?;

        let stream = stream::Connect::new(
            dialer,
            tls.stream(config)?,
            tcp_nodelay,
            #[cfg(feature = "socks")]
            resolver,
        );

        Ok(Self {
            proxies: Arc::new(proxies),
            #[cfg(feature = "http3")]
            quic,
            stream: ServiceBuilder::new()
                .option_layer(verbose::layer(verbose))
                .service(stream),
        })
    }
}

impl Service<ConnectAttempt> for Connect {
    type Response = Conn;
    type Error = BoxError;
    type Future = Either<RoutedFuture, Ready<Result<Conn, BoxError>>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.stream.poll_ready(cx))?;
        #[cfg(feature = "http3")]
        ready!(self.quic.poll_ready(cx))?;
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        ConnectAttempt {
            request, deadline, ..
        }: ConnectAttempt,
    ) -> Self::Future {
        let uri = request.uri();
        // A request proxy takes precedence only when it intercepts this origin.
        let proxy = request
            .connect_config()
            .get_ref::<Cached<Matcher>>()
            .map(Cached::get)
            .and_then(|proxy| proxy.intercept(uri))
            .or_else(|| self.proxies.iter().find_map(|proxy| proxy.intercept(uri)));
        let transport = cfg_select! {
            feature = "http3" => request.body().protocol().transport(),
            _ => TransportKind::Stream,
        };
        let future = match transport {
            TransportKind::Stream => stream::Route::new(proxy, uri.is_https())
                .map(|route| {
                    let future = self.stream.call(ConnectAttempt {
                        request,
                        deadline,
                        route,
                    });
                    cfg_select! {
                        feature = "http3" => Either::Left(future),
                        _ => future,
                    }
                })
                .map_err(Into::into),
            #[cfg(feature = "http3")]
            TransportKind::Quic => quic::Route::new(proxy).map(|route| {
                Either::Right(self.quic.call(ConnectAttempt {
                    request,
                    deadline,
                    route,
                }))
            }),
        };
        match future {
            Ok(future) => Either::Left(future),
            Err(error) => Either::Right(future::err(error)),
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
