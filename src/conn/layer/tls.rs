//! Finishes TCP and Unix streams for HTTP/1 and HTTP/2.
//!
//! The [`proxy`](super::proxy) stage opens the route and handles proxy handshakes. [`TlsLayer`]
//! completes target TLS where needed, restores TCP settings, and attaches metadata
//! before returning [`Conn`].

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures_util::future::BoxFuture;
#[cfg(feature = "http3")]
use futures_util::future::Either;
use pin_project_lite::pin_project;
use tokio_btls::SslStream;
use tower::{BoxError, Layer, Service};

use super::proxy::ProxyConnection;
use crate::{
    conn::{
        AsyncConnWithInfo, Conn, Connection, TlsConn, TlsInfoFactory, request::ConnectRequest,
        verbose::Verbose,
    },
    error::ProxyConnect,
    proxy::matcher::Intercept,
    rt::BoxConnection,
    tls::connector::{EstablishedConn, MaybeHttpsStream},
};

/// Finishes target TLS, restores socket policy, and attaches connection metadata.
#[derive(Clone, Copy)]
pub(crate) struct TlsLayer {
    verbose: bool,
    nodelay: bool,
    tls_info: bool,
}

/// Turns a proxy connection service into the stream service used by the pool.
#[derive(Clone)]
pub(crate) struct TlsConnector<S> {
    inner: S,
    config: TlsLayer,
}

pin_project! {
    /// Drives proxy setup and the target TLS handshake, then attaches connection metadata.
    /// Dropping it drops the active stage; the state machine adds no future allocation.
    pub(crate) struct TlsConnecting<F> {
        #[pin]
        state: State<F>,
        config: TlsLayer,
    }
}

pin_project! {
    #[project = StateProj]
    enum State<F> {
        Connecting { #[pin] future: F },
        Raw {
            #[pin]
            future: BoxFuture<'static, Result<MaybeHttpsStream<BoxConnection>, BoxError>>,
        },
        Tunnel {
            #[pin]
            future: BoxFuture<'static, Result<MaybeHttpsStream<MaybeHttpsStream<BoxConnection>>, BoxError>>,
            tcp: bool,
        },
        Done,
    }
}

// ===== impl TlsLayer =====

impl TlsLayer {
    pub(crate) fn new(verbose: bool, nodelay: bool, tls_info: bool) -> Self {
        Self {
            verbose,
            nodelay,
            tls_info,
        }
    }

    fn connection<IO>(&self, io: MaybeHttpsStream<IO>, proxy: Option<Intercept>) -> Conn
    where
        IO: AsyncConnWithInfo,
        TlsConn<IO>: Connection,
        SslStream<IO>: TlsInfoFactory,
    {
        let stream = match io {
            MaybeHttpsStream::Http(stream) => Verbose(self.verbose).wrap(stream),
            MaybeHttpsStream::Https(stream) => Verbose(self.verbose).wrap(TlsConn { stream }),
        };
        let mut connected = stream.connected();
        if let Some(proxy) = proxy {
            connected = connected.proxy(proxy);
        }
        if self.tls_info
            && let Some(tls_info) = stream.tls_info()
        {
            connected = connected.extra(tls_info);
        }
        Conn {
            inner: cfg_select! {
                feature = "http3" => Either::Left(stream),
                _ => stream,
            },
            connected,
        }
    }
}

impl<S> Layer<S> for TlsLayer {
    type Service = TlsConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            config: *self,
        }
    }
}

// ===== impl TlsConnector =====

impl<S> Service<ConnectRequest> for TlsConnector<S>
where
    S: Service<ConnectRequest, Response = ProxyConnection, Error = BoxError>,
{
    type Response = Conn;
    type Error = BoxError;
    type Future = TlsConnecting<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: ConnectRequest) -> Self::Future {
        TlsConnecting {
            state: State::Connecting {
                future: self.inner.call(req),
            },
            config: self.config,
        }
    }
}

// ===== impl TlsConnecting =====

impl<F> Future for TlsConnecting<F>
where
    F: Future<Output = Result<ProxyConnection, BoxError>>,
{
    type Output = Result<Conn, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        loop {
            match this.state.as_mut().project() {
                StateProj::Connecting { future } => {
                    let connection = ready!(future.poll(cx));
                    this.state.set(State::Done);
                    match connection? {
                        ProxyConnection::Raw { io, req, mut tls } => {
                            this.state.set(State::Raw {
                                future: tls.call(EstablishedConn::new(io, req)),
                            });
                        }
                        ProxyConnection::Tunnel {
                            io,
                            req,
                            mut tls,
                            tcp,
                        } => {
                            this.state.set(State::Tunnel {
                                future: tls.call(EstablishedConn::new(io, req)),
                                tcp,
                            });
                        }
                        ProxyConnection::Forward { io, proxy } => {
                            if !this.config.nodelay && matches!(io, MaybeHttpsStream::Https(_)) {
                                io.as_ref()
                                    .set_nodelay(false)
                                    .map_err(|err| ProxyConnect::Source(err.into()))?;
                            }
                            return Poll::Ready(Ok(this.config.connection(io, proxy)));
                        }
                    }
                }
                StateProj::Raw { future } => {
                    let io = ready!(future.poll(cx));
                    this.state.set(State::Done);
                    let io = io?;
                    if !this.config.nodelay && matches!(io, MaybeHttpsStream::Https(_)) {
                        io.as_ref().set_nodelay(false)?;
                    }
                    return Poll::Ready(Ok(this.config.connection(io, None)));
                }
                StateProj::Tunnel { future, tcp } => {
                    let io = ready!(future.poll(cx));
                    let tcp = *tcp;
                    this.state.set(State::Done);
                    let io = io?;
                    if tcp && !this.config.nodelay && matches!(io, MaybeHttpsStream::Https(_)) {
                        io.as_ref().as_ref().set_nodelay(false)?;
                    }
                    return Poll::Ready(Ok(this.config.connection(io, None)));
                }
                StateProj::Done => return Poll::Pending,
            }
        }
    }
}
