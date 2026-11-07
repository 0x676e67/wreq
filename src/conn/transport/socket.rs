//! Request-aware TCP and Unix socket dialing.

#[cfg(unix)]
use std::{io, path::Path};
use std::{
    sync::Arc,
    task::{Context, Poll},
};

#[cfg(unix)]
use futures_util::future::Either;
use futures_util::{TryFutureExt, future::MapErr};
use http::Uri;
use tower::{Service, ServiceExt, util::Oneshot};

#[cfg(unix)]
use super::UnixConnector;
use super::{BindOptions, ConnectError, TcpConnector};
#[cfg(unix)]
use crate::rt::DynRuntime;
use crate::{dns::DynResolver, error::BoxError, rt::BoxConnection};

#[cfg(unix)]
type SocketConnectorFuture = Either<
    MapErr<Oneshot<TcpConnector<DynResolver>, Uri>, fn(ConnectError) -> BoxError>,
    MapErr<Oneshot<UnixConnector, Uri>, fn(io::Error) -> BoxError>,
>;

#[cfg(not(unix))]
type SocketConnectorFuture =
    MapErr<Oneshot<TcpConnector<DynResolver>, Uri>, fn(ConnectError) -> BoxError>;

/// A physical socket target and the request's binding policy.
/// Secure connections temporarily disable Nagle during the handshake.
#[derive(Clone)]
pub struct SocketRequest {
    pub(crate) uri: Uri,
    #[cfg(unix)]
    pub(crate) unix: Option<Arc<Path>>,
    pub(crate) bind_options: Option<Arc<BindOptions>>,
    pub(crate) secure: bool,
}

/// Dials sockets through the client's configured transport and runtime.
#[derive(Clone)]
pub(crate) struct SocketConnector {
    #[cfg(unix)]
    runtime: DynRuntime,
    tcp: TcpConnector<DynResolver>,
}

impl SocketConnector {
    pub(crate) fn new(#[cfg(unix)] runtime: DynRuntime, tcp: TcpConnector<DynResolver>) -> Self {
        Self {
            #[cfg(unix)]
            runtime,
            tcp,
        }
    }
}

impl Service<SocketRequest> for SocketConnector {
    type Response = BoxConnection;
    type Error = BoxError;
    type Future = SocketConnectorFuture;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: SocketRequest) -> Self::Future {
        #[cfg(unix)]
        let mut req = req;
        #[cfg(unix)]
        if let Some(path) = req.unix.take() {
            let connecting = UnixConnector::new(path, self.runtime.clone())
                .oneshot(req.uri)
                .map_err(Into::into as fn(io::Error) -> BoxError);

            return Either::Right(connecting);
        }

        let mut tcp = self.tcp.clone();

        // Disable Nagle during TLS handshakes.
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
        if req.secure && !self.tcp.nodelay() {
            tcp = tcp.set_nodelay(true);
        }

        if let Some(bind_options) = &req.bind_options {
            tcp = tcp.set_bind_options(bind_options);
        }

        let connecting = tcp
            .oneshot(req.uri)
            .map_err(Into::into as fn(ConnectError) -> BoxError);

        #[cfg(unix)]
        let connecting = Either::Left(connecting);

        connecting
    }
}
