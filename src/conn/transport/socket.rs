//! Request-aware TCP and Unix socket dialing.

#[cfg(unix)]
use std::path::Path;
use std::{
    sync::Arc,
    task::{Context, Poll},
};

#[cfg(unix)]
use futures_util::TryFutureExt;
use futures_util::future::{BoxFuture, Either, ErrInto};
use http::Uri;
use tower::Service;

use super::{BindOptions, TcpConnector};
#[cfg(unix)]
use crate::rt::DynRuntime;
use crate::{
    error::BoxError,
    rt::{BoxConnection, Connecting},
};

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

/// Dials TCP sockets, or Unix sockets through the runtime, for every route.
/// The one leaf dialer beneath stream proxies and SOCKS5 UDP control connections.
#[derive(Clone)]
pub(crate) struct SocketConnector {
    #[cfg(unix)]
    runtime: DynRuntime,
    tcp: TcpConnector,
}

impl SocketConnector {
    pub(crate) fn new(#[cfg(unix)] runtime: DynRuntime, tcp: TcpConnector) -> Self {
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
    // A Unix socket keeps the runtime's own boxed future.
    type Future =
        Either<BoxFuture<'static, Result<BoxConnection, BoxError>>, ErrInto<Connecting, BoxError>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: SocketRequest) -> Self::Future {
        #[cfg(unix)]
        if let Some(path) = req.unix {
            return Either::Right(self.runtime.connect_unix(path).err_into());
        }

        // Disable Nagle during TLS handshakes.
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
        let nodelay = req.secure || self.tcp.nodelay();
        Either::Left(self.tcp.dial(req.uri, nodelay, req.bind_options))
    }
}
