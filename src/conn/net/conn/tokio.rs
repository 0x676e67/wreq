//! Tokio-based network connector (TCP and Unix).

use std::{io, net::SocketAddr};
#[cfg(unix)]
use std::{path::Path, sync::Arc};

use futures_util::{FutureExt, TryFutureExt};
use tokio::net::{TcpSocket, TcpStream};

use super::{Connecting, Connector};
use crate::conn::info::ConnectionInfo;

/// A connector that uses `tokio` for TCP and Unix socket connections.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetConnector {
    _priv: (),
}

impl NetConnector {
    /// Creates a new [`NetConnector`].
    #[inline]
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl Connector for NetConnector {
    #[inline(always)]
    fn connect(&self, socket: std::net::TcpStream, addr: SocketAddr) -> Connecting {
        TcpSocket::from_std_stream(socket)
            .connect(addr)
            .map_ok(|s| Box::new(s) as _)
            .map_err(Into::into)
            .boxed()
    }

    #[cfg(unix)]
    #[inline(always)]
    fn unix_connect(&self, path: Arc<Path>) -> Connecting {
        tokio::net::UnixStream::connect(path)
            .map_ok(|s| Box::new(s) as _)
            .map_err(Into::into)
            .boxed()
    }
}

impl ConnectionInfo for TcpStream {
    #[inline(always)]
    fn local_addr(&self) -> Option<SocketAddr> {
        TcpStream::local_addr(self).ok()
    }

    #[inline(always)]
    fn peer_addr(&self) -> Option<SocketAddr> {
        TcpStream::peer_addr(self).ok()
    }

    #[inline(always)]
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        TcpStream::set_nodelay(self, nodelay)
    }
}

#[cfg(unix)]
impl ConnectionInfo for tokio::net::UnixStream {
    #[inline(always)]
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }

    #[inline(always)]
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }

    #[inline(always)]
    fn set_nodelay(&self, _: bool) -> io::Result<()> {
        Ok(())
    }
}
