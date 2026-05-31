//! Compio-based network connector (TCP and Unix).

#![allow(dead_code)]

use std::{io, net::SocketAddr};
#[cfg(unix)]
use std::{path::Path, sync::Arc};

use super::{Connecting, Connector};
use crate::conn::{info::ConnectionInfo, net::io::CompioConnection};
use compio::net::{TcpSocket, TcpStream};
use futures_util::FutureExt;
use wreq_rt::rt::compio::{future::SendFuture, io::CompioIO};

/// A connector that uses `compio` for TCP and Unix socket connections.
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
        SendFuture::new(async move {
            TcpSocket::from_std_stream(socket)?
                .connect(addr)
                .await
                .map(|stream| CompioConnection {
                    peer_addr: stream.peer_addr().ok(),
                    local_addr: stream.local_addr().ok(),
                    inner: CompioIO::new(stream),
                })
                .map(|stream| Box::new(stream) as _)
                .map_err(Into::into)
        })
        .boxed()
    }

    #[cfg(unix)]
    #[inline(always)]
    fn unix_connect(&self, path: Arc<Path>) -> Connecting {
        SendFuture::new(async move {
            compio::net::UnixStream::connect(path)
                .await
                .map(|stream| CompioConnection {
                    peer_addr: None,
                    local_addr: None,
                    inner: CompioIO::new(stream),
                })
                .map(|stream| Box::new(stream) as _)
                .map_err(Into::into)
        })
        .boxed()
    }
}

impl ConnectionInfo for CompioConnection<TcpStream> {
    #[inline(always)]
    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    #[inline(always)]
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    #[inline(always)]
    fn set_nodelay(&self, _: bool) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
impl ConnectionInfo for CompioConnection<compio::net::UnixStream> {
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
