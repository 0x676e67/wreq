//! Tokio-based network connector (TCP and Unix).

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};

use super::BoxConnecting;
use crate::conn::info::ConnectionInfo;

/// A unified network stream that may be either TCP or a Unix domain socket.
#[derive(Debug)]
pub enum NetStream {
    /// A TCP stream.
    Tcp(TcpStream),
    /// A Unix domain socket stream.
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl AsyncRead for NetStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            NetStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for NetStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            NetStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            NetStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            NetStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl ConnectionInfo for NetStream {
    #[inline]
    fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            NetStream::Tcp(s) => s.local_addr().ok(),
            #[cfg(unix)]
            NetStream::Unix(_) => None,
        }
    }

    #[inline]
    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            NetStream::Tcp(s) => s.peer_addr().ok(),
            #[cfg(unix)]
            NetStream::Unix(_) => None,
        }
    }
}

impl NetStream {
    /// Set the value of the `TCP_NODELAY` option on the underlying TCP stream.
    /// For Unix domain socket streams this is a no-op.
    #[inline]
    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        match self {
            NetStream::Tcp(s) => s.set_nodelay(nodelay),
            #[cfg(unix)]
            NetStream::Unix(_) => Ok(()),
        }
    }
}

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

impl super::NetConnector for NetConnector {
    type TcpStream = std::net::TcpStream;
    type Connection = NetStream;
    type Error = io::Error;
    type Future = BoxConnecting<Self::Connection, Self::Error>;

    #[inline]
    fn connect(&self, socket: Self::TcpStream, addr: SocketAddr) -> Self::Future {
        let socket = TcpSocket::from_std_stream(socket);
        Box::pin(async move { socket.connect(addr).await.map(NetStream::Tcp) })
    }

    #[cfg(unix)]
    type UnixFuture = BoxConnecting<Self::Connection, Self::Error>;

    #[cfg(unix)]
    #[inline]
    fn connect_unix(&self, path: std::sync::Arc<std::path::Path>) -> Self::UnixFuture {
        Box::pin(async move {
            tokio::net::UnixStream::connect(&*path)
                .await
                .map(NetStream::Unix)
        })
    }
}
