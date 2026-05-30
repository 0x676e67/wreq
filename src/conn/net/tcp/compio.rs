//! Compio-based network connector (TCP and Unix).

#![allow(dead_code)]

use std::{io, net::SocketAddr, pin::Pin};
#[cfg(unix)]
use std::{path::Path, sync::Arc};

use compio::net::TcpStream;
use wreq_rt::rt::compio::{future::SendFuture, io::CompioIO};

use super::BoxConnecting;
use crate::conn::{info::ConnectionInfo, net::io::CompioConnection};

/// A unified network stream (compio) that may be TCP or a Unix domain socket.
#[derive(Debug)]
pub enum NetStream {
    /// A TCP stream wrapped for compio I/O.
    Tcp(CompioConnection<TcpStream>),
    /// A Unix domain socket stream wrapped for compio I/O.
    #[cfg(unix)]
    Unix(CompioConnection<compio::net::UnixStream>),
}

impl tokio::io::AsyncRead for NetStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            NetStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for NetStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            NetStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            NetStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            NetStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl ConnectionInfo for NetStream {
    #[inline]
    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            NetStream::Tcp(s) => s.peer_addr,
            #[cfg(unix)]
            NetStream::Unix(_) => None,
        }
    }

    #[inline]
    fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            NetStream::Tcp(s) => s.local_addr,
            #[cfg(unix)]
            NetStream::Unix(_) => None,
        }
    }
}

/// A connector that uses `compio` for TCP and Unix socket connections.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetConnector {
    _priv: (),
}

// ===== impl NetConnector =====

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
        Box::pin(SendFuture::new(async move {
            use compio::net::TcpSocket;
            let socket = TcpSocket::from_std_stream(socket)?;
            let tcp_stream = socket.connect(addr).await?;
            Ok(NetStream::Tcp(CompioConnection {
                peer_addr: tcp_stream.peer_addr().ok(),
                local_addr: tcp_stream.local_addr().ok(),
                inner: CompioIO::new(tcp_stream),
            }))
        }))
    }

    #[cfg(unix)]
    type UnixFuture = BoxConnecting<Self::Connection, Self::Error>;

    #[cfg(unix)]
    #[inline]
    fn connect_unix(&self, path: Arc<Path>) -> Self::UnixFuture {
        Box::pin(SendFuture::new(async move {
            let stream = compio::net::UnixStream::connect(&*path).await?;
            Ok(NetStream::Unix(CompioConnection {
                peer_addr: None,
                local_addr: None,
                inner: CompioIO::new(stream),
            }))
        }))
    }
}
