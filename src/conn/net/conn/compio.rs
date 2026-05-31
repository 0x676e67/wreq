//! Compio-based network connector (TCP and Unix).

#![allow(dead_code)]

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, ready},
};
#[cfg(unix)]
use std::{path::Path, sync::Arc};

use compio::{
    io::{AsyncRead, AsyncWrite, util::Splittable},
    net::{TcpSocket, TcpStream},
};
use futures_util::FutureExt;
use wreq_rt::rt::compio::{future::SendFuture, io::CompioIO};

use super::{Connecting, Connector};
use crate::conn::info::ConnectionInfo;

/// A [`compio`] connection wrapper
#[derive(Debug)]
pub struct Connection<T: Splittable> {
    io: CompioIO<T>,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
}

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

// ===== impl NetConnector =====

impl Connector for NetConnector {
    #[inline(always)]
    fn connect(&self, socket: std::net::TcpStream, addr: SocketAddr) -> Connecting {
        SendFuture::new(async move {
            TcpSocket::from_std_stream(socket)?
                .connect(addr)
                .await
                .map(|stream| Connection {
                    peer_addr: stream.peer_addr().ok(),
                    local_addr: stream.local_addr().ok(),
                    io: CompioIO::new(stream),
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
                .map(|stream| Connection {
                    peer_addr: None,
                    local_addr: None,
                    io: CompioIO::new(stream),
                })
                .map(|stream| Box::new(stream) as _)
                .map_err(Into::into)
        })
        .boxed()
    }
}

// ===== impl CompioConnection =====

impl<S> tokio::io::AsyncRead for Connection<S>
where
    S: Splittable + 'static,
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    #[inline(always)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Flush any buffered writes before reading. This is necessary
        // because code like hyper_util::rt::write_all (used by Tunnel
        // and SOCKS handshakes) and hyper's own body encoder may call
        // poll_write without poll_flush, leaving data buffered in
        // compio's AsyncWriteStream. Since HTTP/1.1 is half-duplex
        // (write then read), flushing here ensures the remote peer
        // receives our data before we wait for its response.
        // In HTTP/2 the stream is split, so this combined poll_read
        // is not called and concurrent reads/writes are unaffected.
        ready!(tokio::io::AsyncWrite::poll_flush(self.as_mut(), cx))?;
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl<S> tokio::io::AsyncWrite for Connection<S>
where
    S: Splittable + 'static,
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    #[inline(always)]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    #[inline(always)]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    #[inline(always)]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl ConnectionInfo for Connection<TcpStream> {
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
impl ConnectionInfo for Connection<compio::net::UnixStream> {
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
