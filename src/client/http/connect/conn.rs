use std::{
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_boring2::SslStream;

use super::{AsyncConnWithInfo, TlsInfoFactory};
use crate::{
    core::client::connect::{Connected, Connection},
    tls::{MaybeHttpsStream, TlsInfo},
};

pin_project! {
    /// Note: the `is_proxy` member means *is plain text HTTP proxy*.
    /// This tells core whether the URI should be written in
    /// * origin-form (`GET /just/a/path HTTP/1.1`), when `is_proxy == false`, or
    /// * absolute-form (`GET http://foo.bar/and/a/path HTTP/1.1`), otherwise.
    pub struct Conn {
        #[pin]
        pub inner: Box<dyn AsyncConnWithInfo>,
        pub tls_info: bool,
        pub is_proxy: bool,
    }
}

pin_project! {
    /// A wrapper around `SslStream` that adapts it for use as a generic async connection.
    ///
    /// This type enables unified handling of plain TCP and TLS-encrypted streams by providing
    /// implementations of `Connection`, `Read`, `Write`, and `TlsInfoFactory`.
    /// It is mainly used internally to abstract over different connection types.
    pub struct TlsConn<T> {
        #[pin]
        inner: SslStream<T>,
    }
}

// ==== impl Conn ====

impl Connection for Conn {
    fn connected(&self) -> Connected {
        let connected = self.inner.connected().proxy(self.is_proxy);

        if self.tls_info {
            if let Some(tls_info) = self.inner.tls_info() {
                connected.extra(tls_info)
            } else {
                connected
            }
        } else {
            connected
        }
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        AsyncRead::poll_read(this.inner, cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        AsyncWrite::poll_write(this.inner, cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        AsyncWrite::poll_write_vectored(this.inner, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        AsyncWrite::poll_flush(this.inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        AsyncWrite::poll_shutdown(this.inner, cx)
    }
}

// ==== impl TlsConn ====

impl<T> TlsConn<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a new `TlsConn` wrapping the provided `SslStream`.
    #[inline(always)]
    pub fn new(inner: SslStream<T>) -> Self {
        Self { inner }
    }
}

// ===== impl TcpStream =====

impl Connection for TlsConn<TcpStream> {
    fn connected(&self) -> Connected {
        let connected = self.inner.get_ref().connected();
        if self.inner.ssl().selected_alpn_protocol() == Some(b"h2") {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

impl Connection for TlsConn<MaybeHttpsStream<TcpStream>> {
    fn connected(&self) -> Connected {
        let connected = self.inner.get_ref().connected();
        if self.inner.ssl().selected_alpn_protocol() == Some(b"h2") {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

// ===== impl UnixStream =====

#[cfg(unix)]
impl Connection for TlsConn<UnixStream> {
    fn connected(&self) -> Connected {
        let connected = self.inner.get_ref().connected();
        if self.inner.ssl().selected_alpn_protocol() == Some(b"h2") {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

#[cfg(unix)]
impl Connection for TlsConn<MaybeHttpsStream<UnixStream>> {
    fn connected(&self) -> Connected {
        let connected = self.inner.get_ref().connected();
        if self.inner.ssl().selected_alpn_protocol() == Some(b"h2") {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsConn<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let this = self.project();
        AsyncRead::poll_read(this.inner, cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsConn<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        let this = self.project();
        AsyncWrite::poll_write(this.inner, cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        AsyncWrite::poll_write_vectored(this.inner, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), tokio::io::Error>> {
        let this = self.project();
        AsyncWrite::poll_flush(this.inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), tokio::io::Error>> {
        let this = self.project();
        AsyncWrite::poll_shutdown(this.inner, cx)
    }
}

impl<T> TlsInfoFactory for TlsConn<T>
where
    SslStream<T>: TlsInfoFactory,
{
    fn tls_info(&self) -> Option<TlsInfo> {
        self.inner.tls_info()
    }
}
