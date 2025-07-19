use std::{
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_boring2::SslStream;

use super::{AsyncConnWithInfo, TlsInfoFactory};
use crate::{
    core::{
        client::connect::{Connected, Connection},
        rt::{Read, ReadBufCursor, TokioIo, Write},
    },
    tls::{MaybeHttpsStream, TlsInfo},
};

pin_project! {
    /// Note: the `is_proxy` member means *is plain text HTTP proxy*.
    /// This tells core whether the URI should be written in
    /// * origin-form (`GET /just/a/path HTTP/1.1`), when `is_proxy == false`, or
    /// * absolute-form (`GET http://foo.bar/and/a/path HTTP/1.1`), otherwise.
    pub struct Conn {
        #[pin]
        inner: Box<dyn AsyncConnWithInfo>,
        is_proxy: bool,
        tls_info: bool,
    }
}

pin_project! {
    /// A wrapper around `SslStream` that adapts it for use as a generic async connection.
    ///
    /// This type enables unified handling of plain TCP and TLS-encrypted streams by providing
    /// implementations of `Connection`, `Read`, `Write`, and `TlsInfoFactory`.
    /// It is mainly used internally to abstract over different connection types.
    pub(super) struct TlsConn<T> {
        #[pin]
        inner: TokioIo<SslStream<T>>,
    }
}

// ==== impl Conn ====

impl Conn {
    /// Creates a new `Conn` instance with the given inner connection and TLS info flag.
    #[inline(always)]
    pub(super) fn new(inner: Box<dyn AsyncConnWithInfo>, is_proxy: bool, tls_info: bool) -> Self {
        Self {
            inner,
            is_proxy,
            tls_info,
        }
    }
}

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

impl Read for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        Read::poll_read(this.inner, cx, buf)
    }
}

impl Write for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        Write::poll_write(this.inner, cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        Write::poll_write_vectored(this.inner, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        Write::poll_flush(this.inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        Write::poll_shutdown(this.inner, cx)
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
        Self {
            inner: TokioIo::new(inner),
        }
    }
}

impl Connection for TlsConn<TcpStream> {
    fn connected(&self) -> Connected {
        let connected = self.inner.inner().get_ref().connected();
        if self.inner.inner().ssl().selected_alpn_protocol() == Some(b"h2") {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

impl Connection for TlsConn<TokioIo<MaybeHttpsStream<TcpStream>>> {
    fn connected(&self) -> Connected {
        let connected = self.inner.inner().get_ref().connected();
        if self.inner.inner().ssl().selected_alpn_protocol() == Some(b"h2") {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Read for TlsConn<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: ReadBufCursor<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let this = self.project();
        Read::poll_read(this.inner, cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Write for TlsConn<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        let this = self.project();
        Write::poll_write(this.inner, cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        Write::poll_write_vectored(this.inner, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), tokio::io::Error>> {
        let this = self.project();
        Write::poll_flush(this.inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), tokio::io::Error>> {
        let this = self.project();
        Write::poll_shutdown(this.inner, cx)
    }
}

impl<T> TlsInfoFactory for TlsConn<T>
where
    TokioIo<SslStream<T>>: TlsInfoFactory,
{
    fn tls_info(&self) -> Option<TlsInfo> {
        self.inner.tls_info()
    }
}
