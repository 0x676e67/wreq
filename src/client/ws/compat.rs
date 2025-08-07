//! Cross-runtime async I/O compatibility layer
//!
//! Provides adapters to bridge between different async runtime I/O traits,
//! enabling interoperability across async ecosystems.

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use pin_project_lite::pin_project;

pin_project! {
    /// A compatibility wrapper that bridges between different async I/O traits.
    ///
    /// This wrapper allows types implementing one set of async I/O traits
    /// to be used with APIs expecting different trait implementations,
    /// enabling interoperability across async ecosystems.
    #[derive(Debug)]
    pub struct Compat<T> {
        #[pin]
        inner: T,
    }
}

impl<T> Compat<T> {
    #[inline]
    pub fn new(inner: T) -> Self {
        Compat { inner }
    }
}

impl<T> futures_util::AsyncRead for Compat<T>
where
    T: tokio::io::AsyncRead + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slice: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut buf = tokio::io::ReadBuf::new(slice);
        ready!(self.project().inner.poll_read(cx, &mut buf))?;
        Poll::Ready(Ok(buf.filled().len()))
    }
}

impl<T> futures_util::AsyncWrite for Compat<T>
where
    T: tokio::io::AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
