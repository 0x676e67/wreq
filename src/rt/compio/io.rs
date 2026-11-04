//! Tokio I/O traits for compio streams.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use compio::io::{AsyncRead, AsyncWrite, compat::AsyncStream, util::Splittable};
use send_wrapper::SendWrapper;

/// Exposes a compio stream through [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`].
///
/// The stream is boxed so this type is `Unpin`, and wrapped in [`SendWrapper`] because
/// compio streams are `!Send`; using it off its runtime thread panics.
#[derive(Debug)]
pub struct CompioIO<S: Splittable>(SendWrapper<Pin<Box<AsyncStream<S>>>>);

// ===== impl CompioIO =====

impl<S> CompioIO<S>
where
    S: Splittable + 'static,
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    /// Wraps a compio stream.
    #[inline]
    pub fn new(stream: S) -> Self {
        Self(SendWrapper::new(Box::pin(AsyncStream::new(stream))))
    }
}

impl<S> tokio::io::AsyncRead for CompioIO<S>
where
    S: Splittable + 'static,
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    #[allow(unsafe_code)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // SAFETY: `poll_read_uninit` only writes into the unfilled region and never
        // de-initializes it, so handing out the uninitialized slice is sound.
        let unfilled = unsafe { buf.unfilled_mut() };
        let len = ready!(self.0.as_mut().poll_read_uninit(cx, unfilled))?;
        // SAFETY: `poll_read_uninit` initialized the first `len` bytes of `unfilled`.
        unsafe { buf.assume_init(len) };
        buf.advance(len);
        Poll::Ready(Ok(()))
    }
}

impl<S> tokio::io::AsyncWrite for CompioIO<S>
where
    S: Splittable + 'static,
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        futures_util::AsyncWrite::poll_write(self.0.as_mut(), cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures_util::AsyncWrite::poll_flush(self.0.as_mut(), cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures_util::AsyncWrite::poll_close(self.0.as_mut(), cx)
    }
}
