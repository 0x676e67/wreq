//! A wrapper around `compio::io::compat::AsyncStream` that implements
//! `tokio::io::AsyncRead` + `tokio::io::AsyncWrite`.

#![allow(unsafe_code)]

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use compio::io::{AsyncRead, AsyncWrite, compat::AsyncStream, util::Splittable};
use send_wrapper::SendWrapper;

/// A wrapper around `compio::io::compat::AsyncStream` that implements
/// `tokio::io::AsyncRead` + `tokio::io::AsyncWrite`.
///
/// The inner `AsyncStream` is stored behind `Pin<Box<...>>` so the outer type
/// is `Unpin`. `SendWrapper` makes the `!Send` compio types `Send`-compatible.
///
/// # Thread safety (Send / Sync)
///
/// Compio types are `!Send` and `!Sync` (they use `Rc` internally for its
/// thread-per-core design). `SendWrapper` provides both `Send` and `Sync`
/// via `unsafe` impls with runtime checks (panics on cross-thread access).
/// This is safe because the compio runtime is single-threaded per core and
/// the stream never actually leaves its runtime thread.
#[derive(Debug)]
pub struct CompioIO<S: Splittable>(SendWrapper<Pin<Box<AsyncStream<S>>>>);

impl<S> CompioIO<S>
where
    S: Splittable,
{
    /// Create a new [`CompioIO`] from a stream that implements [`Splittable`].
    pub fn new(stream: S) -> Self
    where
        S: 'static,
        S::ReadHalf: AsyncRead + Unpin,
        S::WriteHalf: AsyncWrite + Unpin,
    {
        Self(SendWrapper::new(Box::pin(AsyncStream::new(stream))))
    }

    /// Access the inner stream's read half.
    pub fn get_ref(&self) -> (&S::ReadHalf, &S::WriteHalf) {
        let pinned_box: &Pin<Box<AsyncStream<S>>> = &self.0;
        let stream_ref: Pin<&AsyncStream<S>> = pinned_box.as_ref();
        let stream: &AsyncStream<S> = Pin::get_ref(stream_ref);
        stream.get_ref()
    }
}

impl<S> tokio::io::AsyncRead for CompioIO<S>
where
    S: Splittable + 'static,
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let unfilled = unsafe { buf.unfilled_mut() };
        let len = ready!(self.0.as_mut().poll_read_uninit(cx, unfilled))?;
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
