#![allow(unsafe_code, dead_code)]

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use compio::io::compat::AsyncStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{conn::TlsInfoFactory, tls::TlsInfo};

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
pub struct CompioIO<S>
where
    S: compio::io::util::Splittable,
{
    inner: send_wrapper::SendWrapper<Pin<Box<AsyncStream<S>>>>,
}

impl<S> CompioIO<S>
where
    S: compio::io::util::Splittable,
{
    pub fn new(stream: S) -> Self
    where
        S: 'static,
        S::ReadHalf: compio::io::AsyncRead + Unpin,
        S::WriteHalf: compio::io::AsyncWrite + Unpin,
    {
        Self {
            inner: send_wrapper::SendWrapper::new(Box::pin(AsyncStream::new(stream))),
        }
    }

    /// Access the inner stream's read half.
    pub fn get_ref(&self) -> &S::ReadHalf {
        let pinned_box: &Pin<Box<AsyncStream<S>>> = &self.inner;
        let stream_ref: Pin<&AsyncStream<S>> = pinned_box.as_ref();
        let stream: &AsyncStream<S> = Pin::get_ref(stream_ref);
        stream.get_ref().0
    }

    /// Disable Nagle's algorithm on the underlying TCP socket.
    ///
    /// Stub: the inner stream is split into read/write halves inside
    /// `AsyncStream`, so the socket options are not directly accessible.
    pub fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {
        Ok(())
    }
}

impl<S> AsyncRead for CompioIO<S>
where
    S: compio::io::util::Splittable + 'static,
    S::ReadHalf: compio::io::AsyncRead + Unpin,
    S::WriteHalf: compio::io::AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self.inner;
        let unfilled = unsafe { buf.unfilled_mut() };
        let len = match ready!(this.as_mut().poll_read_uninit(cx, unfilled)) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        };
        unsafe { buf.assume_init(len) };
        buf.advance(len);
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for CompioIO<S>
where
    S: compio::io::util::Splittable + 'static,
    S::ReadHalf: compio::io::AsyncRead + Unpin,
    S::WriteHalf: compio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self.inner;
        futures_util::AsyncWrite::poll_write(this.as_mut(), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self.inner;
        futures_util::AsyncWrite::poll_flush(this.as_mut(), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self.inner;
        futures_util::AsyncWrite::poll_close(this.as_mut(), cx)
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for CompioIO<S>
where
    S: compio::io::util::Splittable,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompioIO").finish_non_exhaustive()
    }
}

impl<S> TlsInfoFactory for CompioIO<S>
where
    S: compio::io::util::Splittable + 'static,
    S::ReadHalf: compio::io::AsyncRead + Unpin,
    S::WriteHalf: compio::io::AsyncWrite + Unpin,
{
    fn tls_info(&self) -> Option<TlsInfo> {
        None
    }
}
