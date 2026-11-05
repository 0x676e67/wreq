//! A wrapper around `compio::io::compat::AsyncStream` that implements
//! `tokio::io::AsyncRead` + `tokio::io::AsyncWrite`.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, ready},
};

#[cfg(unix)]
use compio::net::UnixStream;
use compio::{
    io::{AsyncRead, AsyncWrite, compat::AsyncStream, util::Splittable},
    net::TcpStream,
};
use futures_util::AsyncWrite as FuturesAsyncWrite;
use send_wrapper::SendWrapper;
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf};

use crate::rt::Connection;

/// Adapts a Compio stream to Tokio I/O, flushing buffered writes before reading.
///
/// The inner `AsyncStream` is stored behind `Pin<Box<...>>` so the outer type
/// is `Unpin`. `SendWrapper` makes the `!Send` compio types `Send`-compatible.
///
/// # Thread safety (Send / Sync)
///
/// Compio types are `!Send` and `!Sync` (they use `Rc` internally for its
/// thread-per-core design). `SendWrapper` provides both `Send` and `Sync`
/// via `unsafe` impls with runtime checks (panics on cross-thread access).
/// Poll, access and drop the stream on the Compio runtime thread that created it;
/// the wrapper does not make the underlying I/O safe to use across threads.
#[derive(Debug)]
pub(super) struct Compat<S: Splittable>(SendWrapper<Pin<Box<AsyncStream<S>>>>);

impl<S> Compat<S>
where
    S: Splittable,
{
    fn get_ref(&self) -> (&S::ReadHalf, &S::WriteHalf) {
        self.0.as_ref().get_ref().get_ref()
    }

    /// Create a new [`Compat`] from a stream that implements [`Splittable`].
    pub(super) fn new(stream: S) -> Self
    where
        S: 'static,
        S::ReadHalf: AsyncRead + Unpin,
        S::WriteHalf: AsyncWrite + Unpin,
    {
        Self(SendWrapper::new(Box::pin(AsyncStream::new(stream))))
    }
}

impl<S> TokioAsyncRead for Compat<S>
where
    S: Splittable + 'static,
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    #[inline]
    #[allow(unsafe_code)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Send buffered request data before waiting for a response, even when
        // the caller did not explicitly flush after writing.
        ready!(self.as_mut().poll_flush(cx))?;
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

impl<S> TokioAsyncWrite for Compat<S>
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
        FuturesAsyncWrite::poll_write(self.0.as_mut(), cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        FuturesAsyncWrite::poll_flush(self.0.as_mut(), cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        FuturesAsyncWrite::poll_close(self.0.as_mut(), cx)
    }
}

impl Connection for Compat<TcpStream> {
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.get_ref().0.peer_addr().ok()
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.get_ref().0.local_addr().ok()
    }

    fn set_nodelay(&self, value: bool) -> io::Result<()> {
        self.get_ref().0.set_nodelay(value)
    }
}

#[cfg(unix)]
impl Connection for Compat<UnixStream> {}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use compio::runtime::Runtime;

    use super::*;

    #[test]
    fn tcp_controls_use_connected_socket() {
        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (_, peer) = listener.accept().unwrap();
            let stream = Compat::new(stream);
            let connection: &dyn Connection = &stream;
            assert_eq!(connection.local_addr(), Some(peer));
            assert_eq!(connection.peer_addr(), Some(listener.local_addr().unwrap()));
            for value in [true, false] {
                connection.set_nodelay(value).unwrap();
                assert_eq!(stream.get_ref().0.nodelay().unwrap(), value);
            }
        });
    }
}
