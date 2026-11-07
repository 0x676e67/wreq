//! A wrapper around `compio::io::compat::AsyncStream` that implements
//! `tokio::io::AsyncRead` + `tokio::io::AsyncWrite`.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker, ready},
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

/// Adapts a Compio stream to Tokio I/O.
///
/// Compio buffers writes until a flush. A read pushes unflushed bytes without waiting on them,
/// so writing and then reading still sends the request while a stalled upload cannot hold back
/// the response. Compio keeps a single flush waker, so every flush poll wakes both the reader
/// and the writer: split tasks keep their wakeups, and either can finish a flush the other
/// abandoned.
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
pub(super) struct Compat<S: Splittable> {
    stream: SendWrapper<Pin<Box<AsyncStream<S>>>>,
    /// Written bytes may still sit in Compio's buffer.
    unflushed: bool,
    /// Reader waiting on a flush it pushed.
    reader: Option<Waker>,
    /// Writer waiting on a pending flush or shutdown.
    writer: Option<Waker>,
}

/// Wakes both tasks that share Compio's single flush waker.
struct WakeBoth(Waker, Waker);

// ===== impl Compat =====

impl<S> Compat<S>
where
    S: Splittable,
{
    fn get_ref(&self) -> (&S::ReadHalf, &S::WriteHalf) {
        self.stream.as_ref().get_ref().get_ref()
    }

    /// Clears the flush state once Compio's buffer has been flushed or the flush failed.
    fn flushed(&mut self) {
        self.unflushed = false;
        self.reader = None;
        self.writer = None;
    }

    /// Create a new [`Compat`] from a stream that implements [`Splittable`].
    pub(super) fn new(stream: S) -> Self
    where
        S: 'static,
        S::ReadHalf: AsyncRead + Unpin,
        S::WriteHalf: AsyncWrite + Unpin,
    {
        Self {
            stream: SendWrapper::new(Box::pin(AsyncStream::new(stream))),
            unflushed: false,
            reader: None,
            writer: None,
        }
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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Never wait here; a failed push is left for the writer's next write or flush to report.
        if this.unflushed {
            match poll_flush_with(this.stream.as_mut(), cx.waker(), this.writer.as_ref()) {
                Poll::Ready(_) => this.flushed(),
                Poll::Pending => set_waker(&mut this.reader, cx.waker()),
            }
        }
        // SAFETY: `poll_read_uninit` only writes into the unfilled region and never
        // de-initializes it, so handing out the uninitialized slice is sound.
        let unfilled = unsafe { buf.unfilled_mut() };
        let len = ready!(this.stream.as_mut().poll_read_uninit(cx, unfilled))?;
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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = ready!(FuturesAsyncWrite::poll_write(this.stream.as_mut(), cx, buf))?;
        this.unflushed |= written > 0;
        Poll::Ready(Ok(written))
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = poll_flush_with(this.stream.as_mut(), cx.waker(), this.reader.as_ref());
        match poll {
            Poll::Ready(_) => this.flushed(),
            Poll::Pending => set_waker(&mut this.writer, cx.waker()),
        }
        poll
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Compio keeps the close waker apart from the flush waker, so no merge is needed.
        let poll = FuturesAsyncWrite::poll_close(this.stream.as_mut(), cx);
        match poll {
            Poll::Ready(_) => this.flushed(),
            Poll::Pending => set_waker(&mut this.writer, cx.waker()),
        }
        poll
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

/// Polls Compio's flush so that progress wakes `waker` and the other half's `other`.
fn poll_flush_with<S>(
    stream: Pin<&mut AsyncStream<S>>,
    waker: &Waker,
    other: Option<&Waker>,
) -> Poll<io::Result<()>>
where
    S: Splittable + 'static,
    S::WriteHalf: AsyncWrite + Unpin,
{
    match other {
        Some(other) if !other.will_wake(waker) => {
            let both = Waker::from(Arc::new(WakeBoth(waker.clone(), other.clone())));
            FuturesAsyncWrite::poll_flush(stream, &mut Context::from_waker(&both))
        }
        _ => FuturesAsyncWrite::poll_flush(stream, &mut Context::from_waker(waker)),
    }
}

/// Stores `waker` in `slot` unless it already wakes the same task.
fn set_waker(slot: &mut Option<Waker>, waker: &Waker) {
    if !slot.as_ref().is_some_and(|stored| stored.will_wake(waker)) {
        *slot = Some(waker.clone());
    }
}

// ===== impl WakeBoth =====

impl Wake for WakeBoth {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.wake_by_ref();
        self.1.wake_by_ref();
    }
}
