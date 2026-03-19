#![allow(unsafe_code)]

use std::{
    io,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll, ready},
    time::{Duration, Instant},
};

use compio::io::{AsyncRead, AsyncWrite, compat::AsyncStream};
use send_wrapper::SendWrapper;

use super::{Executor, Sleep, Timer};

/// An executor service based on [`compio::runtime`]. It uses
/// [`compio::runtime::spawn`] interally.
#[derive(Debug, Default, Clone)]
pub struct CompioExecutor;

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for CompioExecutor {
    fn execute(&self, fut: F) {
        compio::runtime::spawn(fut).detach();
    }
}

/// An timer service based on [`compio::time`].
#[derive(Debug, Default, Clone)]
pub struct CompioTimer;

struct SleepFuture<T: Send + Sync + Future<Output = ()>>(T);

impl<T: Send + Sync + Future<Output = ()>> Sleep for SleepFuture<T> {}

impl<T: Send + Sync + Future<Output = ()>> Future for SleepFuture<T> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe { self.map_unchecked_mut(|this| &mut this.0) }.poll(cx)
    }
}

impl Timer for CompioTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(SleepFuture(SendWrapper::new(compio::time::sleep(duration))))
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(SleepFuture(SendWrapper::new(compio::time::sleep_until(
            deadline,
        ))))
    }
}

/// A stream wrapper for compio.
pub struct CompioIO<S>(SendWrapper<AsyncStream<S>>);

impl<S> CompioIO<S> {
    /// Create a hyper stream wrapper.
    pub fn new(s: S) -> Self {
        Self(SendWrapper::new(AsyncStream::new(s)))
    }

    /// Get the reference of the inner stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }
}

impl<S: AsyncRead + Unpin + 'static> tokio::io::AsyncRead for CompioIO<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream = unsafe { self.map_unchecked_mut(|this| this.0.deref_mut()) };
        let slice = unsafe { buf.unfilled_mut() };
        let len = ready!(stream.poll_read_uninit(cx, slice))?;
        buf.advance(len);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin + 'static> tokio::io::AsyncWrite for CompioIO<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = unsafe { self.map_unchecked_mut(|this| this.0.deref_mut()) };
        futures_util::AsyncWrite::poll_write(stream, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = unsafe { self.map_unchecked_mut(|this| this.0.deref_mut()) };
        futures_util::AsyncWrite::poll_flush(stream, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = unsafe { self.map_unchecked_mut(|this| this.0.deref_mut()) };
        futures_util::AsyncWrite::poll_close(stream, cx)
    }
}
