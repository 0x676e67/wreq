//! Optional I/O tracing for established stream connections.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
};

use pin_project_lite::pin_project;
use tower::{Layer, Service};

use crate::conn::{Conn, request::ConnectRequest};

/// Middleware layer to use [`Verbose`].
#[derive(Clone, Copy)]
pub(crate) struct VerboseLayer {
    enabled: bool,
}

/// Traces the I/O of each stream the inner service establishes, when enabled with the
/// `tracing` feature. Other connections pass through unchanged.
#[derive(Clone)]
pub(crate) struct Verbose<S> {
    inner: S,
    enabled: bool,
}

pin_project! {
    /// Wraps the established stream once the inner connection completes.
    pub struct ResponseFuture<F> {
        #[pin]
        future: F,
        enabled: bool,
    }
}

/// Wraps a stream so its reads and writes are logged; QUIC transports pass through.
#[cfg(feature = "tracing")]
fn trace(conn: Conn) -> Conn {
    use crate::conn::Transport;

    let Conn {
        transport,
        connected,
    } = conn;
    let transport = match transport {
        Transport::Stream(io) => Transport::Stream(Box::new(sealed::Wrapper {
            id: crate::util::fast_random(),
            inner: io,
        })),
        #[cfg(feature = "http3")]
        quic @ Transport::Quic { .. } => quic,
    };
    Conn {
        transport,
        connected,
    }
}

/// Tracing is compiled out without the `tracing` feature.
#[cfg(not(feature = "tracing"))]
#[inline(always)]
fn trace(conn: Conn) -> Conn {
    conn
}

// ===== impl VerboseLayer =====

impl VerboseLayer {
    pub(crate) fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}

impl<S> Layer<S> for VerboseLayer {
    type Service = Verbose<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        Verbose {
            inner,
            enabled: self.enabled,
        }
    }
}

// ===== impl Verbose =====

impl<S> Service<ConnectRequest> for Verbose<S>
where
    S: Service<ConnectRequest, Response = Conn>,
{
    type Response = Conn;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    #[inline]
    fn call(&mut self, request: ConnectRequest) -> Self::Future {
        ResponseFuture {
            future: self.inner.call(request),
            enabled: self.enabled,
        }
    }
}

// ===== impl ResponseFuture =====

impl<F, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Conn, E>>,
{
    type Output = Result<Conn, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let conn = ready!(this.future.poll(cx))?;
        Poll::Ready(Ok(if *this.enabled { trace(conn) } else { conn }))
    }
}

#[cfg(feature = "tracing")]
mod sealed {
    use std::{
        fmt,
        io::{self, IoSlice},
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use crate::util::Escape;

    pub(super) struct Wrapper<T> {
        pub(super) id: u64,
        pub(super) inner: T,
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for Wrapper<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match Pin::new(&mut self.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    trace!("{:08x} read: {:?}", self.id, Escape::new(buf.filled()));
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Wrapper<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match Pin::new(&mut self.inner).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    trace!("{:08x} write: {:?}", self.id, Escape::new(&buf[..n]));
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            match Pin::new(&mut self.inner).poll_write_vectored(cx, bufs) {
                Poll::Ready(Ok(nwritten)) => {
                    trace!(
                        "{:08x} write (vectored): {:?}",
                        self.id,
                        Vectored { bufs, nwritten }
                    );
                    Poll::Ready(Ok(nwritten))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        #[inline]
        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        #[inline]
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        #[inline]
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    struct Vectored<'a, 'b> {
        bufs: &'a [IoSlice<'b>],
        nwritten: usize,
    }

    impl fmt::Debug for Vectored<'_, '_> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let mut left = self.nwritten;
            for buf in self.bufs.iter() {
                if left == 0 {
                    break;
                }
                let n = std::cmp::min(left, buf.len());
                Escape::new(&buf[..n]).fmt(f)?;
                left -= n;
            }
            Ok(())
        }
    }
}
