//! Optional I/O tracing for established stream connections.

use tower::util::{Either, MapResponse, MapResponseLayer};

use crate::conn::Conn;

/// Maps an established connection to one whose stream I/O is traced.
type Trace = fn(Conn) -> Conn;

/// A service whose established streams are traced when the layer is in place.
pub(crate) type Verbose<S> = Either<MapResponse<S, Trace>, S>;

/// Returns the layer that traces the I/O of each stream the inner service establishes, when
/// `enabled` with the `tracing` feature. Without it the inner service is used as is.
pub(crate) fn layer(
    #[cfg_attr(
        not(feature = "tracing"),
        expect(unused_variables, reason = "Tracing is compiled out")
    )]
    enabled: bool,
) -> Option<MapResponseLayer<Trace>> {
    cfg_select! {
        feature = "tracing" => enabled.then(|| MapResponseLayer::new(trace as Trace)),
        _ => None,
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
