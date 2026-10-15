//! Transport wrappers that report connection events to a [`ConnectionObserver`].
//!
//! [`HandshakeTap`] sits below every TLS stream and reports records only while a handshake runs;
//! without an observer it only forwards I/O. [`Observed`] sits above TLS and below the HTTP codec
//! and is installed only for clients with an observer.

use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use btls::ssl::SslRef;
use http::Extensions;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{AsyncConnWithInfo, Connected, Connection, TlsInfoFactory, http::HttpInfo};
use crate::{
    observe::{ConnectionEvent, ConnectionId, ConnectionObserver},
    tls::TlsVersion,
};

/// A client's observer bound to one connection.
///
/// Every layer of the connection, and every connector that may still perform a handshake for it,
/// holds a clone. Releasing the last clone reports [`ConnectionEvent::Closed`], so a connection
/// reports it exactly once, whether it is used or its attempt fails.
#[derive(Clone)]
pub(crate) struct Probe(Arc<ProbeInner>);

struct ProbeInner {
    id: ConnectionId,
    observer: Arc<dyn ConnectionObserver>,
}

/// The transport under TLS, reporting raw records while a handshake runs.
pub(crate) struct HandshakeTap<T> {
    io: T,
    probe: Option<Probe>,
}

/// A connected transport reporting its plaintext I/O.
pub(super) struct Observed<T> {
    inner: T,
    probe: Probe,
}

// ===== impl Probe =====

impl Probe {
    /// Binds `observer` to a newly allocated connection id.
    pub(crate) fn new(observer: Arc<dyn ConnectionObserver>) -> Probe {
        Probe(Arc::new(ProbeInner {
            id: ConnectionId::next(),
            observer,
        }))
    }

    #[inline]
    pub(crate) fn id(&self) -> ConnectionId {
        self.0.id
    }

    #[inline]
    pub(crate) fn observe(&self, event: ConnectionEvent<'_>) {
        self.0.observer.observe(event);
    }
}

impl Drop for ProbeInner {
    fn drop(&mut self) {
        // The last clone may be dropped during unwinding, where a second panic would abort.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.observer
                .observe(ConnectionEvent::Closed { id: self.id });
        }));
    }
}

// ===== impl HandshakeTap =====

impl<T> HandshakeTap<T> {
    /// Wraps the transport of a handshake for `host`, reporting its start to `probe`.
    pub(crate) fn new(io: T, probe: Option<Probe>, host: &str) -> HandshakeTap<T> {
        if let Some(probe) = &probe {
            probe.observe(ConnectionEvent::TlsHandshake {
                id: probe.id(),
                host,
            });
        }
        HandshakeTap { io, probe }
    }

    /// Stops reporting; called once the handshake has completed.
    #[inline]
    pub(crate) fn finish(&mut self) {
        self.probe = None;
    }

    #[inline]
    pub(crate) fn get_ref(&self) -> &T {
        &self.io
    }
}

impl<T: Connection> Connection for HandshakeTap<T> {
    #[inline]
    fn connected(&self) -> Connected {
        self.io.connected()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for HandshakeTap<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled = buf.filled().len();
        let poll = Pin::new(&mut this.io).poll_read(cx, buf);
        if let (Poll::Ready(Ok(())), Some(probe)) = (&poll, &this.probe)
            && let Some(bytes) = read_bytes(buf, filled)
        {
            probe.observe(ConnectionEvent::TlsRead {
                id: probe.id(),
                bytes,
            });
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for HandshakeTap<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.io).poll_write(cx, buf);
        if let (Poll::Ready(Ok(written)), Some(probe)) = (&poll, &this.probe) {
            for bytes in written_bytes(&[IoSlice::new(buf)], *written) {
                probe.observe(ConnectionEvent::TlsWrite {
                    id: probe.id(),
                    bytes,
                });
            }
        }
        poll
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.io).poll_write_vectored(cx, bufs);
        if let (Poll::Ready(Ok(written)), Some(probe)) = (&poll, &this.probe) {
            for bytes in written_bytes(bufs, *written) {
                probe.observe(ConnectionEvent::TlsWrite {
                    id: probe.id(),
                    bytes,
                });
            }
        }
        poll
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

// ===== impl Observed =====

impl<T: AsyncConnWithInfo> Observed<T> {
    /// Wraps a connected transport, reporting [`ConnectionEvent::Connected`] before any plaintext.
    pub(super) fn new(inner: T, probe: Probe) -> Observed<T> {
        // Addresses come from the `HttpInfo` extra that TCP transports attach, as for
        // `Response::remote_addr`.
        let mut extensions = Extensions::new();
        inner.connected().set_extras(&mut extensions);
        let info = extensions.get::<HttpInfo>();
        let ssl = inner.ssl();
        probe.observe(ConnectionEvent::Connected {
            id: probe.id(),
            local_addr: info.map(HttpInfo::local_addr),
            remote_addr: info.map(HttpInfo::remote_addr),
            alpn: ssl.and_then(SslRef::selected_alpn_protocol),
            tls_version: ssl.and_then(SslRef::version2).map(TlsVersion),
        });

        Observed { inner, probe }
    }
}

impl<T: Connection> Connection for Observed<T> {
    fn connected(&self) -> Connected {
        self.inner.connected().extra(self.probe.id())
    }
}

impl<T: TlsInfoFactory> TlsInfoFactory for Observed<T> {
    #[inline]
    fn ssl(&self) -> Option<&SslRef> {
        self.inner.ssl()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Observed<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let id = this.probe.id();
        let filled = buf.filled().len();
        let had_capacity = buf.remaining() != 0;
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        match &poll {
            Poll::Ready(Ok(())) => match read_bytes(buf, filled) {
                Some(bytes) => this.probe.observe(ConnectionEvent::Read { id, bytes }),
                None if had_capacity => this.probe.observe(ConnectionEvent::Eof { id }),
                None => {}
            },
            Poll::Ready(Err(error)) => this.probe.observe(ConnectionEvent::ReadError { id, error }),
            Poll::Pending => {}
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Observed<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.observe_write(&[IoSlice::new(buf)], &poll);
        poll
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.observe_write(bufs, &poll);
        poll
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_flush(cx);
        if let Poll::Ready(Err(error)) = &poll {
            let id = this.probe.id();
            this.probe
                .observe(ConnectionEvent::FlushError { id, error });
        }
        poll
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_shutdown(cx);
        if let Poll::Ready(Err(error)) = &poll {
            let id = this.probe.id();
            this.probe
                .observe(ConnectionEvent::ShutdownError { id, error });
        }
        poll
    }
}

impl<T> Observed<T> {
    fn observe_write(&self, bufs: &[IoSlice<'_>], poll: &Poll<io::Result<usize>>) {
        let id = self.probe.id();
        match poll {
            Poll::Ready(Ok(written)) => {
                for bytes in written_bytes(bufs, *written) {
                    self.probe.observe(ConnectionEvent::Write { id, bytes });
                }
            }
            Poll::Ready(Err(error)) => self
                .probe
                .observe(ConnectionEvent::WriteError { id, error }),
            Poll::Pending => {}
        }
    }
}

/// Returns the bytes a successful read appended after `filled`, if any.
///
/// A reader that shrinks the filled region violates the `AsyncRead` contract; such a read reports
/// nothing rather than panicking on the I/O task.
fn read_bytes<'a>(buf: &'a ReadBuf<'_>, filled: usize) -> Option<&'a [u8]> {
    buf.filled().get(filled..).filter(|bytes| !bytes.is_empty())
}

/// Splits the first `written` bytes of `bufs` into their non-empty slices.
fn written_bytes<'a>(bufs: &'a [IoSlice<'_>], written: usize) -> impl Iterator<Item = &'a [u8]> {
    bufs.iter()
        .scan(written, |left, buf| {
            if *left == 0 {
                return None;
            }
            let taken = (*left).min(buf.len());
            *left -= taken;
            Some(&buf[..taken])
        })
        .filter(|bytes| !bytes.is_empty())
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[derive(Default)]
    struct Events(Mutex<Vec<(ConnectionId, &'static str, Vec<u8>)>>);

    impl Events {
        fn take(&self) -> Vec<(ConnectionId, &'static str, Vec<u8>)> {
            std::mem::take(&mut self.0.lock().unwrap())
        }
    }

    impl ConnectionObserver for Events {
        fn observe(&self, event: ConnectionEvent<'_>) {
            let (kind, bytes): (_, &[u8]) = match event {
                ConnectionEvent::TlsHandshake { host, .. } => ("handshake", host.as_bytes()),
                ConnectionEvent::TlsWrite { bytes, .. } => ("tls_write", bytes),
                ConnectionEvent::TlsRead { bytes, .. } => ("tls_read", bytes),
                ConnectionEvent::Connected { .. } => ("connected", &[]),
                ConnectionEvent::Read { bytes, .. } => ("read", bytes),
                ConnectionEvent::Write { bytes, .. } => ("write", bytes),
                ConnectionEvent::Eof { .. } => ("eof", &[]),
                ConnectionEvent::ReadError { .. } => ("read_error", &[]),
                ConnectionEvent::WriteError { .. } => ("write_error", &[]),
                ConnectionEvent::FlushError { .. } => ("flush_error", &[]),
                ConnectionEvent::ShutdownError { .. } => ("shutdown_error", &[]),
                ConnectionEvent::Closed { .. } => ("closed", &[]),
            };
            self.0
                .lock()
                .unwrap()
                .push((event.id(), kind, bytes.to_vec()));
        }
    }

    /// Replays scripted reads and accepts at most three bytes per write until `fail` is set.
    #[derive(Default)]
    struct Mock {
        reads: VecDeque<Poll<io::Result<&'static [u8]>>>,
        fail: bool,
    }

    impl Mock {
        fn result(&self, len: usize) -> Poll<io::Result<usize>> {
            Poll::Ready(if self.fail {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(len.min(3))
            })
        }
    }

    impl Connection for Mock {
        fn connected(&self) -> Connected {
            Connected::new()
        }
    }

    impl TlsInfoFactory for Mock {}

    impl AsyncRead for Mock {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.reads.pop_front() {
                Some(Poll::Ready(Ok(bytes))) => {
                    buf.put_slice(bytes);
                    Poll::Ready(Ok(()))
                }
                Some(Poll::Ready(Err(error))) => Poll::Ready(Err(error)),
                Some(Poll::Pending) => Poll::Pending,
                None => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for Mock {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.result(buf.len())
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            self.result(bufs.iter().map(|buf| buf.len()).sum())
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.result(0).map_ok(drop)
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.result(0).map_ok(drop)
        }
    }

    #[tokio::test]
    async fn reports_each_layer_until_the_connection_is_released() {
        let events = Arc::new(Events::default());
        let probe = Probe::new(events.clone());
        let id = probe.id();

        // The handshake layer reports records until the handshake finishes.
        let mut tap = HandshakeTap::new(
            Mock {
                reads: VecDeque::from([Poll::Ready(Ok(b"hello".as_slice()))]),
                fail: false,
            },
            Some(probe.clone()),
            "example.com",
        );
        assert_eq!(tap.write(b"client").await.unwrap(), 3);
        assert_eq!(tap.read(&mut [0; 8]).await.unwrap(), 5);
        tap.finish();
        tap.write_all(b"secret").await.unwrap();
        drop(tap);

        // The plaintext layer reports only new bytes and accepted prefixes.
        let mut io = Observed::new(
            Mock {
                reads: VecDeque::from([
                    Poll::Pending,
                    Poll::Ready(Ok(b"new".as_slice())),
                    Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
                ]),
                fail: false,
            },
            probe.clone(),
        );
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut storage = [0; 16];
        let mut buf = ReadBuf::new(&mut storage);
        buf.put_slice(b"old");
        for _ in 0..4 {
            let _ = Pin::new(&mut io).poll_read(&mut cx, &mut buf);
        }
        // A read without capacity is not an EOF.
        let _ = Pin::new(&mut io).poll_read(&mut cx, &mut ReadBuf::new(&mut []));
        assert_eq!(io.write(b"12345").await.unwrap(), 3);
        let bufs = [
            IoSlice::new(b"ab"),
            IoSlice::new(b""),
            IoSlice::new(b"cdef"),
        ];
        assert_eq!(io.write_vectored(&bufs).await.unwrap(), 3);

        // Failures are reported without changing them.
        io.inner.fail = true;
        assert!(io.write(b"x").await.is_err());
        assert!(io.flush().await.is_err());
        assert!(io.shutdown().await.is_err());

        // Responses carry the connection id.
        let mut extensions = Extensions::new();
        io.connected().set_extras(&mut extensions);
        assert_eq!(extensions.get::<ConnectionId>(), Some(&id));

        // Another holder of the probe keeps the connection open.
        drop(io);
        let observed = events.take();
        assert!(observed.iter().all(|(event_id, ..)| *event_id == id));
        let observed: Vec<_> = observed
            .into_iter()
            .map(|(_, kind, bytes)| (kind, bytes))
            .collect();
        assert_eq!(
            observed,
            [
                ("handshake", b"example.com".to_vec()),
                ("tls_write", b"cli".to_vec()),
                ("tls_read", b"hello".to_vec()),
                ("connected", vec![]),
                ("read", b"new".to_vec()),
                ("read_error", vec![]),
                ("eof", vec![]),
                ("write", b"123".to_vec()),
                ("write", b"ab".to_vec()),
                ("write", b"c".to_vec()),
                ("write_error", vec![]),
                ("flush_error", vec![]),
                ("shutdown_error", vec![]),
            ]
        );

        drop(probe);
        assert_eq!(events.take(), [(id, "closed", vec![])]);
    }

    #[test]
    fn closed_panic_does_not_abort_unwinding() {
        struct Panicking;

        impl ConnectionObserver for Panicking {
            fn observe(&self, _: ConnectionEvent<'_>) {
                panic!("observer panic");
            }
        }

        drop(Probe::new(Arc::new(Panicking)));
        let panic = std::panic::catch_unwind(|| {
            let _probe = Probe::new(Arc::new(Panicking));
            panic!("original panic");
        })
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"original panic"));
    }
}
