//! Tokio runtime adapter for wreq.

#[cfg(not(all(
    feature = "hickory-dns",
    feature = "tokio-rt",
    not(feature = "compio-rt")
)))]
mod gai;

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures_util::future::BoxFuture;
use pin_project_lite::pin_project;

use crate::{
    dns::Resolve,
    rt::{BoxConnection, BoxSleep, Connecting, Connection, Sleep, Timer},
};

/// Runtime that uses Tokio for task execution, timers, DNS and socket I/O.
/// DNS uses Hickory with `hickory-dns` (unless `compio-rt` is enabled), else the system resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioRuntime;

// Project the pinned Tokio sleep in place; BoxSleep provides its single allocation.
// Tokio's Sleep remains !Unpin: https://docs.rs/tokio/latest/tokio/time/struct.Sleep.html
pin_project! {
    #[derive(Debug)]
    struct TokioSleep {
        #[pin]
        inner: ::tokio::time::Sleep,
    }
}

// ===== impl TokioRuntime =====

impl Timer for TokioRuntime {
    #[inline]
    fn sleep(&self, duration: Duration) -> BoxSleep {
        BoxSleep::new(TokioSleep {
            inner: ::tokio::time::sleep(duration),
        })
    }

    #[inline]
    fn sleep_until(&self, deadline: Instant) -> BoxSleep {
        BoxSleep::new(TokioSleep {
            inner: ::tokio::time::sleep_until(deadline.into()),
        })
    }

    #[inline]
    fn now(&self) -> Instant {
        ::tokio::time::Instant::now().into()
    }
}

impl super::Runtime for TokioRuntime {
    #[inline]
    fn execute(&self, task: BoxFuture<'static, ()>) {
        ::tokio::spawn(task);
    }

    #[inline]
    fn resolver(&self) -> Arc<dyn Resolve> {
        #[cfg(all(
            feature = "hickory-dns",
            feature = "tokio-rt",
            not(feature = "compio-rt")
        ))]
        let resolver = crate::dns::hickory::HickoryDnsResolver::new();
        #[cfg(not(all(
            feature = "hickory-dns",
            feature = "tokio-rt",
            not(feature = "compio-rt")
        )))]
        let resolver = gai::GaiResolver::new();
        Arc::new(resolver)
    }

    #[inline]
    fn connect_tcp(
        &self,
        socket: std::net::TcpStream,
        address: std::net::SocketAddr,
    ) -> Connecting {
        Box::pin(async move {
            let stream = ::tokio::net::TcpSocket::from_std_stream(socket)
                .connect(address)
                .await?;
            Ok(Box::new(stream) as BoxConnection)
        })
    }

    #[inline]
    #[cfg(unix)]
    fn connect_unix(&self, path: Arc<std::path::Path>) -> Connecting {
        Box::pin(async move {
            let stream = ::tokio::net::UnixStream::connect(path).await?;
            Ok(Box::new(stream) as BoxConnection)
        })
    }

    #[inline]
    #[cfg(feature = "http3")]
    fn udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Box<dyn ::quic::AsyncUdpSocket>> {
        use ::quic::Runtime as _;
        ::quic::TokioRuntime.wrap_udp_socket(socket)
    }
}

// ===== impl TokioSleep =====

impl Future for TokioSleep {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

impl Sleep for TokioSleep {
    #[inline]
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.project().inner.reset(deadline.into());
    }
}

// ===== impl TcpStream =====

impl Connection for ::tokio::net::TcpStream {
    #[inline]
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.peer_addr().ok()
    }

    #[inline]
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.local_addr().ok()
    }

    #[inline]
    fn set_nodelay(&self, value: bool) -> io::Result<()> {
        self.set_nodelay(value)
    }
}

// ===== impl UnixStream =====

#[cfg(unix)]
impl Connection for ::tokio::net::UnixStream {}

#[cfg(test)]
mod tests {
    use super::*;

    #[::tokio::test]
    async fn tcp_controls_use_connected_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = ::tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_, peer) = listener.accept().unwrap();
        let connection: &dyn Connection = &stream;
        assert_eq!(connection.local_addr(), Some(peer));
        assert_eq!(connection.peer_addr(), Some(listener.local_addr().unwrap()));
        for value in [true, false] {
            connection.set_nodelay(value).unwrap();
            assert_eq!(stream.nodelay().unwrap(), value);
        }
    }
}
