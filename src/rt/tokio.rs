//! Tokio runtime adapter for wreq.

// Hickory replaces the system resolver when it is compiled in.
cfg_select! {
    all(
        feature = "hickory-dns",
        feature = "tokio-rt",
        not(feature = "compio-rt")
    ) => {
        use crate::dns::hickory::HickoryDnsResolver as Resolver;
    }
    _ => {
        mod gai;
        use self::gai::GaiResolver as Resolver;
    }
}

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
///
/// Tasks and sockets use the Tokio runtime current at each call. With HTTP/3, a client's
/// connections share one QUIC endpoint per address family, driven on the runtime of the first
/// HTTP/3 connection. Keep that runtime running while other runtimes open HTTP/3 connections (a
/// `current_thread` runtime runs only inside `block_on`), or use one client per runtime.
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
        Arc::new(Resolver)
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
