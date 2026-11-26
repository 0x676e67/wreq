//! Tokio runtime adapter for wreq.

// Hickory replaces the system resolver when it is compiled in.
cfg_select! {
    all(
        feature = "hickory-dns",
        feature = "tokio-rt",
        not(feature = "compio-rt")
    ) => {
        use crate::dns::hickory::HickoryResolver as Resolver;
    }
    _ => {
        mod gai;
        use self::gai::GaiResolver as Resolver;
    }
}

use std::{
    future::Future,
    io,
    net::{SocketAddr, TcpStream},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use futures_util::future::{BoxFuture, TryFutureExt};
use pin_project_lite::pin_project;
use tokio::net::TcpSocket;

use crate::{
    dns::Resolve,
    rt::{BoxSleep, Connecting, Connection, Executor, Runtime, Sleep, Timer},
};

/// Runtime that uses Tokio for task execution, timers, DNS and socket I/O.
/// DNS uses Hickory with `hickory-dns` (unless `compio-rt` is enabled), else the system resolver.
///
/// Tasks and sockets use the Tokio runtime current at each call. Direct HTTP/3 connections with
/// the client's bindings share a QUIC endpoint per address family. Keep the runtime that created
/// the endpoint running while other runtimes use it (a `current_thread` runtime runs only inside
/// `block_on`), or use one client per runtime.
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

impl Executor for TokioRuntime {
    #[inline]
    fn execute(&self, task: BoxFuture<'static, ()>) {
        ::tokio::spawn(task);
    }
}

impl Runtime for TokioRuntime {
    #[inline]
    fn resolver(&self) -> Arc<dyn Resolve> {
        Arc::new(Resolver)
    }

    #[inline]
    fn connect_tcp(&self, socket: TcpStream, addr: SocketAddr) -> Connecting {
        Box::pin(
            TcpSocket::from_std_stream(socket)
                .connect(addr)
                .map_ok(|stream| Box::new(stream) as _),
        )
    }

    #[inline]
    #[cfg(unix)]
    fn connect_unix(&self, path: Arc<std::path::Path>) -> Connecting {
        Box::pin(::tokio::net::UnixStream::connect(path).map_ok(|stream| Box::new(stream) as _))
    }

    #[inline]
    #[cfg(feature = "http3")]
    fn udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Box<dyn super::AsyncUdpSocket>> {
        ::quic::Runtime::wrap_udp_socket(&::quic::TokioRuntime, socket)
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
