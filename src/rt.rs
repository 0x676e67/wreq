//! Runtime components selected by `Client::builder`.
//!
//! Implement [`Runtime`] to supply task execution, timers, DNS resolution and socket I/O.

mod handle;

#[cfg(feature = "compio-rt")]
pub mod compio;
#[cfg(any(test, feature = "tokio-rt"))]
pub mod tokio;

use std::{
    fmt::{self, Debug, Formatter},
    future::Future,
    io,
    net::{SocketAddr, TcpStream},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use ::tokio::io::{AsyncRead, AsyncWrite};
use futures_util::future::BoxFuture;
use pin_project_lite::pin_project;

pub(crate) use self::handle::RuntimeHandle;
use crate::dns::Resolve;

/// Runtime facilities selected when constructing a client.
///
/// Supplies background execution, timers through [`Timer`], socket I/O and a default
/// DNS resolver. Blocking DNS lookups should be offloaded by the resolver implementation.
/// Callers can replace the resolver with
/// [`ClientBuilder::dns_resolver`](crate::ClientBuilder::dns_resolver).
pub trait Runtime: Timer + Send + Sync + Debug + 'static {
    /// Schedules a task to run in the background.
    #[track_caller]
    fn execute(&self, fut: BoxFuture<'static, ()>);

    /// Returns the resolver used unless the client builder overrides DNS.
    fn resolver(&self) -> Arc<dyn Resolve>;

    /// Connects an unconnected, nonblocking socket to `address`.
    /// The socket already has the client's TCP and local binding options applied.
    fn connect_tcp(&self, socket: TcpStream, address: SocketAddr) -> Connecting;

    /// Connects a Unix domain socket.
    #[cfg(unix)]
    fn connect_unix(&self, path: Arc<std::path::Path>) -> Connecting;

    /// Registers a bound, nonblocking UDP socket for HTTP/3 over QUIC.
    /// Defaults to an [`Unsupported`](io::ErrorKind::Unsupported) error, which fails
    /// HTTP/3 connections without affecting HTTP/1 or HTTP/2.
    ///
    /// A client reuses the socket for later HTTP/3 connections, so the task it then spawns with
    /// [`execute`](Self::execute) to receive on the socket must keep running while the client
    /// opens them.
    #[cfg(feature = "http3")]
    fn udp_socket(
        &self,
        _socket: std::net::UdpSocket,
    ) -> io::Result<Box<dyn ::quic::AsyncUdpSocket>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "runtime does not support UDP sockets",
        ))
    }
}

impl_into_shared!(
    /// Accepts a runtime value or an existing shared runtime for a client.
    pub trait IntoRuntime => Runtime
);

/// An established transport with address metadata and socket controls.
/// By default, transports report no IP addresses and ignore TCP options.
pub trait Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {
    /// Returns the peer socket address, when available.
    /// Defaults to `None`.
    /// SOCKS5 UDP needs it when the proxy returns an unspecified relay address.
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Returns the local socket address, when available.
    /// Defaults to `None`.
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Sets TCP_NODELAY, including restoring the option after a TLS handshake.
    /// Defaults to a no-op; TCP transports should override this method.
    fn set_nodelay(&self, _value: bool) -> io::Result<()> {
        Ok(())
    }
}

/// An established connection returned by a runtime.
pub type BoxConnection = Box<dyn Connection>;

/// A pending runtime connection attempt.
pub type Connecting = BoxFuture<'static, io::Result<BoxConnection>>;

/// Creates sleeps using the selected runtime's clock.
/// Deadlines and [`Timer::now`] must use the same clock.
pub trait Timer: Send + Sync {
    /// Returns a future that completes after `duration`.
    /// Oversized durations must not panic; Tokio caps them at about 30 years.
    fn sleep(&self, duration: Duration) -> BoxSleep;

    /// Returns a future that completes at `deadline`.
    fn sleep_until(&self, deadline: Instant) -> BoxSleep;

    /// Returns the current time; override this when using a simulated clock.
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A resettable timer future. Dropping it cancels the wait.
pub trait Sleep: Future<Output = ()> + Send + Sync {
    /// Sets a new deadline, allowing the future to be polled again after completion.
    fn reset(self: Pin<&mut Self>, deadline: Instant);
}

/// An owned, resettable sleep returned by a [`Timer`].
/// Moving this handle keeps the underlying future pinned; dropping it cancels the wait.
/// Construction adapts and boxes the concrete sleep in one allocation.
pub struct BoxSleep {
    inner: Pin<Box<dyn netty::rt::Sleep>>,
}

pin_project! {
    /// Adapts a concrete sleep before boxing it for the protocol timer interface.
    /// The inner future stays pinned while polling and resetting; no runtime is retained.
    struct SleepAdapter<S> {
        #[pin]
        inner: S,
    }
}

// ===== impl Connection =====

impl Debug for dyn Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("local_addr", &self.local_addr())
            .field("peer_addr", &self.peer_addr())
            .finish_non_exhaustive()
    }
}

// ===== impl BoxSleep =====

impl BoxSleep {
    /// Adapts and pins a concrete sleep without an intermediate allocation.
    #[inline]
    pub fn new<S: Sleep + 'static>(sleep: S) -> Self {
        Self {
            inner: Box::pin(SleepAdapter { inner: sleep }),
        }
    }

    /// Sets a new deadline, including after completion, without replacing the outer allocation.
    #[inline]
    pub fn reset(&mut self, deadline: Instant) {
        self.inner.as_mut().reset(deadline);
    }

    #[inline]
    fn into_inner(self) -> Pin<Box<dyn netty::rt::Sleep>> {
        self.inner
    }
}

impl Future for BoxSleep {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

#[cfg(feature = "http3")]
impl ::quic::AsyncTimer for BoxSleep {
    #[inline]
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.get_mut().reset(deadline);
    }

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Future::poll(self, cx)
    }
}

impl Debug for BoxSleep {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoxSleep").finish_non_exhaustive()
    }
}

// ===== impl SleepAdapter =====

impl<S: Sleep> Future for SleepAdapter<S> {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.project().inner.poll(cx)
    }
}

impl<S: Sleep> netty::rt::Sleep for SleepAdapter<S> {
    #[inline]
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.project().inner.reset(deadline);
    }
}
