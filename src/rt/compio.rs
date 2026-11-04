//! Compio runtime adapter for wreq.

#[cfg(not(feature = "http3"))]
mod future;
#[cfg(not(feature = "http3"))]
mod gai;
#[cfg(not(feature = "http3"))]
mod io;

#[cfg(all(unix, not(feature = "http3")))]
use std::path::Path;
use std::{
    fmt::{self, Debug, Formatter},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
#[cfg(not(feature = "http3"))]
use std::{
    net::{SocketAddr, TcpStream},
    sync::Arc,
};

#[cfg(all(unix, not(feature = "http3")))]
use ::compio::net::UnixStream;
use ::compio::time;
#[cfg(not(feature = "http3"))]
use ::compio::{net::TcpSocket, runtime};
#[cfg(not(feature = "http3"))]
use futures_util::future::BoxFuture;
use futures_util::future::LocalBoxFuture;
use send_wrapper::SendWrapper;

#[cfg(not(feature = "http3"))]
use self::{future::SendFuture, gai::GaiResolver, io::Compat};
use crate::rt::{BoxSleep, Sleep, Timer};
#[cfg(not(feature = "http3"))]
use crate::{
    dns::Resolve,
    rt::{BoxConnection, Connecting, Runtime},
};

/// Runtime that uses Compio for task execution, timers, system DNS and socket I/O.
/// Implements [`super::Runtime`] when HTTP/3 is disabled; its QUIC backend is not yet available.
/// Poll and drop its futures and streams on the Compio thread that created them.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompioRuntime;

/// A Compio timer bound to its creating runtime thread.
/// SendWrapper checks thread affinity; the boxed anonymous future can be replaced on reset.
struct CompioSleep {
    inner: SendWrapper<LocalBoxFuture<'static, ()>>,
}

// ===== impl CompioRuntime =====

impl Timer for CompioRuntime {
    #[inline]
    fn sleep(&self, duration: Duration) -> BoxSleep {
        BoxSleep::new(CompioSleep::new(time::sleep(duration)))
    }

    #[inline]
    fn sleep_until(&self, deadline: Instant) -> BoxSleep {
        BoxSleep::new(CompioSleep::new(time::sleep_until(deadline)))
    }
}

#[cfg(not(feature = "http3"))]
impl Runtime for CompioRuntime {
    #[inline]
    fn new_timer(&self) -> Arc<dyn Timer> {
        Arc::new(*self)
    }

    #[inline]
    fn execute(&self, task: BoxFuture<'static, ()>) {
        runtime::spawn(task).detach();
    }

    #[inline]
    fn resolver(&self) -> Arc<dyn Resolve> {
        Arc::new(GaiResolver::new())
    }

    #[inline]
    fn connect_tcp(&self, socket: TcpStream, address: SocketAddr) -> Connecting {
        Box::pin(SendFuture::new(async move {
            let stream = TcpSocket::from_std_stream(socket)?.connect(address).await?;
            Ok(Box::new(Compat::new(stream)) as BoxConnection)
        }))
    }

    #[inline]
    #[cfg(unix)]
    fn connect_unix(&self, path: Arc<Path>) -> Connecting {
        Box::pin(SendFuture::new(async move {
            let stream = UnixStream::connect(path).await?;
            Ok(Box::new(Compat::new(stream)) as BoxConnection)
        }))
    }
}

// ===== impl CompioSleep =====

impl CompioSleep {
    #[inline]
    fn new<Fut>(fut: Fut) -> Self
    where
        Fut: Future<Output = ()> + 'static,
    {
        Self {
            inner: SendWrapper::new(Box::pin(fut)),
        }
    }
}

impl Future for CompioSleep {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

impl Sleep for CompioSleep {
    #[inline]
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.get_mut().inner = SendWrapper::new(Box::pin(time::sleep_until(deadline)));
    }
}

impl Debug for CompioSleep {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompioSleep").finish()
    }
}
