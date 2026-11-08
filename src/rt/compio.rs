//! Compio runtime adapter for wreq.

mod future;
mod gai;
mod io;

use std::{
    fmt::{self, Debug, Formatter},
    future::Future,
    net::{SocketAddr, TcpStream},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Instant,
};

use ::compio::{net::TcpSocket, runtime, time};
use futures_util::future::{BoxFuture, LocalBoxFuture};
use send_wrapper::SendWrapper;
#[cfg(unix)]
use {::compio::net::UnixStream, std::path::Path};

use self::{future::SendFuture, gai::GaiResolver, io::Compat};
use crate::{
    dns::Resolve,
    rt::{BoxConnection, BoxSleep, Connecting, Runtime, Sleep, Timer},
};

/// Runtime that uses Compio for task execution, timers, system DNS and socket I/O.
/// UDP sockets are not supported yet, so HTTP/3 connections fail with an unsupported error.
///
/// Compio is thread-per-core, and a client's clones share one pool that hands connections
/// and timers between requests. Keep a client, its clones, futures and responses on one
/// Compio runtime thread, and build one client per thread. Use from another thread or
/// outside a Compio runtime panics, as Tokio does outside a runtime.
///
/// Socket writes are buffered until a flush or the next read; flush upgraded connections as
/// `AsyncWrite` requires.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompioRuntime;

/// A fused Compio timer bound to its creating runtime thread.
/// Compio's sleep is an `async fn` that panics if resumed after completion, so the finished
/// future is dropped and later polls stay ready until `reset` arms a new one.
struct CompioSleep {
    inner: Option<SendWrapper<LocalBoxFuture<'static, ()>>>,
}

// ===== impl CompioRuntime =====

impl Timer for CompioRuntime {
    #[inline]
    fn sleep_until(&self, deadline: Instant) -> BoxSleep {
        BoxSleep::new(CompioSleep::new(time::sleep_until(deadline)))
    }
}

impl Runtime for CompioRuntime {
    #[inline]
    fn execute(&self, task: BoxFuture<'static, ()>) {
        runtime::spawn(task).detach();
    }

    #[inline]
    fn try_execute(&self, task: BoxFuture<'static, ()>) -> Result<(), BoxFuture<'static, ()>> {
        let Some(current) = runtime::Runtime::try_current() else {
            return Err(task);
        };
        current.spawn(task).detach();
        Ok(())
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
            inner: Some(SendWrapper::new(Box::pin(fut))),
        }
    }
}

impl Future for CompioSleep {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(sleep) = &mut this.inner {
            ready!(sleep.as_mut().poll(cx));
            this.inner = None;
        }
        Poll::Ready(())
    }
}

impl Sleep for CompioSleep {
    #[inline]
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.get_mut().inner = Some(SendWrapper::new(Box::pin(time::sleep_until(deadline))));
    }
}

impl Debug for CompioSleep {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompioSleep").finish()
    }
}
