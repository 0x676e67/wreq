//! Compio runtime adapter for wreq.

mod future;
mod gai;
mod io;

#[cfg(unix)]
use std::path::Path;
use std::{
    fmt::{self, Debug, Formatter},
    future::Future,
    net::{SocketAddr, TcpStream},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

#[cfg(unix)]
use ::compio::net::UnixStream;
use ::compio::{net::TcpSocket, runtime, time};
use futures_util::future::{BoxFuture, LocalBoxFuture};
use send_wrapper::SendWrapper;

use self::{future::SendFuture, gai::GaiResolver, io::Compat};
use crate::{
    dns::Resolve,
    rt::{BoxConnection, BoxSleep, Connecting, Runtime, Sleep, Timer},
};

/// Runtime that uses Compio for task execution, timers, system DNS and socket I/O.
/// UDP sockets are not supported yet, so HTTP/3 connections fail with an unsupported error.
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
        self.sleep_until(crate::util::deadline_after(self.now(), duration))
    }

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
