//! Lazily creates physical connections under the pool's reuse policy.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{self, Poll},
    time::Duration,
};

use futures_util::future::BoxFuture;
use tower::{BoxError, Service, util::Oneshot};

use super::{PoolTarget, TransportConnector, cache::Started};
use crate::{
    client::proto::Established,
    conn::Conn,
    rt::{DynRuntime, Timer as _},
};

/// Lazily creates physical connections under the configured reuse policy.
///
/// The maker defers every expensive step until its future is polled. It may wait
/// for a reuse-first window, then runs a cloned connector through `Oneshot` so
/// readiness and `call` use the same service instance.
#[derive(Clone)]
pub(super) struct ConnectionMaker<C> {
    /// Physical transport connector.
    pub(super) connector: C,

    /// Optional delay giving connection reuse time to win.
    pub(super) reuse_delay: Option<Duration>,

    /// Clock shared by reuse waits and transport timestamps.
    pub(super) runtime: DynRuntime,
}

/// Connection-maker future with explicit started-work tracking.
///
/// `polled` distinguishes a never-started checkout from one that has entered
/// policy work. When `started` is present, it becomes true immediately before
/// the physical connector is awaited. The HTTP/1 cache uses this distinction to
/// decide whether a lost reuse race is worth completing in the background.
pub(super) struct MakeFuture<T> {
    /// Deferred delay and physical connect work.
    future: BoxFuture<'static, Result<T, BoxError>>,

    /// Records whether the future has ever been polled.
    polled: bool,

    /// Separates waiting for policy from useful connection work.
    started: Option<Arc<AtomicBool>>,
}

// ===== impl ConnectionMaker =====

impl<C> Service<PoolTarget> for ConnectionMaker<C>
where
    C: TransportConnector,
{
    type Response = Established;
    type Error = BoxError;
    type Future = MakeFuture<Self::Response>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: PoolTarget) -> Self::Future {
        let PoolTarget {
            req,
            wait_for_reuse,
        } = target;
        let reuse_delay = if wait_for_reuse {
            self.reuse_delay
        } else {
            None
        };
        let started = reuse_delay
            .is_some()
            .then(|| Arc::new(AtomicBool::new(false)));
        let start_signal = started.clone();
        let connector = self.connector.clone();
        let runtime = self.runtime.clone();

        let future = Box::pin(async move {
            if let Some(duration) = reuse_delay {
                runtime.sleep(duration).await;
            }

            if let Some(started) = &start_signal {
                started.store(true, Ordering::Release);
            }

            let Conn {
                transport,
                connected,
            } = Oneshot::new(connector, req).await?;

            Ok(Established::new(
                transport.into_stream()?,
                connected,
                #[cfg(feature = "http2")]
                runtime.now(),
            ))
        });

        MakeFuture {
            future,
            polled: false,
            started,
        }
    }
}

// ===== impl MakeFuture =====

impl<T> Future for MakeFuture<T> {
    type Output = Result<T, BoxError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.polled = true;
        self.future.as_mut().poll(cx)
    }
}

impl<T> Started for MakeFuture<T> {
    fn started(&self) -> bool {
        self.started
            .as_ref()
            .map_or(self.polled, |started| started.load(Ordering::Acquire))
    }
}
