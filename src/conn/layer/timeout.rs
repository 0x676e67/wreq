//! Runtime-neutral timeout middleware for connector services.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use tower::{BoxError, Layer, Service};

use crate::{
    error::TimedOut,
    rt::{BoxSleep, RuntimeHandle, Timer},
};

/// Adds a connection timeout using the client's timer provider.
/// The timer starts when the service is called.
#[derive(Clone)]
pub(in crate::conn) struct TimeoutLayer {
    timer: Arc<dyn Timer>,
    timeout: Option<Duration>,
}

/// Creates a separate deadline for each connection attempt.
/// Readiness waits before `call` are outside the deadline.
#[derive(Clone)]
pub struct Timeout<S> {
    inner: S,
    timer: Arc<dyn Timer>,
    timeout: Option<Duration>,
}

pin_project! {
    /// Owns one in-flight connection and its optional timeout sleep.
    ///
    /// The connection is polled first; while it remains pending, the sleep can end the attempt.
    /// Dropping this future drops both operations.
    pub struct TimeoutFuture<F> {
        #[pin]
        future: F,
        sleep: Option<BoxSleep>,
    }
}

// ===== impl TimeoutLayer =====

impl TimeoutLayer {
    pub(in crate::conn) fn new(runtime: RuntimeHandle, timeout: Option<Duration>) -> Self {
        Self {
            timer: runtime.timer(),
            timeout,
        }
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = Timeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Timeout {
            inner,
            timer: self.timer.clone(),
            timeout: self.timeout,
        }
    }
}

// ===== impl Timeout =====

impl<S, Request> Service<Request> for Timeout<S>
where
    S: Service<Request>,
    S::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = TimeoutFuture<S::Future>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let future = self.inner.call(request);
        let sleep = self.timeout.map(|timeout| self.timer.sleep(timeout));
        TimeoutFuture::new(future, sleep)
    }
}

// ===== impl TimeoutFuture =====

impl<F> TimeoutFuture<F> {
    pub(in crate::conn) fn new(future: F, sleep: Option<BoxSleep>) -> Self {
        Self { future, sleep }
    }
}

impl<F, T, E> Future for TimeoutFuture<F>
where
    F: Future<Output = Result<T, E>>,
    E: Into<BoxError>,
{
    type Output = Result<T, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.future.poll(cx) {
            Poll::Ready(result) => return Poll::Ready(result.map_err(Into::into)),
            Poll::Pending => {}
        }

        if let Some(sleep) = this.sleep.as_mut()
            && Pin::new(&mut *sleep).poll(cx).is_ready()
        {
            return Poll::Ready(Err(Box::new(TimedOut)));
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::{future::pending, task::Waker, time::Instant};

    use futures_util::future::BoxFuture;

    use super::*;
    use crate::rt::Sleep;

    #[derive(Clone, Debug)]
    struct ReadyRuntime;

    struct ReadySleep;

    impl crate::rt::Timer for ReadyRuntime {
        fn sleep(&self, _duration: Duration) -> BoxSleep {
            BoxSleep::new(ReadySleep)
        }

        fn sleep_until(&self, _deadline: Instant) -> BoxSleep {
            BoxSleep::new(ReadySleep)
        }
    }

    impl crate::rt::Runtime for ReadyRuntime {
        fn execute(&self, _future: BoxFuture<'static, ()>) {
            panic!("a connection timeout must not spawn a task");
        }

        fn resolver(&self) -> std::sync::Arc<dyn crate::dns::Resolve> {
            crate::rt::tokio::TokioRuntime.resolver()
        }

        fn connect_tcp(
            &self,
            socket: std::net::TcpStream,
            address: std::net::SocketAddr,
        ) -> crate::rt::Connecting {
            crate::rt::tokio::TokioRuntime.connect_tcp(socket, address)
        }

        #[cfg(unix)]
        fn connect_unix(&self, path: std::sync::Arc<std::path::Path>) -> crate::rt::Connecting {
            crate::rt::tokio::TokioRuntime.connect_unix(path)
        }
    }

    impl Future for ReadySleep {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(())
        }
    }

    impl Sleep for ReadySleep {
        fn reset(self: Pin<&mut Self>, _new_deadline: Instant) {}
    }

    #[test]
    fn connect_timeout_uses_selected_runtime_without_ambient_runtime() {
        let mut service = TimeoutLayer::new(
            RuntimeHandle::new(ReadyRuntime),
            Some(Duration::from_millis(50)),
        )
        .layer(tower::service_fn(|()| pending::<Result<(), BoxError>>()));

        let mut future = std::pin::pin!(service.call(()));
        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready(Err(error)) = future.as_mut().poll(&mut cx) else {
            panic!("connect timeout did not complete");
        };

        assert!(error.is::<TimedOut>());
    }
}
