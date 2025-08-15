use std::{
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::Uri;
use pin_project_lite::pin_project;
use tokio::net::UnixStream;

use super::{Connected, Connection};
use crate::core::rt::TokioIo;

pub type UnixConnectOptions = Option<Arc<Path>>;

pub struct UnixConnector(pub Arc<Path>);

impl tower::Service<Uri> for UnixConnector {
    type Response = TokioIo<UnixStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let fut = UnixStream::connect(self.0.clone());
        Box::pin(async move {
            let io = fut.await?;
            Ok::<_, std::io::Error>(TokioIo::new(io))
        })
    }
}

type ConnectResult = Result<TokioIo<UnixStream>, std::io::Error>;
type BoxConnecting = Pin<Box<dyn Future<Output = ConnectResult> + Send>>;

pin_project! {
    // Not publicly exported (so missing_docs doesn't trigger).
    //
    // We return this `Future` instead of the `Pin<Box<dyn Future>>` directly
    // so that users don't rely on it fitting in a `Pin<Box<dyn Future>>` slot
    // (and thus we can change the type in the future).
    #[must_use = "futures do nothing unless polled"]
    pub struct UnixConnecting {
        #[pin]
        fut: BoxConnecting,
    }
}

impl Connection for UnixStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}
