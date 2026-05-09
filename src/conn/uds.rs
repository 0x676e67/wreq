#![allow(dead_code)]

#[cfg(feature = "tokio-rt")]
use std::{
    io,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[cfg(feature = "tokio-rt")]
use http::Uri;
#[cfg(feature = "tokio-rt")]
use tokio::net::UnixStream;

#[cfg(feature = "tokio-rt")]
use super::{Connected, Connection};

#[cfg(feature = "tokio-rt")]
type ConnectResult = io::Result<UnixStream>;
#[cfg(feature = "tokio-rt")]
type BoxConnecting = Pin<Box<dyn Future<Output = ConnectResult> + Send>>;

#[cfg(feature = "tokio-rt")]
#[derive(Clone)]
pub struct UnixConnector {
    path: Arc<Path>,
}

#[cfg(feature = "tokio-rt")]
impl UnixConnector {
    pub fn new(path: impl Into<Arc<Path>>) -> Self {
        Self { path: path.into() }
    }
}

#[cfg(feature = "tokio-rt")]
impl tower::Service<Uri> for UnixConnector {
    type Response = UnixStream;
    type Error = io::Error;
    type Future = BoxConnecting;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let fut = UnixStream::connect(self.path.clone());
        Box::pin(async move {
            let io = fut.await?;
            Ok::<_, io::Error>(io)
        })
    }
}

#[cfg(feature = "tokio-rt")]
impl Connection for UnixStream {
    #[inline]
    fn connected(&self) -> Connected {
        Connected::new()
    }
}
