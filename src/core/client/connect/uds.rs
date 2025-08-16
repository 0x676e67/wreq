use std::{
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::Uri;
use tokio::net::UnixStream;

use super::{Connected, Connection};
use crate::core::rt::TokioIo;

type ConnectResult = Result<TokioIo<UnixStream>, std::io::Error>;
type BoxConnecting = Pin<Box<dyn Future<Output = ConnectResult> + Send>>;

#[derive(Clone)]
pub struct UnixConnector(pub(crate) Arc<Path>);

impl tower::Service<Uri> for UnixConnector {
    type Response = TokioIo<UnixStream>;
    type Error = std::io::Error;
    type Future = BoxConnecting;

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

impl Connection for UnixStream {
    #[inline]
    fn connected(&self) -> Connected {
        Connected::new()
    }
}
