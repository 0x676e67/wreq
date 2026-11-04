//! Unix Domain Socket (UDS) connector.

use std::{
    io,
    path::Path,
    sync::Arc,
    task::{Context, Poll},
};

use http::Uri;
use tower::Service;

use crate::rt::{BoxConnection, Connecting, RuntimeHandle};

/// Connects a Unix socket through the runtime selected by the client.
#[derive(Clone)]
pub struct UnixConnector {
    runtime: RuntimeHandle,
    path: Arc<Path>,
}

impl UnixConnector {
    pub(crate) fn new(path: Arc<Path>, runtime: RuntimeHandle) -> Self {
        Self { path, runtime }
    }
}

impl Service<Uri> for UnixConnector {
    type Response = BoxConnection;
    type Error = io::Error;
    type Future = Connecting;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        self.runtime.connect_unix(self.path.clone())
    }
}
