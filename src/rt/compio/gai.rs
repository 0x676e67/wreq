// This module contains the `GaiResolver` implementation for the `compio` runtime.

use std::{
    future::Future,
    io,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    task::{Context, Poll},
    vec::IntoIter,
};

use compio::runtime::{JoinHandle, spawn_blocking};
use tower::Service;

use crate::dns::{Addrs, Name, Resolve, Resolving};

/// A system resolver that offloads lookups to the Compio thread pool.
#[derive(Clone, Default)]
pub(super) struct GaiResolver {
    _priv: (),
}

/// A future to resolve a name returned by `GaiResolver`.
pub(super) struct GaiFuture(JoinHandle<io::Result<IntoIter<SocketAddr>>>);

// ===== impl GaiResolver =====

impl GaiResolver {
    /// Creates a new [`GaiResolver`].
    pub(super) fn new() -> Self {
        GaiResolver { _priv: () }
    }
}

impl Service<Name> for GaiResolver {
    type Response = IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = GaiFuture;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        GaiFuture(spawn_blocking(move || {
            debug!("resolving {}", name);
            (name.as_str(), 0).to_socket_addrs()
        }))
    }
}

impl Resolve for GaiResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let mut this = self.clone();
        Box::pin(async move {
            this.call(name)
                .await
                .map(|addrs| Box::new(addrs) as Addrs)
                .map_err(Into::into)
        })
    }
}

// ===== impl GaiFuture =====

impl Future for GaiFuture {
    type Output = Result<IntoIter<SocketAddr>, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|res| match res {
            Ok(Ok(addrs)) => Ok(addrs),
            Ok(Err(err)) => Err(err),
            Err(join_err) => Err(io::Error::other(format!(
                "DNS resolution blocked task panicked: {join_err}"
            ))),
        })
    }
}
