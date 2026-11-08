// This module contains the `GaiResolver` implementation for the `tokio` runtime.

use std::{
    future::Future,
    io,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    task::{Context, Poll},
    vec::IntoIter,
};

use tokio::task::{JoinHandle, spawn_blocking};

use crate::dns::{Addrs, Name, Resolve, Resolving};

/// A system resolver that offloads lookups to the Tokio thread pool.
#[derive(Clone, Default)]
pub(super) struct GaiResolver;

/// A future to resolve a name returned by `GaiResolver`.
pub(super) struct GaiFuture(JoinHandle<io::Result<IntoIter<SocketAddr>>>);

// ===== impl GaiResolver =====

impl Resolve for GaiResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addrs = GaiFuture(spawn_blocking(move || {
                debug!("resolving {}", name);
                (name.as_str(), 0).to_socket_addrs()
            }))
            .await?;
            Ok(Box::new(addrs) as Addrs)
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
            Err(join_err) => {
                if join_err.is_cancelled() {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, join_err));
                }

                Err(io::Error::other(format!(
                    "DNS resolution blocked task panicked: {join_err}"
                )))
            }
        })
    }
}

impl Drop for GaiFuture {
    fn drop(&mut self) {
        self.0.abort();
    }
}
