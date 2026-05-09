#![allow(dead_code)]
//! DNS resolver using compio's `spawn_blocking`.
//!
//! Runs `getaddrinfo` on the compio runtime's blocking thread pool,
//! avoiding extra OS thread creation.

use std::{
    future::Future,
    io,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    task::{self, Poll},
};

use tower::Service;

use super::{Addrs, Name, Resolve, Resolving, SocketAddrs};

/// A resolver using compio's `spawn_blocking` for DNS lookups.
#[derive(Clone, Default)]
pub struct CompioResolver {
    _priv: (),
}

/// An iterator of IP addresses returned from `getaddrinfo`.
pub struct CompioAddrs {
    inner: SocketAddrs,
}

/// A future to resolve a name returned by `CompioResolver`.
pub struct CompioFuture {
    inner: compio::runtime::JoinHandle<Result<SocketAddrs, io::Error>>,
}

// ===== impl CompioResolver =====

impl CompioResolver {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl Service<Name> for CompioResolver {
    type Response = CompioAddrs;
    type Error = io::Error;
    type Future = CompioFuture;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        debug!("resolving {}", name);
        let handle = compio::runtime::spawn_blocking(move || {
            (name.as_str(), 0)
                .to_socket_addrs()
                .map(|i| SocketAddrs::new(i.collect()))
        });
        CompioFuture { inner: handle }
    }
}

impl Resolve for CompioResolver {
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

// ===== impl CompioFuture =====

impl Future for CompioFuture {
    type Output = Result<CompioAddrs, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx).map(|res| match res {
            Ok(Ok(addrs)) => Ok(CompioAddrs { inner: addrs }),
            Ok(Err(err)) => Err(err),
            Err(_panic) => Err(io::Error::new(
                io::ErrorKind::Other,
                "dns blocking task panicked",
            )),
        })
    }
}

// ===== impl CompioAddrs =====

impl Iterator for CompioAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}
