//! Senders checked out from the pool.
//!
//! [`Pooled`] presents one request interface over an exclusive HTTP/1 sender or a shared
//! HTTP/2 or HTTP/3 sender, and decides on drop whether the sender returns for reuse.

use std::{
    fmt,
    task::{self, Poll},
};

use futures_util::future::BoxFuture;
use http::{Request, Response, Version};
use netty::body::Incoming;
use tower::Service;

#[cfg(any(feature = "http2", feature = "http3"))]
use super::entry::MuxPooled;
use super::{
    cache::Cached,
    entry::{EntryCleanupGuard, EntryUse},
};
use crate::{
    Body,
    client::proto::{SendError, http1},
    conn::Connected,
};

/// Protocol-agnostic sender checked out from one pool entry.
///
/// HTTP/1 owns an exclusive [`Cached`] sender that returns to its cache on drop.
/// HTTP/2 and HTTP/3 own a [`Singled`](super::singleton::Singled) clone and count
/// checkouts until response headers. The wrapper presents one request interface to
/// the client and records whether a healthy sender may be retained after dispatch.
///
/// Dropping this value marks HTTP/1 idle or ends the HTTP/2 or HTTP/3 checkout.
/// Poisoned or closed senders are removed instead of being reused.
pub(in crate::client) struct Pooled {
    /// HTTP/1 cache checkout or HTTP/2 or HTTP/3 singleton checkout.
    inner: PooledInner,

    /// Whether healthy senders should return to their pool.
    pool_enabled: bool,

    /// Runs after `inner` is dropped when this checkout discarded its sender.
    cleanup: EntryCleanupGuard,
}

/// HTTP sender selected for one pool checkout.
enum PooledInner {
    Http1(Cached<http1::Connection>),
    #[cfg(any(feature = "http2", feature = "http3"))]
    Mux(MuxPooled),
}

// ===== impl Pooled =====

impl Pooled {
    /// Wraps a checked-out sender and takes over entry cleanup from `usage`.
    ///
    /// HTTP/2 and HTTP/3 checkout accounting starts first; with pooling enabled the
    /// entry is then reconciled with empty cleanup and the idle-group LRU.
    fn new(inner: PooledInner, pool_enabled: bool, usage: EntryUse) -> Self {
        #[cfg(any(feature = "http2", feature = "http3"))]
        if let PooledInner::Mux(service) = &inner {
            service.inner().begin_checkout();
        }
        let cleanup = usage.into_cleanup();
        if pool_enabled {
            cleanup.maintain();
        }
        Self {
            inner,
            pool_enabled,
            cleanup,
        }
    }

    /// Wraps an HTTP/1 sender, maintaining its entry when pooling is enabled.
    pub(super) fn new_h1(
        service: Cached<http1::Connection>,
        pool_enabled: bool,
        usage: EntryUse,
    ) -> Self {
        Self::new(PooledInner::Http1(service), pool_enabled, usage)
    }

    /// Wraps an HTTP/2 or HTTP/3 sender, maintaining its entry when pooling is enabled.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) fn new_mux(service: MuxPooled, pool_enabled: bool, usage: EntryUse) -> Self {
        Self::new(PooledInner::Mux(service), pool_enabled, usage)
    }

    /// Returns the HTTP version of this checkout's connection; HTTP/1 reports HTTP/1.1.
    pub(in crate::client) fn version(&self) -> Version {
        match &self.inner {
            PooledInner::Http1(_) => Version::HTTP_11,
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.inner().version(),
        }
    }

    /// Returns whether the peer enabled extended CONNECT, or `None` before its SETTINGS.
    /// HTTP/1 never supports it.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(in crate::client) fn extended_connect(&self) -> Option<bool> {
        match &self.inner {
            PooledInner::Http1(_) => Some(false),
            PooledInner::Mux(service) => service.inner().extended_connect(),
        }
    }

    /// Returns whether the sender came from an existing pooled connection.
    pub(in crate::client) fn is_reused(&self) -> bool {
        match &self.inner {
            PooledInner::Http1(service) => service.is_reused(),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.is_reused(),
        }
    }

    /// Returns whether completed senders may be retained for reuse.
    pub(in crate::client) fn is_pool_enabled(&self) -> bool {
        self.pool_enabled
    }

    /// Returns whether the protocol sender can accept a request immediately.
    pub(in crate::client) fn is_ready(&self) -> bool {
        match &self.inner {
            PooledInner::Http1(service) => service.inner().is_ready(),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.inner().is_ready(),
        }
    }

    /// Returns metadata for the underlying physical connection.
    pub(in crate::client) fn connected(&self) -> &Connected {
        match &self.inner {
            PooledInner::Http1(service) => service.inner().connected(),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.inner().connected(),
        }
    }
}

impl Service<Request<Body>> for Pooled {
    type Response = Response<Incoming>;
    type Error = SendError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        match &mut self.inner {
            PooledInner::Http1(service) => service.poll_ready(cx),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.poll_ready(cx),
        }
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        match &mut self.inner {
            PooledInner::Http1(service) => service.call(req),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.call(req),
        }
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        match &mut self.inner {
            PooledInner::Http1(service) => {
                service.inner_mut().mark_idle();
                if !service.inner().is_open() {
                    service.discard_on_drop();
                }
                let returned = service.return_to_cache();
                if self.pool_enabled {
                    if returned {
                        self.cleanup.maintain();
                    } else {
                        self.cleanup.arm();
                    }
                }
            }
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => {
                let discard = {
                    let connection = service.inner();
                    connection.finish_checkout();
                    connection.connected().poisoned() || connection.is_closed()
                };
                if discard {
                    service.discard_shared();
                }
                if self.pool_enabled && discard {
                    self.cleanup.arm();
                }
            }
        }
    }
}

impl fmt::Debug for Pooled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pooled")
            .field("version", &self.version())
            .field("reused", &self.is_reused())
            .finish()
    }
}
