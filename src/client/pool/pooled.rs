//! Checked-out HTTP senders from the pool.
//!
//! [`Pooled`] provides a uniform request service over exclusive HTTP/1 and shared
//! HTTP/2 or HTTP/3 senders, deciding on drop whether to return or discard them.

use std::{
    fmt,
    task::{self, Poll},
};

use futures_util::future::BoxFuture;
use http::{Request, Response, Version};
use netty::body::Incoming;
use tower::Service;

#[cfg(any(feature = "http2", feature = "http3"))]
use super::entry::MuxSingled;
use super::{
    cache::Cached,
    entry::{EntryCleanupGuard, EntryUse},
};
use crate::{
    Body,
    client::proto::{SendError, http1},
    conn::Connected,
};

/// A sender checked out from a pool entry.
///
/// On drop, healthy HTTP/1 senders return to their cache, while HTTP/2 and HTTP/3 release
/// their checkout handle while letting the connection driver finish any open streams.
pub(in crate::client) struct Pooled {
    /// Checked-out HTTP/1 cache handle or shared HTTP/2 or HTTP/3 singleton handle.
    inner: PooledInner,
    /// Whether healthy senders return to their pool on drop.
    pool_enabled: bool,
    /// Must drop after `inner` so maintenance sees the updated cache or singleton state.
    cleanup: EntryCleanupGuard,
}

/// Underlying protocol sender held by [`Pooled`].
enum PooledInner {
    /// Exclusive HTTP/1 sender.
    Http1(Cached<http1::Connection>),
    /// Shared HTTP/2 or HTTP/3 sender.
    #[cfg(any(feature = "http2", feature = "http3"))]
    Mux(MuxSingled),
}

// ===== impl Pooled =====

impl Pooled {
    /// Wraps a checked-out sender and takes over entry cleanup from `usage`.
    ///
    /// HTTP/2 and HTTP/3 checkout accounting starts before handing off entry cleanup.
    #[must_use]
    fn new(inner: PooledInner, pool_enabled: bool, usage: EntryUse) -> Self {
        #[cfg(any(feature = "http2", feature = "http3"))]
        if let PooledInner::Mux(service) = &inner {
            service.inner().begin_checkout();
        }
        let pooled = Self {
            inner,
            pool_enabled,
            cleanup: usage.into_cleanup(),
        };
        if pool_enabled {
            pooled.cleanup.maintain(pooled.is_reused());
        }
        pooled
    }

    /// Wraps an HTTP/1 sender, maintaining its entry when pooling is enabled.
    #[must_use]
    pub(super) fn new_http1(
        service: Cached<http1::Connection>,
        pool_enabled: bool,
        usage: EntryUse,
    ) -> Self {
        Self::new(PooledInner::Http1(service), pool_enabled, usage)
    }

    /// Wraps an HTTP/2 or HTTP/3 sender, maintaining its entry when pooling is enabled.
    #[must_use]
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) fn new_mux(service: MuxSingled, pool_enabled: bool, usage: EntryUse) -> Self {
        Self::new(PooledInner::Mux(service), pool_enabled, usage)
    }

    /// Returns the HTTP version of this connection (HTTP/1 reports HTTP/1.1).
    #[must_use]
    pub(in crate::client) fn version(&self) -> Version {
        match &self.inner {
            PooledInner::Http1(_) => Version::HTTP_11,
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.inner().version(),
        }
    }

    /// Returns whether the peer enabled extended CONNECT, or `None` before its SETTINGS arrive.
    ///
    /// Always returns `Some(false)` for HTTP/1.
    #[must_use]
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(in crate::client) fn extended_connect(&self) -> Option<bool> {
        match &self.inner {
            PooledInner::Http1(_) => Some(false),
            PooledInner::Mux(service) => service.inner().extended_connect(),
        }
    }

    /// Returns whether the sender came from an existing pooled connection.
    #[must_use]
    pub(in crate::client) fn is_reused(&self) -> bool {
        match &self.inner {
            PooledInner::Http1(service) => service.is_reused(),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.is_reused(),
        }
    }

    /// Returns whether completed senders may be retained for reuse.
    #[must_use]
    pub(in crate::client) fn is_pool_enabled(&self) -> bool {
        self.pool_enabled
    }

    /// Returns whether the protocol sender can accept a request immediately.
    #[must_use]
    pub(in crate::client) fn is_ready(&self) -> bool {
        match &self.inner {
            PooledInner::Http1(service) => service.inner().is_ready(),
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => service.inner().is_ready(),
        }
    }

    /// Returns metadata for the underlying physical connection.
    #[must_use]
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
                        self.cleanup.maintain(false);
                    } else {
                        self.cleanup.arm();
                    }
                }
            }
            #[cfg(any(feature = "http2", feature = "http3"))]
            PooledInner::Mux(service) => {
                let connection = service.inner();
                let became_idle = connection.finish_checkout();
                let discard = !connection.is_open();
                if discard {
                    service.discard_shared();
                }
                if self.pool_enabled && (discard || became_idle && self.cleanup.needs_tracking()) {
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
