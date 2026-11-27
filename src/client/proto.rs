//! Adapts established transports into protocol request senders.
//!
//! The HTTP/1 and optional HTTP/2 layers handshake established streams.
//! With the `http3` feature, the HTTP/3 layer wraps a QUIC connector.
//! The pool composes these Tower services with reuse.
//!
//! A successful handshake starts the protocol driver and returns a sender with
//! the connection metadata needed by request preparation and pool health checks.
//! HTTP/2 and HTTP/3 share one multiplexed sender type in `mux`.

pub(super) mod http1;
#[cfg(feature = "http2")]
pub(super) mod http2;
#[cfg(feature = "http3")]
pub(super) mod http3;
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) mod mux;

use std::sync::Arc;
#[cfg(feature = "http2")]
use std::time::Instant;

use crate::{
    config::ConnectConfig,
    conn::{Connected, Io},
    rt::DynRuntime,
};

/// Shares the client's builder unless the request overrides its protocol options.
#[must_use]
pub(super) fn configure<B: Clone, O: Clone>(
    builder: &Arc<B>,
    options: Option<&O>,
    apply: fn(B, O) -> B,
) -> Arc<B> {
    match options {
        Some(options) => Arc::new(apply(B::clone(builder), options.clone())),
        None => builder.clone(),
    }
}

/// Client-wide HTTP handshake builder and shared protocol runtime.
///
/// Constructed once per client from default [`ConnectConfig`] options and queried when
/// creating a pool entry so per-request protocol overrides only clone a builder when they
/// actually differ from the client defaults.
pub(super) struct Builder {
    /// Runtime spawning HTTP connection drivers and timers.
    runtime: DynRuntime,
    /// Whether the HTTP/1 sender supplies a missing `Host` header.
    set_host: bool,
    /// Client-wide default HTTP/1 handshake builder.
    http1: Arc<netty::conn::http1::Builder>,
    /// Client-wide default HTTP/2 handshake builder.
    #[cfg(feature = "http2")]
    http2: Arc<netty::conn::http2::Builder<DynRuntime>>,
    /// Client-wide default HTTP/3 handshake builder.
    #[cfg(feature = "http3")]
    http3: Arc<netty::conn::http3::Builder<DynRuntime>>,
}

/// Established byte stream and transport metadata passed to an HTTP handshake.
///
/// An ALPN-upgraded transport may wait in the negotiation queue before the HTTP/2
/// handshake starts.
pub(super) struct Established {
    /// Type-erased transport stream ready for an HTTP/1 or HTTP/2 handshake.
    io: Box<dyn Io>,
    /// Connection metadata including negotiated protocol and poison state.
    connected: Connected,
    /// Time when the transport became available for protocol selection.
    #[cfg(feature = "http2")]
    idle_at: Instant,
}

// ===== impl Builder =====

impl Builder {
    /// Builds the default protocol settings for the client.
    #[must_use]
    pub(super) fn new(runtime: DynRuntime, config: &ConnectConfig, set_host: bool) -> Self {
        let http1 = netty::conn::http1::Builder::default();
        let http1 = match config.get_ref::<netty::http1::Http1Options>() {
            Some(options) => http1.options(options.clone()),
            None => http1,
        };

        #[cfg(feature = "http2")]
        let http2 = {
            let builder = netty::conn::http2::Builder::new(runtime.clone()).timer(runtime.clone());
            match config.get_ref::<netty::http2::Http2Options>() {
                Some(options) => builder.options(options.clone()),
                None => builder,
            }
        };

        #[cfg(feature = "http3")]
        let http3 = {
            let builder = netty::conn::http3::Builder::new(runtime.clone());
            match config.get_ref::<netty::http3::Http3Options>() {
                Some(options) => builder.options(options.clone()),
                None => builder,
            }
        };

        Self {
            runtime,
            set_host,
            http1: Arc::new(http1),
            #[cfg(feature = "http2")]
            http2: Arc::new(http2),
            #[cfg(feature = "http3")]
            http3: Arc::new(http3),
        }
    }

    /// Applies the request's HTTP/1 handshake overrides.
    #[must_use]
    pub(super) fn http1<'a>(&'a self, config: &'a ConnectConfig) -> http1::ConnectLayer<'a> {
        let options = config.override_if_different(PartialEq::eq).map(Arc::as_ref);
        http1::ConnectLayer::new(&self.runtime, &self.http1, options, self.set_host)
    }

    /// Applies the request's HTTP/2 handshake overrides.
    #[cfg(feature = "http2")]
    #[must_use]
    pub(super) fn http2<'a>(&'a self, config: &'a ConnectConfig) -> http2::ConnectLayer<'a> {
        let options = config.override_if_different(PartialEq::eq).map(Arc::as_ref);
        http2::ConnectLayer::new(&self.runtime, &self.http2, options)
    }

    /// Applies the request's HTTP/3 handshake overrides.
    #[cfg(feature = "http3")]
    #[must_use]
    pub(super) fn http3<'a>(&'a self, config: &'a ConnectConfig) -> http3::ConnectLayer<'a> {
        let options = config.override_if_different(PartialEq::eq).map(Arc::as_ref);
        http3::ConnectLayer::new(&self.runtime, &self.http3, options)
    }
}

// ===== impl Established =====

impl Established {
    /// Creates the protocol-neutral output of a physical connector.
    #[must_use]
    pub(super) fn new(
        io: Box<dyn Io>,
        connected: Connected,
        #[cfg(feature = "http2")] idle_at: Instant,
    ) -> Self {
        Self {
            io,
            connected,
            #[cfg(feature = "http2")]
            idle_at,
        }
    }

    /// Returns metadata for the transport, including its negotiated ALPN.
    #[must_use]
    #[cfg(feature = "http2")]
    pub(super) fn connected(&self) -> &Connected {
        &self.connected
    }

    /// Returns when this transport became available for protocol selection.
    #[must_use]
    #[cfg(feature = "http2")]
    pub(super) fn idle_at(&self) -> Instant {
        self.idle_at
    }
}
