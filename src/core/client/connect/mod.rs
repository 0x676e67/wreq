//! Connectors used by the `Client`.

mod http;
#[cfg(unix)]
mod uds;

pub mod proxy;

use std::{
    fmt::{self, Formatter},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use ::http::Extensions;

pub use self::http::{HttpConnector, HttpInfo, TcpConnectOptions};
#[cfg(unix)]
pub use self::uds::UnixConnector;

/// Describes a type returned by a connector.
pub trait Connection {
    /// Return metadata describing the connection.
    fn connected(&self) -> Connected;
}

/// Extra information about the connected transport.
///
/// This can be used to inform recipients about things like if ALPN
/// was used, or if connected to an HTTP proxy.
#[derive(Debug)]
pub struct Connected {
    pub(super) alpn: Alpn,
    pub(super) is_proxied: bool,
    pub(super) extra: Option<Extra>,
    pub(super) poisoned: PoisonPill,
}

#[derive(Clone)]
pub(crate) struct PoisonPill {
    poisoned: Arc<AtomicBool>,
}

impl fmt::Debug for PoisonPill {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // print the address of the pill—this makes debugging issues much easier
        write!(
            f,
            "PoisonPill@{:p} {{ poisoned: {} }}",
            self.poisoned,
            self.poisoned.load(Ordering::Relaxed)
        )
    }
}

impl PoisonPill {
    pub(crate) fn healthy() -> Self {
        Self {
            poisoned: Arc::new(AtomicBool::new(false)),
        }
    }
    pub(crate) fn poison(&self) {
        self.poisoned.store(true, Ordering::Relaxed)
    }

    pub(crate) fn poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Relaxed)
    }
}

pub(super) struct Extra(Box<dyn ExtraInner>);

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Alpn {
    H2,
    None,
}

impl Default for Connected {
    fn default() -> Self {
        Self::new()
    }
}

impl Connected {
    /// Create new `Connected` type with empty metadata.
    pub fn new() -> Connected {
        Connected {
            alpn: Alpn::None,
            is_proxied: false,
            extra: None,
            poisoned: PoisonPill::healthy(),
        }
    }

    /// Set whether the connected transport is to an HTTP proxy.
    ///
    /// This setting will affect if HTTP/1 requests written on the transport
    /// will have the request-target in absolute-form or origin-form:
    ///
    /// - When `proxy(false)`:
    ///
    /// ```http
    /// GET /guide HTTP/1.1
    /// ```
    ///
    /// - When `proxy(true)`:
    ///
    /// ```http
    /// GET http://hyper.rs/guide HTTP/1.1
    /// ```
    ///
    /// Default is `false`.
    pub fn proxy(mut self, is_proxied: bool) -> Connected {
        self.is_proxied = is_proxied;
        self
    }

    /// Determines if the connected transport is to an HTTP proxy.
    pub fn is_proxied(&self) -> bool {
        self.is_proxied
    }

    /// Set extra connection information to be set in the extensions of every `Response`.
    pub fn extra<T: Clone + Send + Sync + 'static>(mut self, extra: T) -> Connected {
        if let Some(prev) = self.extra {
            self.extra = Some(Extra(Box::new(ExtraChain(prev.0, extra))));
        } else {
            self.extra = Some(Extra(Box::new(ExtraEnvelope(extra))));
        }
        self
    }

    /// Copies the extra connection information into an `Extensions` map.
    pub fn get_extras(&self, extensions: &mut Extensions) {
        if let Some(extra) = &self.extra {
            extra.set(extensions);
        }
    }

    /// Set that the connected transport negotiated HTTP/2 as its next protocol.
    pub fn negotiated_h2(mut self) -> Connected {
        self.alpn = Alpn::H2;
        self
    }

    /// Determines if the connected transport negotiated HTTP/2 as its next protocol.
    pub fn is_negotiated_h2(&self) -> bool {
        self.alpn == Alpn::H2
    }

    /// Poison this connection
    ///
    /// A poisoned connection will not be reused for subsequent requests by the pool
    pub fn poison(&self) {
        self.poisoned.poison();
        debug!(
            "connection was poisoned. this connection will not be reused for subsequent requests"
        );
    }

    // Don't public expose that `Connected` is `Clone`, unsure if we want to
    // keep that contract...
    pub(super) fn clone(&self) -> Connected {
        Connected {
            alpn: self.alpn,
            is_proxied: self.is_proxied,
            extra: self.extra.clone(),
            poisoned: self.poisoned.clone(),
        }
    }
}

// ===== impl Extra =====

impl Extra {
    pub(super) fn set(&self, res: &mut Extensions) {
        self.0.set(res);
    }
}

impl Clone for Extra {
    fn clone(&self) -> Extra {
        Extra(self.0.clone_box())
    }
}

impl fmt::Debug for Extra {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extra").finish()
    }
}

trait ExtraInner: Send + Sync {
    fn clone_box(&self) -> Box<dyn ExtraInner>;
    fn set(&self, res: &mut Extensions);
}

// This indirection allows the `Connected` to have a type-erased "extra" value,
// while that type still knows its inner extra type. This allows the correct
// TypeId to be used when inserting into `res.extensions_mut()`.
#[derive(Clone)]
struct ExtraEnvelope<T>(T);

impl<T> ExtraInner for ExtraEnvelope<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn clone_box(&self) -> Box<dyn ExtraInner> {
        Box::new(self.clone())
    }

    fn set(&self, res: &mut Extensions) {
        res.insert(self.0.clone());
    }
}

struct ExtraChain<T>(Box<dyn ExtraInner>, T);

impl<T: Clone> Clone for ExtraChain<T> {
    fn clone(&self) -> Self {
        ExtraChain(self.0.clone_box(), self.1.clone())
    }
}

impl<T> ExtraInner for ExtraChain<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn clone_box(&self) -> Box<dyn ExtraInner> {
        Box::new(self.clone())
    }

    fn set(&self, res: &mut Extensions) {
        self.0.set(res);
        res.insert(self.1.clone());
    }
}
