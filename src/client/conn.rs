#[allow(clippy::module_inception)]
mod conn;
mod connector;
mod http;
mod proxy;
mod tls_info;
#[cfg(unix)]
mod uds;
mod verbose;

use std::{
    fmt::{self, Debug, Formatter},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use ::http::Extensions;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::{
    BoxError,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer},
};

#[cfg(feature = "socks")]
pub(super) use self::proxy::socks;
pub(super) use self::{
    conn::Conn,
    connector::Connector,
    http::{HttpInfo, TcpConnectOptions},
    proxy::tunnel,
    tls_info::TlsInfoFactory,
};
use crate::{client::ConnectRequest, dns::DynResolver};

/// HTTP connector with dynamic DNS resolver.
pub type HttpConnector = self::http::HttpConnector<DynResolver>;

/// Boxed connector service for establishing connections.
pub type BoxedConnectorService = BoxCloneSyncService<Unnameable, Conn, BoxError>;

/// Boxed layer for building a boxed connector service.
pub type BoxedConnectorLayer =
    BoxCloneSyncServiceLayer<BoxedConnectorService, Unnameable, Conn, BoxError>;

/// A wrapper type for [`ConnectRequest`] used to erase its concrete type.
///
/// [`Unnameable`] allows passing connection requests through trait objects or
/// type-erased interfaces where the concrete type of the request is not important.
/// This is mainly used internally to simplify service composition and dynamic dispatch.
pub struct Unnameable(pub(super) ConnectRequest);

/// A trait alias for types that can be used as async connections.
///
/// This trait is automatically implemented for any type that satisfies the required bounds:
/// - [`AsyncRead`] + [`AsyncWrite`]: For I/O operations
/// - [`Connection`]: For connection metadata
/// - [`Send`] + [`Sync`] + [`Unpin`] + `'static`: For async/await compatibility
trait AsyncConn: AsyncRead + AsyncWrite + Connection + Send + Sync + Unpin + 'static {}

/// An async connection that can also provide TLS information.
///
/// This extends [`AsyncConn`] with the ability to extract TLS certificate information
/// when available. Useful for connections that may be either plain TCP or TLS-encrypted.
trait AsyncConnWithInfo: AsyncConn + TlsInfoFactory {}

impl<T> AsyncConn for T where T: AsyncRead + AsyncWrite + Connection + Send + Sync + Unpin + 'static {}

impl<T> AsyncConnWithInfo for T where T: AsyncConn + TlsInfoFactory {}

/// Describes a type returned by a connector.
pub trait Connection {
    /// Return metadata describing the connection.
    fn connected(&self) -> Connected;
}

/// Indicates the negotiated ALPN protocol.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Alpn {
    H2,
    None,
}

/// A pill that can be poisoned to indicate that a connection should not be reused.
#[derive(Clone)]
struct PoisonPill {
    poisoned: Arc<AtomicBool>,
}

/// A boxed asynchronous connection with associated information.
#[derive(Debug)]
struct Extra(Box<dyn ExtraInner>);

/// Inner trait for extra connection information.
trait ExtraInner: Send + Sync + Debug {
    fn clone_box(&self) -> Box<dyn ExtraInner>;
    fn set(&self, res: &mut Extensions);
}

// This indirection allows the `Connected` to have a type-erased "extra" value,
// while that type still knows its inner extra type. This allows the correct
// TypeId to be used when inserting into `res.extensions_mut()`.
#[derive(Debug, Clone)]
struct ExtraEnvelope<T>(T);

/// Chains two `ExtraInner` implementations together, inserting both into
/// the extensions.
#[derive(Debug)]
struct ExtraChain<T>(Box<dyn ExtraInner>, T);

/// Extra information about the connected transport.
///
/// This can be used to inform recipients about things like if ALPN
/// was used, or if connected to an HTTP proxy.
#[derive(Debug)]
pub struct Connected {
    alpn: Alpn,
    is_proxied: bool,
    extra: Option<Extra>,
    poisoned: PoisonPill,
}

// ===== impl PoisonPill =====

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
    /// Create a healthy (not poisoned) pill.
    #[inline]
    fn healthy() -> Self {
        Self {
            poisoned: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Poison this pill.
    #[inline]
    fn poison(&self) {
        self.poisoned.store(true, Ordering::Relaxed)
    }

    /// Check if this pill is poisoned.
    #[inline]
    fn poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Relaxed)
    }
}

// ===== impl Connected =====

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

    /// Set extra connection information to be set in the extensions of every `Response`.
    pub fn extra<T: Clone + Send + Sync + Debug + 'static>(mut self, extra: T) -> Connected {
        if let Some(prev) = self.extra {
            self.extra = Some(Extra(Box::new(ExtraChain(prev.0, extra))));
        } else {
            self.extra = Some(Extra(Box::new(ExtraEnvelope(extra))));
        }
        self
    }

    /// Copies the extra connection information into an `Extensions` map.
    pub fn set_extras(&self, extensions: &mut Extensions) {
        if let Some(extra) = &self.extra {
            extra.set(extensions);
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
    #[inline]
    pub fn proxy(mut self, is_proxied: bool) -> Connected {
        self.is_proxied = is_proxied;
        self
    }

    /// Determines if the connected transport is to an HTTP proxy.
    #[inline]
    pub fn is_proxied(&self) -> bool {
        self.is_proxied
    }

    /// Set that the connected transport negotiated HTTP/2 as its next protocol.
    #[inline]
    pub fn negotiated_h2(mut self) -> Connected {
        self.alpn = Alpn::H2;
        self
    }

    /// Determines if the connected transport negotiated HTTP/2 as its next protocol.
    #[inline]
    pub fn is_negotiated_h2(&self) -> bool {
        self.alpn == Alpn::H2
    }

    /// Determine if this connection is poisoned
    #[inline]
    pub fn poisoned(&self) -> bool {
        self.poisoned.poisoned()
    }

    /// Poison this connection
    ///
    /// A poisoned connection will not be reused for subsequent requests by the pool
    #[inline]
    pub fn poison(&self) {
        self.poisoned.poison();
        debug!(
            "connection was poisoned. this connection will not be reused for subsequent requests"
        );
    }

    // Don't public expose that `Connected` is `Clone`, unsure if we want to
    // keep that contract...
    pub(crate) fn clone(&self) -> Connected {
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
    #[inline]
    fn set(&self, res: &mut Extensions) {
        self.0.set(res);
    }
}

impl Clone for Extra {
    fn clone(&self) -> Extra {
        Extra(self.0.clone_box())
    }
}

// ===== impl ExtraEnvelope =====

impl<T> ExtraInner for ExtraEnvelope<T>
where
    T: Clone + Send + Sync + Debug + 'static,
{
    fn clone_box(&self) -> Box<dyn ExtraInner> {
        Box::new(self.clone())
    }

    fn set(&self, res: &mut Extensions) {
        res.insert(self.0.clone());
    }
}

// ===== impl ExtraChain =====

impl<T: Clone> Clone for ExtraChain<T> {
    fn clone(&self) -> Self {
        ExtraChain(self.0.clone_box(), self.1.clone())
    }
}

impl<T> ExtraInner for ExtraChain<T>
where
    T: Clone + Send + Sync + Debug + 'static,
{
    fn clone_box(&self) -> Box<dyn ExtraInner> {
        Box::new(self.clone())
    }

    fn set(&self, res: &mut Extensions) {
        self.0.set(res);
        res.insert(self.1.clone());
    }
}
