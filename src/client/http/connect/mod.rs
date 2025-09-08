mod conn;
mod connector;
mod tls_info;
mod verbose;

use tokio::io::{AsyncRead, AsyncWrite};
use tower::{
    BoxError,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer},
};

pub(super) use self::{conn::Conn, connector::Connector, tls_info::TlsInfoFactory};
use crate::{
    core::client::{ConnectRequest, connect::Connection},
    dns::DynResolver,
};

/// HTTP connector with dynamic DNS resolver.
pub type HttpConnector = crate::core::client::connect::HttpConnector<DynResolver>;

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
/// - [`Read`] + [`Write`]: For I/O operations
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
