use std::sync::Arc;

use http::Uri;

use crate::{
    core::{client::connect::TcpConnectOptions, collections::memo::HashMemo},
    proxy::Matcher as ProxyMacher,
    tls::{AlpnProtocol, TlsOptions},
};

/// Uniquely identifies a connection configuration and its lifecycle.
///
/// [`Identifier`] serves as the unique key for a connection, representing all parameters
/// that define its identity (URI, protocol, proxy, TCP/TLS options). It is used for pooling,
/// caching, and tracking connections throughout their entire lifecycle.
pub(crate) type Identifier = Arc<HashMemo<ConnectMeta>>;

/// Metadata describing a reusable network connection.
///
/// [`ConnectMeta`] holds connection-specific parameters such as the target URI, ALPN protocol,
/// proxy settings, and optional TCP/TLS options. Used for connection
#[must_use]
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub(crate) struct ConnectMeta {
    /// The target URI for the connection.
    pub(super) uri: Uri,
    /// The negotiated ALPN protocol.
    pub(super) alpn: Option<AlpnProtocol>,
    /// The proxy matcher.
    pub(super) proxy: Option<ProxyMacher>,
    /// Optional TLS options.
    pub(super) tls_options: Option<TlsOptions>,
    /// Optional TCP connection options.
    pub(super) tcp_options: Option<TcpConnectOptions>,
}

// ===== impl ConnectMeta =====

impl ConnectMeta {
    /// Return the negotiated [`AlpnProtocol`].
    #[inline]
    pub(crate) fn alpn(&self) -> Option<AlpnProtocol> {
        self.alpn
    }

    /// Return a reference to the [`ProxyMacher`].
    #[inline]
    pub(crate) fn proxy(&self) -> Option<&ProxyMacher> {
        self.proxy.as_ref()
    }

    /// Return a reference to the [`TlsOptions`].
    #[inline]
    pub(crate) fn tls_options(&self) -> Option<&TlsOptions> {
        self.tls_options.as_ref()
    }

    /// Return a reference to the [`TcpConnectOptions`].
    #[inline]
    pub(crate) fn tcp_options(&self) -> Option<&TcpConnectOptions> {
        self.tcp_options.as_ref()
    }
}
