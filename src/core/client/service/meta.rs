use std::sync::Arc;

use http::{Uri, Version};

use crate::{
    core::client::{
        connect::TcpConnectOptions,
        options::{RequestOptions, TransportOptions},
    },
    proxy::Matcher as ProxyMacher,
    tls::{AlpnProtocol, TlsOptions},
    util::hash::HashMemo,
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
    /// Target URI.
    uri: Uri,
    /// Request options.
    options: Option<RequestOptions>,
}

// ===== impl ConnectMeta =====

impl ConnectMeta {
    /// Create a new [`ConnectMeta`] with the given URI and options.
    #[inline]
    pub(super) fn new(uri: Uri, options: Option<RequestOptions>) -> Self {
        Self { uri, options }
    }

    /// Return the negotiated [`AlpnProtocol`].
    pub(crate) fn alpn_protocol(&self) -> Option<AlpnProtocol> {
        match self
            .options
            .as_ref()
            .and_then(RequestOptions::enforced_version)
        {
            Some(Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09) => {
                Some(AlpnProtocol::HTTP1)
            }
            Some(Version::HTTP_2) => Some(AlpnProtocol::HTTP2),
            _ => None,
        }
    }

    /// Return a reference to the [`ProxyMacher`].
    #[inline]
    pub(crate) fn proxy_matcher(&self) -> Option<&ProxyMacher> {
        self.options
            .as_ref()
            .and_then(RequestOptions::proxy_matcher)
    }

    /// Return a reference to the [`TlsOptions`].
    #[inline]
    pub(crate) fn tls_options(&self) -> Option<&TlsOptions> {
        self.options
            .as_ref()
            .and_then(RequestOptions::transport_opts)
            .and_then(TransportOptions::tls_options)
    }

    /// Return a reference to the [`TcpConnectOptions`].
    #[inline]
    pub(crate) fn tcp_options(&self) -> Option<&TcpConnectOptions> {
        self.options
            .as_ref()
            .and_then(RequestOptions::tcp_connect_opts)
    }
}
