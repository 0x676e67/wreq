use std::sync::Arc;

use http::Uri;

use crate::{
    core::{
        client::connect::TcpConnectOptions,
        collections::{RANDOM_STATE, memo::HashMemo},
    },
    proxy::Matcher as ProxyMacher,
    tls::{AlpnProtocol, TlsOptions},
};

/// Uniquely identifies a connection configuration and its lifecycle.
///
/// [`Identifier`] serves as the unique key for a connection, representing all parameters
/// that define its identity (URI, protocol, proxy, TCP/TLS options). It is used for pooling,
/// caching, and tracking connections throughout their entire lifecycle.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub(crate) struct Identifier(Arc<HashMemo<Extra>>);

/// Metadata describing a reusable network connection.
///
/// [`Extra`] holds connection-specific parameters such as the target URI, ALPN protocol,
/// proxy settings, and optional TCP/TLS options. Used for connection
#[must_use]
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Extra {
    /// The target URI for the connection.
    uri: Uri,
    /// The negotiated ALPN protocol.
    alpn: Option<AlpnProtocol>,
    /// The proxy matcher.
    proxy: Option<ProxyMacher>,
    /// Optional TLS options.
    tls_options: Option<TlsOptions>,
    /// Optional TCP connection options.
    tcp_options: Option<TcpConnectOptions>,
}

// ===== impl Extra =====

impl Extra {
    /// Creates a new [`Extra`] instance with the specified parameters.
    #[inline]
    pub(super) fn new(
        uri: Uri,
        alpn: Option<AlpnProtocol>,
        proxy: Option<ProxyMacher>,
        tls_options: Option<TlsOptions>,
        tcp_options: Option<TcpConnectOptions>,
    ) -> Self {
        Extra {
            uri,
            alpn,
            proxy,
            tls_options,
            tcp_options,
        }
    }

    /// Returns the negotiated [`AlpnProtocol`].
    #[inline]
    pub(crate) fn alpn_protocol(&self) -> Option<AlpnProtocol> {
        self.alpn
    }

    /// Return a reference to the [`ProxyMacher`].
    #[inline]
    pub(crate) fn proxy_matcher(&self) -> Option<&ProxyMacher> {
        self.proxy.as_ref()
    }

    /// Return the [`TlsOptions`] configuration.
    #[inline]
    pub(crate) fn tls_options(&self) -> Option<&TlsOptions> {
        self.tls_options.as_ref()
    }

    /// Return the [`TcpConnectOptions`].
    #[inline]
    pub(crate) fn tcp_options(&self) -> Option<&TcpConnectOptions> {
        self.tcp_options.as_ref()
    }
}

/// Parameters required to initiate a new connection.
///
/// [`ConnectRequest`] holds the target URI and all connection-specific options
/// (protocol, proxy, TCP/TLS settings) needed to establish a new network connection.
/// Used by connectors to drive the connection setup process.
#[must_use]
#[derive(Clone)]
pub struct ConnectRequest {
    uri: Uri,
    extra: Arc<HashMemo<Extra>>,
}

// ===== impl ConnectRequest =====

impl ConnectRequest {
    /// Creates a new [`ConnectRequest`] with the specified [`Uri`] and connection parameters.
    #[inline]
    pub(super) fn new(uri: Uri, extra: Extra) -> Self {
        let extra = Arc::new(HashMemo::with_hasher(extra, RANDOM_STATE));
        ConnectRequest { uri, extra }
    }

    /// Returns a reference to the [`Uri`].
    #[inline]
    pub(crate) fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns a mutable reference to the [`Uri`].
    #[inline]
    pub(crate) fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }

    /// Returns the [`Extra`] connection parameters (ALPN, proxy, TCP/TLS options).
    #[inline]
    pub(crate) fn ex_data(&self) -> &Extra {
        self.extra.as_ref().as_ref()
    }

    /// Returns a unique [`Identifier`].
    #[inline]
    pub(crate) fn identify(&self) -> Identifier {
        Identifier(self.extra.clone())
    }
}
