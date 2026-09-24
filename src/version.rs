//! HTTP protocol selection shared by clients, connection pools, and TLS.

/// Selects the HTTP protocol used when establishing a connection.
/// Unlike [`Version`](crate::Version), this type includes automatic negotiation.
/// An explicit request version can override the client's selection.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum HttpVersion {
    /// Negotiates HTTP/2 through TLS ALPN, otherwise uses HTTP/1.
    /// Nonempty TLS ALPN options are preserved; otherwise `h2, http/1.1` is offered.
    /// Cleartext connections use HTTP/1 unless a request explicitly selects HTTP/2.
    #[default]
    Auto,

    /// Uses HTTP/1 without upgrading to HTTP/2.
    /// TLS connections offer only `http/1.1`, regardless of TLS ALPN options.
    /// Both HTTP/1.0 and HTTP/1.1 requests use this connection mode.
    Http1,

    /// Uses HTTP/2 without falling back to HTTP/1.
    /// Cleartext connections use prior knowledge; TLS connections offer only `h2`.
    /// If the peer omits ALPN, the client still attempts HTTP/2.
    Http2,
}
