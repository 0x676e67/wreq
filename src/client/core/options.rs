pub mod http1;
pub mod http2;

use http::Version;
use http1::Http1Options;
use http2::Http2Options;

use super::connect::TcpConnectOptions;
use crate::{proxy::Matcher, tls::TlsOptions};

/// Transport options for HTTP/1, HTTP/2, and TLS layers.
///
/// This struct allows you to customize protocol-specific and TLS settings
/// for network connections made by the client.
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct TransportOptions {
    tls_options: Option<TlsOptions>,
    http1_options: Option<Http1Options>,
    http2_options: Option<Http2Options>,
}

impl TransportOptions {
    /// Get the reference to the TLS options.
    #[inline]
    pub fn tls_options(&self) -> Option<&TlsOptions> {
        self.tls_options.as_ref()
    }

    /// Get a mutable reference to the TLS options.
    #[inline]
    pub fn tls_options_mut(&mut self) -> &mut Option<TlsOptions> {
        &mut self.tls_options
    }

    /// Get the reference to the HTTP/1 options.
    #[inline]
    pub fn http1_options(&self) -> Option<&Http1Options> {
        self.http1_options.as_ref()
    }

    /// Get a mutable reference to the HTTP/1 options.
    #[inline]
    pub fn http1_options_mut(&mut self) -> &mut Option<Http1Options> {
        &mut self.http1_options
    }

    /// Get the reference to the HTTP/2 options.
    #[inline]
    pub fn http2_options(&self) -> Option<&Http2Options> {
        self.http2_options.as_ref()
    }

    /// Get a mutable reference to the HTTP/2 options.
    #[inline]
    pub fn http2_options_mut(&mut self) -> &mut Option<Http2Options> {
        &mut self.http2_options
    }

    /// Consumes the transport options and returns the individual parts.
    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<TlsOptions>,
        Option<Http1Options>,
        Option<Http2Options>,
    ) {
        (self.tls_options, self.http1_options, self.http2_options)
    }

    /// Apply the transport options for HTTP/1, HTTP/2, and TLS.
    pub(crate) fn apply_transport_options(&mut self, opts: TransportOptions) -> &mut Self {
        if let Some(tls) = opts.tls_options {
            *self.tls_options_mut() = Some(tls);
        }
        if let Some(http1) = opts.http1_options {
            *self.http1_options_mut() = Some(http1);
        }
        if let Some(http2) = opts.http2_options {
            *self.http2_options_mut() = Some(http2);
        }
        self
    }
}

/// Per-request configuration for proxy, protocol, and transport options.
/// Overrides client defaults for a single request.
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct RequestOptions {
    proxy_matcher: Option<Matcher>,
    enforced_version: Option<Version>,
    tcp_connect_opts: TcpConnectOptions,
    transport_opts: TransportOptions,
}

impl RequestOptions {
    /// Get a reference to the proxy matcher.
    #[inline]
    pub fn proxy_matcher(&self) -> Option<&Matcher> {
        self.proxy_matcher.as_ref()
    }

    /// Get a mutable reference to the proxy matcher.
    #[inline]
    pub fn proxy_matcher_mut(&mut self) -> &mut Option<Matcher> {
        &mut self.proxy_matcher
    }

    /// Get the enforced HTTP version.
    #[inline]
    pub fn enforced_version(&self) -> Option<Version> {
        self.enforced_version
    }

    /// Get a mutable reference to the enforced HTTP version.
    #[inline]
    pub fn enforced_version_mut(&mut self) -> &mut Option<Version> {
        &mut self.enforced_version
    }

    /// Get a reference to the TCP connection options.
    #[inline]
    pub fn tcp_connect_opts(&self) -> &TcpConnectOptions {
        &self.tcp_connect_opts
    }

    /// Get a mutable reference to the TCP connection options.
    #[inline]
    pub fn tcp_connect_opts_mut(&mut self) -> &mut TcpConnectOptions {
        &mut self.tcp_connect_opts
    }

    /// Get a reference to the transport options.
    #[inline]
    pub fn transport_opts(&self) -> &TransportOptions {
        &self.transport_opts
    }

    /// Get a mutable reference to the transport options.
    #[inline]
    pub fn transport_opts_mut(&mut self) -> &mut TransportOptions {
        &mut self.transport_opts
    }
}
