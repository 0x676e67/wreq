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
#[must_use]
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct TransportOptions {
    tls_options: Option<TlsOptions>,
    http1_options: Option<Http1Options>,
    http2_options: Option<Http2Options>,
}

impl TransportOptions {
    /// Get the reference to the HTTP/1 options.
    #[inline]
    pub fn http1_options(&self) -> Option<&Http1Options> {
        self.http1_options.as_ref()
    }

    /// Sets the HTTP/1 options configuration.
    #[inline]
    pub fn set_http1_options<C>(&mut self, opts: C) -> &mut Self
    where
        C: Into<Option<Http1Options>>,
    {
        if let Some(opts) = opts.into() {
            self.http1_options = Some(opts);
        }
        self
    }

    /// Get the reference to the HTTP/2 options.
    #[inline]
    pub fn http2_options(&self) -> Option<&Http2Options> {
        self.http2_options.as_ref()
    }

    /// Sets the HTTP/2 options configuration.
    #[inline]
    pub fn set_http2_options<C>(&mut self, opts: C) -> &mut Self
    where
        C: Into<Option<Http2Options>>,
    {
        if let Some(opts) = opts.into() {
            self.http2_options = Some(opts);
        }
        self
    }

    /// Get the reference to the TLS options.
    #[inline]
    pub fn tls_options(&self) -> Option<&TlsOptions> {
        self.tls_options.as_ref()
    }

    /// Sets the TLS options configuration.
    #[inline]
    pub fn set_tls_options<C>(&mut self, opts: C) -> &mut Self
    where
        C: Into<Option<TlsOptions>>,
    {
        if let Some(opts) = opts.into() {
            self.tls_options = Some(opts);
        }
        self
    }

    /// Consumes the transport options and returns the individual parts.
    #[inline]
    pub fn into_parts(
        self,
    ) -> (
        Option<TlsOptions>,
        Option<Http1Options>,
        Option<Http2Options>,
    ) {
        (self.tls_options, self.http1_options, self.http2_options)
    }
}

/// Per-request configuration for proxy, protocol, and transport options.
/// Overrides client defaults for a single request.
#[must_use]
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
pub(crate) struct RequestOptions {
    proxy_matcher: Option<Matcher>,
    enforced_version: Option<Version>,
    tcp_connect_opts: Option<TcpConnectOptions>,
    transport_opts: Option<TransportOptions>,
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
    pub fn tcp_connect_opts(&self) -> Option<&TcpConnectOptions> {
        self.tcp_connect_opts.as_ref()
    }

    /// Get a mutable reference to the TCP connection options.
    #[inline]
    pub fn tcp_connect_opts_mut(&mut self) -> &mut Option<TcpConnectOptions> {
        &mut self.tcp_connect_opts
    }

    /// Get a reference to the transport options.
    #[inline]
    pub fn transport_opts(&self) -> Option<&TransportOptions> {
        self.transport_opts.as_ref()
    }

    /// Get a mutable reference to the transport options.
    #[inline]
    pub fn transport_opts_mut(&mut self) -> &mut Option<TransportOptions> {
        &mut self.transport_opts
    }
}
