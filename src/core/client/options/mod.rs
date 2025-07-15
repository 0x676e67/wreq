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
#[derive(Debug, Default, Clone)]
pub struct TransportOptions {
    tls_options: Option<TlsOptions>,
    http1_options: Option<Http1Options>,
    http2_options: Option<Http2Options>,
}

impl TransportOptions {
    /// Sets the HTTP/1 options configuration.
    #[inline]
    pub fn http1_options<C>(&mut self, config: C) -> &mut Self
    where
        C: Into<Option<Http1Options>>,
    {
        if let Some(http1) = config.into() {
            self.http1_options = Some(http1);
        }
        self
    }

    /// Sets the HTTP/2 options configuration.
    #[inline]
    pub fn http2_options<C>(&mut self, config: C) -> &mut Self
    where
        C: Into<Option<Http2Options>>,
    {
        if let Some(http2) = config.into() {
            self.http2_options = Some(http2);
        }
        self
    }

    /// Sets the TLS options configuration.
    #[inline]
    pub fn tls_options<C>(&mut self, config: C) -> &mut Self
    where
        C: Into<Option<TlsOptions>>,
    {
        if let Some(tls) = config.into() {
            self.tls_options = Some(tls);
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

/// Internal options that are extracted from request extensions and applied before connection
/// establishment.
///
/// This struct holds configuration that affects how a specific request will be processed,
/// including proxy settings, protocol enforcement, and connection parameters.
/// These options are typically set per-request and override any client-level defaults.
#[must_use]
#[derive(Debug, Default, Clone)]
pub(crate) struct PerRequestOptions {
    proxy_matcher: Option<Matcher>,
    enforced_version: Option<Version>,
    tcp_connect_opts: Option<TcpConnectOptions>,
    transport_opts: Option<TransportOptions>,
}

impl PerRequestOptions {
    /// Get mutable reference to the proxy matcher.
    #[inline]
    pub fn proxy_matcher_mut(&mut self) -> &mut Option<Matcher> {
        &mut self.proxy_matcher
    }

    /// Get the enforced HTTP version.
    #[inline]
    pub fn enforced_version(&self) -> Option<Version> {
        self.enforced_version
    }

    /// Get mutable reference to the enforced HTTP version.
    #[inline]
    pub fn enforced_version_mut(&mut self) -> &mut Option<Version> {
        &mut self.enforced_version
    }

    /// Get mutable reference to the TCP connection options.
    #[inline]
    pub fn tcp_connect_opts_mut(&mut self) -> &mut Option<TcpConnectOptions> {
        &mut self.tcp_connect_opts
    }

    /// Get mutable reference to the transport options.
    #[inline]
    pub fn transport_opts_mut(&mut self) -> &mut Option<TransportOptions> {
        &mut self.transport_opts
    }

    /// Consumes the per-request options and returns the individual parts.
    #[inline]
    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<Matcher>,
        Option<Version>,
        Option<TcpConnectOptions>,
        Option<TransportOptions>,
    ) {
        (
            self.proxy_matcher,
            self.enforced_version,
            self.tcp_connect_opts,
            self.transport_opts,
        )
    }
}
