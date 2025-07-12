pub mod http1;
pub mod http2;

use http1::Http1Options;
use http2::Http2Options;

use crate::tls::TlsOptions;

/// Transport options for HTTP/1, HTTP/2, and TLS layers.
///
/// This struct allows you to customize protocol-specific and TLS settings
/// for network connections made by the client.
#[must_use]
#[derive(Debug, Default, Clone)]
pub(crate) struct TransportOptions {
    tls: Option<TlsOptions>,
    http1: Option<Http1Options>,
    http2: Option<Http2Options>,
}

impl TransportOptions {
    /// Sets the HTTP/1 options configuration.
    #[inline]
    pub fn configure_http1<C>(&mut self, config: C)
    where
        C: Into<Option<Http1Options>>,
    {
        self.http1 = config.into();
    }

    /// Sets the HTTP/2 options configuration.
    #[inline]
    pub fn configure_http2<C>(&mut self, config: C)
    where
        C: Into<Option<Http2Options>>,
    {
        self.http2 = config.into();
    }

    /// Sets the TLS options configuration.
    #[inline]
    pub fn configure_tls<C>(&mut self, config: C)
    where
        C: Into<Option<TlsOptions>>,
    {
        self.tls = config.into();
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
        (self.tls, self.http1, self.http2)
    }
}
