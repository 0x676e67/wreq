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
