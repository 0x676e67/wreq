pub mod http1;
pub mod http2;

use http1::Http1Options;
use http2::Http2Options;

use crate::tls::TlsOptions;

/// Transport options for HTTP/1, HTTP/2, and TLS layers.
///
/// This struct allows you to customize protocol-specific and TLS settings
/// for network connections made by the client.
#[derive(Debug, Default, Clone)]
pub(crate) struct TransportOptions {
    tls: Option<TlsOptions>,
    http1: Option<Http1Options>,
    http2: Option<Http2Options>,
}

impl TransportOptions {
    /// Configures HTTP/1 settings.
    #[inline]
    pub fn configure_http1<C>(&mut self, config: C)
    where
        C: Into<Option<Http1Options>>,
    {
        self.http1 = config.into();
    }

    /// Configures HTTP/2 settings.
    #[inline]
    pub fn configure_http2<C>(&mut self, config: C)
    where
        C: Into<Option<Http2Options>>,
    {
        self.http2 = config.into();
    }

    /// Configures TLS settings for the transport layer.
    #[inline]
    pub fn configure_tls<C>(&mut self, config: C)
    where
        C: Into<Option<TlsOptions>>,
    {
        self.tls = config.into();
    }

    /// Decomposes the transport options into individual protocol configurations.
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
