pub mod http1;
pub mod http2;

use http1::Http1Config;
use http2::Http2Config;

use crate::tls::TlsConfig;

/// TransportConfig holds configuration for HTTP/1, HTTP/2, and TLS transport layers.
///
/// This struct allows you to customize protocol-specific and TLS settings
/// for network connections made by the client.
#[derive(Debug, Default, Clone)]
pub(crate) struct TransportConfig {
    pub(super) http1_config: Option<Http1Config>,
    pub(super) http2_config: Option<Http2Config>,
    pub(super) tls_config: Option<TlsConfig>,
}

impl TransportConfig {
    /// Sets the HTTP/1 configuration.
    #[inline]
    pub fn set_http1_config<C>(&mut self, config: C)
    where
        C: Into<Option<Http1Config>>,
    {
        self.http1_config = config.into();
    }

    /// Sets the HTTP/2 configuration.
    #[inline]
    pub fn set_http2_config<C>(&mut self, config: C)
    where
        C: Into<Option<Http2Config>>,
    {
        self.http2_config = config.into();
    }

    /// Sets the TLS configuration.
    #[inline]
    pub fn set_tls_config<C>(&mut self, config: C)
    where
        C: Into<Option<TlsConfig>>,
    {
        self.tls_config = config.into();
    }
}
