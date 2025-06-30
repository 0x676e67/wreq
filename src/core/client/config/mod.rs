pub mod http1;
pub mod http2;

use crate::tls;

/// TransportConfig holds configuration for HTTP/1, HTTP/2, and TLS transport layers.
///
/// This struct allows you to customize protocol-specific and TLS settings
/// for network connections made by the client.
#[derive(Debug, Clone)]
pub(crate) struct TransportConfig {
    pub(super) http1: Option<http1::Http1Config>,
    pub(super) http2: Option<http2::Http2Config>,
    pub(super) tls: Option<tls::TlsConfig>,
}
