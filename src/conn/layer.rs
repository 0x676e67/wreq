//! Connection middleware stacked on the leaf transports, like `client::layer` on the client.
//!
//! [`proxy`] wraps the socket dialer with stream proxy routes and target TLS, and the QUIC
//! transport with MASQUE and SOCKS5 UDP routes. [`timeout`] bounds one connector call.

pub(crate) mod proxy;
pub(crate) mod timeout;
