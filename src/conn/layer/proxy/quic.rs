//! QUIC proxy tunnels: MASQUE CONNECT-UDP and SOCKS5 UDP associations.
//! Proxy setup and the target handshake share the connector's deadline.

pub(crate) mod masque;
#[cfg(feature = "socks")]
pub(crate) mod socks;
