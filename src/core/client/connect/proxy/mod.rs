//! Proxy helpers
#[cfg(feature = "socks")]
mod socks;
mod tunnel;

#[cfg(feature = "socks")]
pub use self::socks::{DnsResolve, SocksConnector, Version};
pub use self::tunnel::TunnelConnector;
