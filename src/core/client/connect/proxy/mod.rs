//! Proxy helpers
#[cfg(feature = "socks")]
mod socks;
mod tunnel;

#[cfg(feature = "socks")]
pub use self::socks::{DnsResolve, Socks, SocksVersion};
pub use self::tunnel::Tunnel;
