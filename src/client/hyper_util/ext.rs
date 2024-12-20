use http::{
    uri::{Authority, Scheme},
    HeaderValue,
};
use std::net::IpAddr;

/// Extension for pool key
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum PoolKeyExtension {
    /// Interface name
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    Interface(std::borrow::Cow<'static, str>),
    /// Local address
    Address(Option<IpAddr>, Option<IpAddr>),
    /// Http,Https proxy pool key
    Http(Scheme, Authority, Option<HeaderValue>),
    /// Socks4 proxy pool key
    #[cfg(feature = "socks")]
    Socks4(std::net::SocketAddr, Option<(String, String)>),
    /// Socks5 proxy pool key
    #[cfg(feature = "socks")]
    Socks5(std::net::SocketAddr, Option<(String, String)>),
}
