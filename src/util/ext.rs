use http::{uri::Uri, HeaderValue};
use std::net::IpAddr;

/// Extension for pool key
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum PoolKeyExtension {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    Interface(std::borrow::Cow<'static, str>),
    Address(Option<IpAddr>, Option<IpAddr>),
    Http(Uri, Option<HeaderValue>),
    #[cfg(feature = "socks")]
    Socks4(std::net::SocketAddr, Option<(String, String)>),
    #[cfg(feature = "socks")]
    Socks5(std::net::SocketAddr, Option<(String, String)>),
}
