//! Route selection shared by the stream and QUIC paths.

#[cfg(unix)]
use std::{path::Path, sync::Arc};

#[cfg(feature = "socks")]
use netty::proxy::socks::{DnsResolve, Version};

use super::request::ConnectRequest;
use crate::proxy::{Intercepted, Matcher, matcher::Intercept};

/// How a connection reaches its target. Selected once per attempt, so each path matches on a
/// route instead of on proxy URI schemes.
pub(crate) enum Route {
    /// No proxy.
    Direct,
    /// An `http` or `https` proxy: a CONNECT tunnel for `https` targets, forwarding otherwise.
    Http(Intercept),
    /// A SOCKS4 or SOCKS5 proxy, resolving the target locally or at the proxy.
    #[cfg(feature = "socks")]
    Socks {
        proxy: Intercept,
        version: Version,
        dns: DnsResolve,
    },
    /// A `quic` proxy, which carries HTTP/3 over MASQUE CONNECT-UDP.
    Quic(
        #[cfg_attr(
            not(feature = "http3"),
            expect(dead_code, reason = "Only the QUIC path connects through it")
        )]
        Intercept,
    ),
    /// A Unix socket in place of the network.
    #[cfg(unix)]
    Unix(Arc<Path>),
}

impl Route {
    /// Selects the route for `request`: its own proxy override decides, or else the first of
    /// the client's `proxies` that intercepts its origin.
    pub(crate) fn select(request: &ConnectRequest, proxies: &[Matcher]) -> Self {
        let uri = request.uri();
        let intercepted = request
            .config_override::<Matcher>()
            .and_then(|proxy| proxy.intercept(uri))
            .or_else(|| proxies.iter().find_map(|proxy| proxy.intercept(uri)));
        let proxy = match intercepted {
            None => return Self::Direct,
            #[cfg(unix)]
            Some(Intercepted::Unix(path)) => return Self::Unix(path),
            Some(Intercepted::Proxy(proxy)) => proxy,
        };

        #[cfg(feature = "socks")]
        if let Some((version, dns)) = match proxy.uri().scheme_str() {
            Some("socks4") => Some((Version::V4, DnsResolve::Local)),
            Some("socks4a") => Some((Version::V4, DnsResolve::Remote)),
            Some("socks5") => Some((Version::V5, DnsResolve::Local)),
            Some("socks5h") => Some((Version::V5, DnsResolve::Remote)),
            _ => None,
        } {
            return Self::Socks {
                proxy,
                version,
                dns,
            };
        }

        if proxy.uri().scheme_str() == Some("quic") {
            Self::Quic(proxy)
        } else {
            Self::Http(proxy)
        }
    }
}
