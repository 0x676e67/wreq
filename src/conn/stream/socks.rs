//! SOCKS negotiation over a TCP proxy socket.

use std::time::Instant;

use http::Uri;
use netty::proxy::socks::{DnsResolve, SocksConnector, SocksError, Version};
use tower::ServiceExt;

use crate::{
    conn::dialer::{Dial, Dialer, SocketBindings},
    dns::{DynResolver, Name},
    ext::UriExt,
    proxy::matcher::Intercept,
    rt::BoxConnection,
};

/// Dials the proxy and negotiates a SOCKS connection to the request's origin.
///
/// The dialer resolves the proxy address. The DNS mode controls whether netty
/// resolves the origin locally or passes its hostname to the proxy.
pub(super) async fn connect(
    dialer: Dialer,
    resolver: DynResolver,
    target: &Uri,
    bindings: SocketBindings,
    deadline: Option<Instant>,
    proxy: &Intercept,
    (version, dns): (Version, DnsResolve),
) -> Result<BoxConnection, SocksError> {
    let is_https = target.is_https();
    let resolver = resolver.map_request(Name::new);
    let connect_proxy = dialer.map_request(move |uri: Uri| Dial::Tcp {
        nodelay: is_https || uri.is_https(),
        uri,
        bindings: bindings.clone(),
        deadline,
    });
    let mut connector = SocksConnector::new(proxy.uri().clone(), connect_proxy, resolver);
    connector.set_auth(proxy.raw_auth());
    connector.set_version(version);
    connector.set_dns_mode(dns);
    connector.oneshot(target.clone()).await
}
