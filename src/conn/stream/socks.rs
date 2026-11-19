//! SOCKS negotiation over a TCP proxy socket.

use http::{Request, Uri};
use netty::proxy::socks::{DnsResolve, SocksConnector, SocksError, Version};
use tower::ServiceExt;

use crate::{
    config::connect::ConnectConfig,
    conn::dialer::{Dial, Dialer},
    dns::{DynResolver, Name},
    ext::UriExt,
    proxy::matcher::Intercept,
    rt::Connection,
};

/// Dials the proxy and negotiates a SOCKS connection to the request's origin.
///
/// The dialer resolves the proxy address. The DNS mode controls whether netty
/// resolves the origin locally or passes its hostname to the proxy.
pub(super) async fn connect(
    dialer: Dialer,
    resolver: DynResolver,
    request: &Request<ConnectConfig>,
    proxy: &Intercept,
    (version, dns): (Version, DnsResolve),
) -> Result<Box<dyn Connection>, SocksError> {
    let target = request.uri();
    let is_https = target.is_https();
    let resolver = resolver.map_request(Name::new);
    let svc = dialer.map_request(move |uri: Uri| {
        let nodelay = is_https || uri.is_https();
        Dial::tcp(request, uri, nodelay)
    });
    let mut connector = SocksConnector::new(proxy.uri().clone(), svc, resolver);
    connector.set_auth(proxy.raw_auth());
    connector.set_version(version);
    connector.set_dns_mode(dns);
    connector.oneshot(target.clone()).await
}
