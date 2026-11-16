//! SOCKS negotiation over a TCP proxy socket.

use std::time::Instant;

use http::Uri;
use netty::proxy::socks::{DnsResolve, SocksConnector, SocksError, Version};
use tower::{ServiceExt, service_fn};

use crate::{
    conn::{
        dialer::{Dialer, SocketRequest},
        request::ConnectRequest,
    },
    dns::Name,
    ext::UriExt,
    proxy::matcher::Intercept,
    rt::BoxConnection,
};

/// Dials the proxy and negotiates a SOCKS connection to the request's origin.
///
/// The dialer resolves the proxy address. The DNS mode controls whether netty
/// resolves the origin locally or passes its hostname to the proxy.
pub(super) async fn connect(
    dialer: &Dialer,
    request: &ConnectRequest,
    deadline: Option<Instant>,
    proxy: &Intercept,
    version: Version,
    dns: DnsResolve,
) -> Result<BoxConnection, SocksError> {
    let bindings = dialer.bindings(request.bindings());
    let is_https = request.uri().is_https();
    let resolver = dialer.resolver().clone().map_request(Name::new);
    let dialer = dialer.clone();
    let connect_proxy = service_fn(move |uri: Uri| {
        let secure = is_https || uri.is_https();
        dialer.dial(SocketRequest::Tcp {
            secure,
            uri,
            bindings: bindings.clone(),
            deadline,
        })
    });
    let mut connector = SocksConnector::new(proxy.uri().clone(), connect_proxy, resolver);
    connector.set_auth(proxy.raw_auth());
    connector.set_version(version);
    connector.set_dns_mode(dns);
    connector.oneshot(request.uri().clone()).await
}
