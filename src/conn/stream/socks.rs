//! SOCKS negotiation over a TCP proxy socket.

use std::time::Instant;

use netty::proxy::socks::{DnsResolve, SocksConnector, SocksError, Version};
use tower::{ServiceExt, service_fn};

use super::tcp_request;
use crate::{
    conn::{dialer::Dialer, request::ConnectRequest},
    dns::Name,
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
    proxy: &Intercept,
    version: Version,
    dns: DnsResolve,
    deadline: Option<Instant>,
) -> Result<BoxConnection, SocksError> {
    let connect_proxy = service_fn(|uri| dialer.dial(tcp_request(request, uri, deadline)));
    let resolver = dialer.resolver().clone().map_request(Name::new);
    let mut connector = SocksConnector::new(proxy.uri().clone(), connect_proxy, resolver);
    connector.set_auth(proxy.raw_auth());
    connector.set_version(version);
    connector.set_dns_mode(dns);
    connector.oneshot(request.uri().clone()).await
}
