use std::net::{Ipv4Addr, Ipv6Addr};

use http::{
    Request, Uri, Version,
    uri::{PathAndQuery, Scheme},
};

use super::{Error, ErrorKind, PoolKey, set_scheme};
use crate::{
    core::ext::{
        RequestConfig, RequestHttpVersionPref, RequestInterface, RequestIpv4Addr, RequestIpv6Addr,
        RequestProxyMatcher,
    },
    proxy::Intercepted,
    tls::AlpnProtocol,
};

/// Destination of the request.
///
/// The `Dst` struct is used to store the destination of the request, including the HTTP version
/// preference, network scheme, and the pool key. It provides methods to create and manipulate the
/// destination.
#[derive(Debug, Clone)]
pub struct Dst(PoolKey);

impl Dst {
    /// Creates a new `Dst`.
    ///
    /// This method initializes a new `Dst` instance based on the provided URI, HTTP connect flag,
    /// network scheme, and HTTP version.
    pub(crate) fn new<B>(req: &mut Request<B>, is_http_connect: bool) -> Result<Dst, Error> {
        let uri = req.uri_mut();
        let (scheme, auth) = match (uri.scheme().cloned(), uri.authority().cloned()) {
            (Some(scheme), Some(auth)) => (scheme, auth),
            (None, Some(auth)) if is_http_connect => {
                let scheme = match auth.port_u16() {
                    Some(443) => {
                        set_scheme(uri, Scheme::HTTPS);
                        Scheme::HTTPS
                    }
                    _ => {
                        set_scheme(uri, Scheme::HTTP);
                        Scheme::HTTP
                    }
                };
                (scheme, auth)
            }
            _ => {
                return Err(Error {
                    kind: ErrorKind::UserAbsoluteUriRequired,
                    source: Some(
                        format!("Client requires absolute-form URIs, received: {:?}", uri).into(),
                    ),
                    connect_info: None,
                });
            }
        };

        let extensions = req.extensions_mut();

        let version = RequestConfig::<RequestHttpVersionPref>::remove(extensions);

        let alpn = match version {
            Some(Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09) => {
                Some(AlpnProtocol::HTTP1)
            }
            Some(Version::HTTP_2) => Some(AlpnProtocol::HTTP2),
            _ => None,
        };

        let local_ipv4_address = RequestConfig::<RequestIpv4Addr>::remove(extensions);
        let local_ipv6_address = RequestConfig::<RequestIpv6Addr>::remove(extensions);
        let interface = RequestConfig::<RequestInterface>::remove(extensions);
        let proxy_scheme = RequestConfig::<RequestProxyMatcher>::remove(extensions);

        // Convert the scheme and host to a URI
        Uri::builder()
            .scheme(scheme)
            .authority(auth)
            .path_and_query(PathAndQuery::from_static("/"))
            .build()
            .map(|uri| {
                let proxy_intercepted = proxy_scheme.and_then(|matcher| matcher.intercept(&uri));
                Dst((
                    uri,
                    alpn,
                    local_ipv4_address,
                    local_ipv6_address,
                    interface,
                    proxy_intercepted,
                ))
            })
            .map_err(Into::into)
    }

    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn uri(&self) -> &Uri {
        &self.0.0
    }

    #[inline(always)]
    pub(crate) fn set_uri(&mut self, mut uri: Uri) {
        std::mem::swap(&mut self.0.0, &mut uri);
    }

    #[inline(always)]
    pub(crate) fn alpn_protos(&self) -> Option<AlpnProtocol> {
        self.0.1
    }

    #[inline(always)]
    pub(crate) fn only_http2(&self) -> bool {
        self.0.1 == Some(AlpnProtocol::HTTP2)
    }

    #[inline(always)]
    pub(crate) fn addresses(&self) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        (self.0.2, self.0.3)
    }

    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    #[inline(always)]
    pub(crate) fn interface(&mut self) -> Option<std::borrow::Cow<'static, str>> {
        self.0.4.take()
    }

    #[inline(always)]
    pub(crate) fn take_proxy_intercepted(&mut self) -> Option<Intercepted> {
        self.0.5.take()
    }

    #[inline(always)]
    pub(super) fn pool_key(&self) -> &PoolKey {
        &self.0
    }
}
