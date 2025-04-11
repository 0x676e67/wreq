use super::{Error, ErrorKind, NetworkScheme, PoolKey, set_scheme};
use crate::proxy::ProxyScheme;
use crate::{AlpnProtos, util::into_uri};
use http::{Uri, Version, uri::Scheme};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;

/// Destination of the request.
///
/// The `Dst` struct is used to store the destination of the request, including the HTTP version preference,
/// network scheme, and the pool key. It provides methods to create and manipulate the destination.
#[derive(Debug, Clone)]
pub struct Dst(PoolKey);

impl Dst {
    /// Creates a new `Dst`.
    ///
    /// This method initializes a new `Dst` instance based on the provided URI, HTTP connect flag,
    /// network scheme, and HTTP version.
    ///
    /// # Parameters
    ///
    /// - `uri`: A mutable reference to the URI of the request.
    /// - `is_http_connect`: A boolean indicating whether the request is an HTTP CONNECT request.
    /// - `network`: The network scheme to be used for the request.
    /// - `version`: An optional HTTP version for the request.
    ///
    /// # Returns
    ///
    /// A `Result` containing the constructed `Dst` or an `Error` if the URI is not absolute.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rquest::util::client::dst::Dst;
    /// use http::Uri;
    ///
    /// let mut uri: Uri = "http://example.com".parse().unwrap();
    /// let dst = Dst::new(&mut uri, false, Default::default(), None).unwrap();
    /// ```
    pub fn new(
        uri: &mut Uri,
        is_http_connect: bool,
        network: NetworkScheme,
        version: Option<Version>,
    ) -> Result<Dst, Error> {
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

        let alpn = match version {
            Some(Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09) => Some(AlpnProtos::HTTP1),
            Some(Version::HTTP_2) => Some(AlpnProtos::HTTP2),
            _ => None,
        };

        // Convert the scheme and host to a URI
        into_uri(scheme, auth)
            .map(|uri| Dst(PoolKey { uri, alpn, network }))
            .map_err(Into::into)
    }

    /// Returns a reference to the URI of the destination.
    #[inline(always)]
    pub(crate) fn uri(&self) -> &Uri {
        &self.0.uri
    }

    /// Sets a new URI for the destination.
    #[inline(always)]
    pub(crate) fn set_uri(&mut self, mut uri: Uri) {
        std::mem::swap(&mut self.0.uri, &mut uri);
    }

    /// Returns the ALPN protocols of the destination.
    #[inline(always)]
    pub(crate) fn alpn_protos(&self) -> Option<AlpnProtos> {
        self.0.alpn
    }

    /// Checks if the destination only supports HTTP/2.
    #[inline(always)]
    pub(crate) fn only_http2(&self) -> bool {
        self.0.alpn == Some(AlpnProtos::HTTP2)
    }

    /// Takes the IP addresses from the network scheme.
    #[inline(always)]
    pub(crate) fn take_addresses(&mut self) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        self.0.network.take_addresses()
    }

    /// Takes the network interface from the network scheme.
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
    pub(crate) fn take_interface(&mut self) -> Option<std::borrow::Cow<'static, str>> {
        self.0.network.take_interface()
    }

    /// Takes the proxy scheme from the network scheme.
    #[inline(always)]
    pub(crate) fn take_proxy_scheme(&mut self) -> Option<ProxyScheme> {
        self.0.network.take_proxy_scheme()
    }

    /// Returns a reference to the pool key of the destination.
    #[inline(always)]
    pub(super) fn pool_key(&self) -> &PoolKey {
        &self.0
    }
}

impl Deref for Dst {
    type Target = Uri;

    fn deref(&self) -> &Self::Target {
        &self.0.uri
    }
}

impl From<Dst> for Uri {
    fn from(dst: Dst) -> Self {
        dst.0.uri
    }
}
