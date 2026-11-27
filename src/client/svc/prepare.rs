//! Request validation, upgrade planning, and pool key freezing before dispatch.

use http::{Method, Version};

use super::super::{
    error::{self, ErrorKind},
    request::RequestVersion,
    upgrade,
};
use crate::{
    Body,
    config::{ConnectConfig, RequestConfig},
    conn,
    ext::UriExt,
    protocol::Protocol,
    reuse,
};

/// Validated connection request and pool keys extracted once before dispatch.
pub(super) struct Prepared {
    pub(super) request: conn::Request<ConnectConfig>,
    pub(super) key: Option<reuse::Key>,
    pub(super) negotiable: bool,
    pub(super) upgrade: upgrade::Plan,
}

impl Prepared {
    /// Validates `request` and freezes its pool key and connection config before dispatch.
    ///
    /// Redirect hops and user-level retries pass through here again.
    pub(super) fn prepare(
        request: &mut http::Request<Body>,
        client_protocol: Protocol,
        config: &RequestConfig<ConnectConfig>,
    ) -> Result<Self, error::Error> {
        match request.version() {
            Version::HTTP_10 if request.method() == Method::CONNECT => {
                warn!("CONNECT is not allowed for HTTP/1.0");
                return Err(error::Error::from_kind(
                    ErrorKind::UserUnsupportedRequestMethod,
                ));
            }
            Version::HTTP_10 | Version::HTTP_11 => {}
            #[cfg(feature = "http2")]
            Version::HTTP_2 => {}
            #[cfg(feature = "http3")]
            Version::HTTP_3 => {}
            _unsupported => {
                warn!("Request has unsupported version: {:?}", _unsupported);
                return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion));
            }
        }

        // Senders must not generate userinfo (RFC 9110 section 4.2.4), and the
        // connection origin is taken from this authority:
        // <https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.4>
        if request
            .uri()
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        {
            request.uri_mut().set_userinfo("", None);
        }

        let extensions = request.extensions_mut();
        let upgrade = RequestConfig::<upgrade::Upgrade>::default().remove(extensions);
        // Normalize wire versions to protocol choices; HTTP/1.0 and HTTP/1.1 share a pool.
        let version = RequestConfig::<RequestVersion>::default().remove(extensions);
        let uri = request.uri();

        let dedicated = match upgrade.as_ref() {
            Some(upgrade) => {
                upgrade.validate_request(request.method(), request.version(), version)?
            }
            None => false,
        };

        // curl's ordinary H2 mode allows HTTPS negotiation; prior knowledge
        // remains explicit: https://curl.se/libcurl/c/CURLOPT_HTTP_VERSION.html
        let protocol = if dedicated {
            Some(Protocol::Http1)
        } else {
            match version {
                Some(Version::HTTP_10 | Version::HTTP_11) => Some(Protocol::Http1),
                #[cfg(feature = "http2")]
                Some(Version::HTTP_2) if uri.is_https() && client_protocol != Protocol::Http2 => {
                    Some(Protocol::Auto)
                }
                #[cfg(feature = "http2")]
                Some(Version::HTTP_2) => Some(Protocol::Http2),
                #[cfg(feature = "http3")]
                Some(Version::HTTP_3) => Some(Protocol::Http3),
                Some(_) => {
                    return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion));
                }
                None => None,
            }
        };

        let origin = uri.origin().map_err(|source| {
            debug!("Client requires absolute-form URIs, received: {uri:?}");
            error::Error::new(ErrorKind::UserAbsoluteUriRequired, source)
        })?;
        let negotiable = protocol == Some(Protocol::Auto);
        let protocol = protocol.unwrap_or(client_protocol);

        // HTTP/3 has no cleartext form; an https-to-http redirect also ends here:
        // https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1
        #[cfg(feature = "http3")]
        if protocol == Protocol::Http3 && !uri.is_https() {
            warn!("HTTP/3 requires an https URI");
            return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
                .with_context("HTTP/3 requires an https URI"));
        }

        let config = config
            .remove(request.extensions_mut())
            .unwrap_or_default()
            .with_base(config.as_ref());
        let request = conn::Request::new(origin, protocol, config);
        let key = (!dedicated).then(|| request.reuse_key(protocol));

        let upgrade = upgrade::Plan::new(
            upgrade,
            protocol,
            client_protocol,
            request.uri().is_https(),
            |protocol| request.reuse_key(protocol),
        )?;

        Ok(Self {
            request,
            key,
            negotiable,
            upgrade,
        })
    }
}
