//! HTTP upgrade and Extended CONNECT support ([RFC 9110 §7.8], [RFC 8441], [RFC 9220]).
//!
//! [RFC 9110 §7.8]: https://www.rfc-editor.org/rfc/rfc9110#section-7.8
//! [RFC 8441]: https://www.rfc-editor.org/rfc/rfc8441
//! [RFC 9220]: https://www.rfc-editor.org/rfc/rfc9220

use std::{
    borrow::Cow,
    fmt, io,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use http::{HeaderName, Method, Version};
use netty::upgrade;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(any(feature = "http2", feature = "http3"))]
use {
    crate::{protocol::Protocol as ClientProtocol, reuse},
    http::{
        HeaderMap,
        header::{CONNECTION, UPGRADE},
    },
    std::mem,
};

use super::error::{self, ErrorKind};
use crate::{Error, config::impl_request_config_value};

/// A bidirectional stream from an HTTP upgrade or CONNECT tunnel.
/// An HTTP/2 or HTTP/3 tunnel owns one stream on a shared connection and shares its flow
/// control; an HTTP/3 tunnel also holds one `Http3Options::max_concurrent_requests` slot
/// until it closes.
#[derive(Debug)]
pub struct Upgraded(upgrade::Upgraded);

/// Protocol token for HTTP Upgrade and Extended CONNECT (`:protocol`, [RFC 8441], [RFC 9220]).
///
/// [RFC 8441]: https://www.rfc-editor.org/rfc/rfc8441#section-4
/// [RFC 9220]: https://www.rfc-editor.org/rfc/rfc9220#section-3
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Protocol(Cow<'static, str>);

/// Request-level HTTP upgrade and Extended CONNECT configuration.
///
/// Controls connection pool isolation, Extended CONNECT `:protocol` signaling, and adaptive
/// reuse of an established HTTP/2 or HTTP/3 connection for HTTP/1.1 upgrades.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Upgrade(Kind);

#[derive(Clone, Debug, Eq, PartialEq)]
enum Kind {
    Http1,
    ExtendedConnect(Protocol),
    Adaptive {
        protocol: Protocol,
        strip_headers: Option<Arc<[HeaderName]>>,
    },
}

/// Prepared upgrade plan consumed by `svc::Client` across connection checkouts and retries.
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) enum Plan {
    ExtendedConnect(Protocol),
    Adaptive {
        key: reuse::Key,
        protocol: Protocol,
        strip_headers: Option<Arc<[HeaderName]>>,
    },
}

/// Original HTTP/1 upgrade fields saved while attempting Extended CONNECT, restored if unsent.
#[cfg(any(feature = "http2", feature = "http3"))]
pub(super) struct Rewritten {
    method: Method,
    version: Version,
    headers: HeaderMap,
}

// ===== impl Upgraded =====

impl AsyncRead for Upgraded {
    #[inline(always)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Upgraded {
    #[inline(always)]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    #[inline(always)]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    #[inline(always)]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    #[inline(always)]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    #[inline(always)]
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

impl From<upgrade::Upgraded> for Upgraded {
    fn from(inner: upgrade::Upgraded) -> Self {
        Upgraded(inner)
    }
}

// ===== impl Response =====

impl super::response::Response {
    /// Consumes the response and returns a future for a possible HTTP upgrade.
    pub async fn upgrade(self) -> crate::Result<Upgraded> {
        upgrade::on(http::Response::from(self))
            .await
            .map(Upgraded::from)
            .map_err(Error::upgrade)
    }
}

// ===== impl Protocol =====

impl Protocol {
    /// WebSocket protocol ([RFC 8441], [RFC 9220]).
    ///
    /// [RFC 8441]: https://www.rfc-editor.org/rfc/rfc8441
    /// [RFC 9220]: https://www.rfc-editor.org/rfc/rfc9220
    pub const WEBSOCKET: Self = Self::from_static("websocket");
    /// WebTransport protocol.
    pub const WEB_TRANSPORT: Self = Self::from_static("webtransport");
    /// UDP proxying over HTTP ([RFC 9298](https://www.rfc-editor.org/rfc/rfc9298)).
    pub const CONNECT_UDP: Self = Self::from_static("connect-udp");
    /// IP proxying over HTTP ([RFC 9484](https://www.rfc-editor.org/rfc/rfc9484)).
    pub const CONNECT_IP: Self = Self::from_static("connect-ip");

    /// Creates a protocol token from a static string without allocating.
    #[inline]
    #[must_use]
    pub const fn from_static(value: &'static str) -> Self {
        Self(Cow::Borrowed(value))
    }

    /// Returns the wire `:protocol` token string.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    #[cfg(feature = "http3")]
    #[must_use]
    fn to_http3(&self) -> Option<netty::http3::Protocol> {
        self.as_str().parse().ok()
    }

    /// Inserts the wire `:protocol` extension for `version`, or returns a version error.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) fn insert_into<B>(
        &self,
        request: &mut http::Request<B>,
        version: Version,
    ) -> Result<(), error::Error> {
        let extensions = request.extensions_mut();
        match version {
            #[cfg(feature = "http2")]
            Version::HTTP_2 => {
                let protocol = match &self.0 {
                    Cow::Borrowed(value) => http2::ext::Protocol::from_static(value),
                    Cow::Owned(value) => http2::ext::Protocol::from(value.as_str()),
                };
                extensions.insert(protocol);
                Ok(())
            }
            #[cfg(feature = "http3")]
            Version::HTTP_3 => {
                let Some(protocol) = self.to_http3() else {
                    warn!("extended CONNECT protocol {self:?} is not supported on HTTP/3");
                    return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
                        .with_context("extended CONNECT protocol is not supported on HTTP/3"));
                };
                extensions.insert(protocol);
                Ok(())
            }
            _ => Err(requires_multiplexed()),
        }
    }

    /// Removes any wire `:protocol` extensions inserted for HTTP/2 or HTTP/3.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) fn clear_from<B>(request: &mut http::Request<B>) {
        let extensions = request.extensions_mut();
        #[cfg(feature = "http2")]
        extensions.remove::<http2::ext::Protocol>();
        #[cfg(feature = "http3")]
        extensions.remove::<netty::http3::Protocol>();
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for Protocol {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&'static str> for Protocol {
    #[inline]
    fn from(value: &'static str) -> Self {
        Self::from_static(value)
    }
}

impl From<String> for Protocol {
    #[inline]
    fn from(value: String) -> Self {
        Self(Cow::Owned(value))
    }
}

impl From<Cow<'static, str>> for Protocol {
    #[inline]
    fn from(value: Cow<'static, str>) -> Self {
        Self(value)
    }
}

// ===== impl Upgrade =====

impl_request_config_value!(Upgrade);

impl Upgrade {
    /// Uses a dedicated HTTP/1 connection that bypasses the pool.
    #[inline]
    #[must_use]
    pub const fn http1() -> Self {
        Self(Kind::Http1)
    }

    /// Uses Extended CONNECT (`:protocol`) over HTTP/2 or HTTP/3.
    ///
    /// Requires `Method::CONNECT` and fails before sending if the connection uses HTTP/1,
    /// cannot encode `protocol`, or the peer did not enable Extended CONNECT.
    #[inline]
    #[must_use]
    pub fn extended_connect<P: Into<Protocol>>(protocol: P) -> Self {
        Self(Kind::ExtendedConnect(protocol.into()))
    }

    /// Uses a dedicated HTTP/1 upgrade, first probing an established HTTP/2 or HTTP/3
    /// connection whose peer enabled Extended CONNECT for `protocol`.
    ///
    /// On a hit, rewrites to `CONNECT` with `:protocol` (stripping `connection`, `upgrade`,
    /// and [`Self::strip_headers`]) and restores the original request if unsent.
    #[inline]
    #[must_use]
    pub fn adaptive<P: Into<Protocol>>(protocol: P) -> Self {
        Self(Kind::Adaptive {
            protocol: protocol.into(),
            strip_headers: None,
        })
    }

    /// Strips additional HTTP/1-only headers when an [`Self::adaptive`] upgrade rewrites for
    /// Extended CONNECT (`connection` and `upgrade` are always stripped).
    #[inline]
    #[must_use]
    pub fn strip_headers<I: IntoIterator<Item = HeaderName>>(mut self, headers: I) -> Self {
        if let Kind::Adaptive { strip_headers, .. } = &mut self.0 {
            let headers: Arc<[HeaderName]> = headers.into_iter().collect();
            *strip_headers = (!headers.is_empty()).then_some(headers);
        }
        self
    }

    /// Returns the Extended CONNECT protocol token, if configured.
    #[inline]
    #[must_use]
    pub fn protocol(&self) -> Option<&Protocol> {
        match &self.0 {
            Kind::Http1 => None,
            Kind::ExtendedConnect(protocol) | Kind::Adaptive { protocol, .. } => Some(protocol),
        }
    }

    /// Validates method and version, returning `true` for a dedicated HTTP/1 path.
    pub(super) fn validate_request(
        &self,
        method: &Method,
        wire_version: Version,
        request_version: Option<Version>,
    ) -> Result<bool, error::Error> {
        match &self.0 {
            Kind::Http1 | Kind::Adaptive { .. } => {
                if !matches!(
                    request_version.unwrap_or(wire_version),
                    Version::HTTP_10 | Version::HTTP_11
                ) {
                    warn!("HTTP/1 upgrade cannot be combined with a non-HTTP/1 request version");
                    return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion));
                }
                Ok(true)
            }
            Kind::ExtendedConnect(_) => {
                if *method != Method::CONNECT {
                    warn!("extended CONNECT requires the CONNECT method");
                    return Err(error::Error::from_kind(
                        ErrorKind::UserUnsupportedRequestMethod,
                    ));
                }
                #[cfg(not(any(feature = "http2", feature = "http3")))]
                return Err(requires_multiplexed());
                #[cfg(any(feature = "http2", feature = "http3"))]
                Ok(false)
            }
        }
    }

    /// Validates protocol compatibility and constructs the dispatch plan for H2/H3.
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) fn into_plan(
        self,
        protocol: ClientProtocol,
        client_protocol: ClientProtocol,
        is_https: bool,
        reuse_key: impl FnOnce(ClientProtocol) -> reuse::Key,
    ) -> Result<Option<Box<Plan>>, error::Error> {
        match self.0 {
            Kind::Http1 => Ok(None),
            Kind::ExtendedConnect(proto) => {
                if protocol == ClientProtocol::Http1 {
                    return Err(requires_multiplexed());
                }
                #[cfg(feature = "http3")]
                if protocol == ClientProtocol::Http3 && proto.to_http3().is_none() {
                    warn!("extended CONNECT protocol {proto:?} is not supported on HTTP/3");
                    return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
                        .with_context("extended CONNECT protocol is not supported on HTTP/3"));
                }
                Ok(Some(Box::new(Plan::ExtendedConnect(proto))))
            }
            Kind::Adaptive {
                protocol: proto,
                strip_headers,
            } => {
                let probe = match client_protocol {
                    #[cfg(feature = "http2")]
                    ClientProtocol::Auto | ClientProtocol::Http2 => true,
                    #[cfg(feature = "http3")]
                    ClientProtocol::Http3 => is_https && proto.to_http3().is_some(),
                    _ => false,
                };
                #[cfg(not(feature = "http3"))]
                let _ = is_https;
                Ok(probe.then(|| {
                    Box::new(Plan::Adaptive {
                        key: reuse_key(client_protocol),
                        protocol: proto,
                        strip_headers,
                    })
                }))
            }
        }
    }
}

// ===== impl Rewritten =====

#[cfg(any(feature = "http2", feature = "http3"))]
impl Rewritten {
    /// Rewrites an HTTP/1 upgrade request as Extended CONNECT for `version` ([RFC 8441 §5],
    /// [RFC 9220 §3]), returning `None` untouched if `version` cannot encode `protocol`.
    ///
    /// [RFC 8441 §5]: https://www.rfc-editor.org/rfc/rfc8441#section-5
    /// [RFC 9220 §3]: https://www.rfc-editor.org/rfc/rfc9220#section-3
    #[must_use]
    pub(super) fn try_rewrite<B>(
        request: &mut http::Request<B>,
        version: Version,
        protocol: &Protocol,
        strip_headers: &[HeaderName],
    ) -> Option<Box<Self>> {
        protocol.insert_into(request, version).ok()?;
        let method = mem::replace(request.method_mut(), Method::CONNECT);
        let orig_version = mem::replace(request.version_mut(), version);
        let headers = mem::take(request.headers_mut());
        // Connection-specific fields are malformed in HTTP/2 and HTTP/3; the rest keep their order:
        // https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2
        // https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        let extended = request.headers_mut();
        extended.reserve(headers.len());
        for (name, value) in &headers {
            if name != UPGRADE && name != CONNECTION && !strip_headers.contains(name) {
                extended.append(name, value.clone());
            }
        }
        Some(Box::new(Self {
            method,
            version: orig_version,
            headers,
        }))
    }

    /// Restores the original HTTP/1 upgrade request after an unsent Extended CONNECT.
    pub(super) fn restore<B>(self, request: &mut http::Request<B>) {
        *request.method_mut() = self.method;
        *request.version_mut() = self.version;
        Protocol::clear_from(request);
        *request.headers_mut() = self.headers;
    }
}

#[must_use]
fn requires_multiplexed() -> error::Error {
    warn!("extended CONNECT requires HTTP/2 or HTTP/3");
    error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
        .with_context("extended CONNECT requires HTTP/2 or HTTP/3")
}
