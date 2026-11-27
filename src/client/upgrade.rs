//! HTTP upgrade and Extended CONNECT support ([RFC 9110 §7.8], [RFC 8441], [RFC 9220]).
//!
//! [RFC 9110 §7.8]: https://www.rfc-editor.org/rfc/rfc9110#section-7.8
//! [RFC 8441]: https://www.rfc-editor.org/rfc/rfc8441
//! [RFC 9220]: https://www.rfc-editor.org/rfc/rfc9220

use std::{
    borrow::Cow,
    fmt, io,
    pin::Pin,
    task::{self, Poll},
};

use http::{Method, Version};
use netty::upgrade;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(any(feature = "http2", feature = "http3"))]
use {
    http::{
        HeaderMap,
        header::{CONNECTION, SEC_WEBSOCKET_KEY, UPGRADE},
    },
    std::mem,
};

use super::error::{self, ErrorKind};
use crate::{
    Error, config::impl_request_config_value, protocol::Protocol as ClientProtocol, reuse,
};

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

/// Optional request-level HTTP upgrade and Extended CONNECT configuration.
///
/// Ordinary HTTP/1 `Upgrade` and plain `CONNECT` requests work without this setting. Use it
/// only when requiring a dedicated HTTP/1 connection, Extended CONNECT `:protocol`, or
/// adaptive reuse of an established HTTP/2 or HTTP/3 connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Upgrade(Kind);

#[derive(Clone, Debug, Eq, PartialEq)]
enum Kind {
    Http1,
    ExtendedConnect(Protocol),
    Adaptive(Protocol),
}

/// Prepared upgrade plan consumed by `svc` across connection checkouts and retries.
///
/// Zero-sized when neither `http2` nor `http3` is enabled.
pub(super) struct Plan {
    #[cfg(any(feature = "http2", feature = "http3"))]
    inner: Option<Box<PlanInner>>,
}

#[cfg(any(feature = "http2", feature = "http3"))]
enum PlanInner {
    ExtendedConnect(Protocol),
    Adaptive { key: reuse::Key, protocol: Protocol },
}

/// Per-attempt upgrade state carried while a request is in flight.
///
/// Zero-sized when neither `http2` nor `http3` is enabled.
pub(super) struct State {
    #[cfg(any(feature = "http2", feature = "http3"))]
    inner: StateInner,
}

#[cfg(any(feature = "http2", feature = "http3"))]
enum StateInner {
    None,
    /// Caller supplied a raw H2/H3 `:protocol` extension directly on the request.
    ExternalExtendedConnect,
    /// `PlanInner::ExtendedConnect` inserted the wire `:protocol` extension for this attempt.
    ExtendedConnect,
    /// `PlanInner::Adaptive` rewrote an HTTP/1 upgrade request into an Extended CONNECT.
    Rewritten(Box<Rewritten>),
}

/// Original HTTP/1 upgrade fields saved while attempting Extended CONNECT, restored if unsent.
#[cfg(any(feature = "http2", feature = "http3"))]
struct Rewritten {
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
    fn insert_into<B>(
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
    fn clear_from<B>(request: &mut http::Request<B>) {
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
    /// and `sec-websocket-key` for [`Protocol::WEBSOCKET`]) and restores the request if unsent.
    #[inline]
    #[must_use]
    pub fn adaptive<P: Into<Protocol>>(protocol: P) -> Self {
        Self(Kind::Adaptive(protocol.into()))
    }

    /// Returns the Extended CONNECT protocol token, if configured.
    #[inline]
    #[must_use]
    pub fn protocol(&self) -> Option<&Protocol> {
        match &self.0 {
            Kind::Http1 => None,
            Kind::ExtendedConnect(protocol) | Kind::Adaptive(protocol) => Some(protocol),
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
            Kind::Http1 | Kind::Adaptive(_) => {
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
}

// ===== impl Plan =====

impl Plan {
    /// Validates protocol compatibility and constructs the dispatch plan for `upgrade`.
    #[inline]
    pub(super) fn new(
        upgrade: Option<Upgrade>,
        protocol: ClientProtocol,
        client_protocol: ClientProtocol,
        is_https: bool,
        reuse_key: impl FnOnce(ClientProtocol) -> reuse::Key,
    ) -> Result<Self, error::Error> {
        #[cfg(any(feature = "http2", feature = "http3"))]
        {
            let inner = match upgrade.map(|upgrade| upgrade.0) {
                None | Some(Kind::Http1) => None,
                Some(Kind::ExtendedConnect(proto)) => {
                    if protocol == ClientProtocol::Http1 {
                        return Err(requires_multiplexed());
                    }
                    #[cfg(feature = "http3")]
                    if protocol == ClientProtocol::Http3 && proto.to_http3().is_none() {
                        warn!("extended CONNECT protocol {proto:?} is not supported on HTTP/3");
                        return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
                            .with_context("extended CONNECT protocol is not supported on HTTP/3"));
                    }
                    Some(Box::new(PlanInner::ExtendedConnect(proto)))
                }
                Some(Kind::Adaptive(proto)) => {
                    let probe = match client_protocol {
                        #[cfg(feature = "http2")]
                        ClientProtocol::Auto | ClientProtocol::Http2 => true,
                        #[cfg(feature = "http3")]
                        ClientProtocol::Http3 => is_https && proto.to_http3().is_some(),
                        _ => false,
                    };
                    #[cfg(not(feature = "http3"))]
                    let _ = is_https;
                    probe.then(|| {
                        Box::new(PlanInner::Adaptive {
                            key: reuse_key(client_protocol),
                            protocol: proto,
                        })
                    })
                }
            };
            Ok(Self { inner })
        }
        #[cfg(not(any(feature = "http2", feature = "http3")))]
        {
            let _ = (upgrade, protocol, client_protocol, is_https, reuse_key);
            Ok(Self {})
        }
    }

    /// Probes an established H2/H3 connection for an adaptive upgrade and rewrites `request`.
    ///
    /// Returns `None` untouched on a miss or if the checked-out version cannot encode `:protocol`.
    #[inline]
    pub(super) fn try_adaptive<B, C>(
        &self,
        request: &mut http::Request<B>,
        checkout: impl FnOnce(&reuse::Key) -> Option<C>,
        version: impl FnOnce(&C) -> Version,
    ) -> Option<(C, State)> {
        #[cfg(any(feature = "http2", feature = "http3"))]
        {
            let Some(PlanInner::Adaptive { key, protocol }) = self.inner.as_deref() else {
                return None;
            };
            let conn = checkout(key)?;
            let rewritten = Rewritten::try_rewrite(request, version(&conn), protocol)?;
            Some((
                conn,
                State {
                    inner: StateInner::Rewritten(rewritten),
                },
            ))
        }
        #[cfg(not(any(feature = "http2", feature = "http3")))]
        {
            let _ = (request, checkout, version);
            None
        }
    }

    /// Attaches or validates Extended CONNECT `:protocol` extensions for `version` and records
    /// the attempt state, rejecting peers known to have disabled Extended CONNECT.
    #[inline]
    pub(super) fn reconcile<B>(
        &self,
        request: &mut http::Request<B>,
        state: &mut State,
        version: Version,
        extended_connect: Option<bool>,
    ) -> Result<(), error::Error> {
        #[cfg(any(feature = "http2", feature = "http3"))]
        {
            if matches!(state.inner, StateInner::Rewritten(_)) {
                return Ok(());
            }
            if let Some(PlanInner::ExtendedConnect(protocol)) = self.inner.as_deref() {
                protocol.insert_into(request, version)?;
                if extended_connect == Some(false) {
                    return Err(extended_connect_disabled());
                }
                state.inner = StateInner::ExtendedConnect;
            } else if request.method() == Method::CONNECT
                && matched_extended_connect(request, version)?
            {
                if extended_connect == Some(false) {
                    return Err(extended_connect_disabled());
                }
                state.inner = StateInner::ExternalExtendedConnect;
            }
            Ok(())
        }
        #[cfg(not(any(feature = "http2", feature = "http3")))]
        {
            let _ = (request, state, version, extended_connect);
            Ok(())
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn is_none(&self) -> bool {
        #[cfg(any(feature = "http2", feature = "http3"))]
        {
            self.inner.is_none()
        }
        #[cfg(not(any(feature = "http2", feature = "http3")))]
        {
            true
        }
    }

    #[cfg(all(test, feature = "http2"))]
    #[must_use]
    pub(super) fn adaptive_key(&self) -> Option<&reuse::Key> {
        match self.inner.as_deref() {
            Some(PlanInner::Adaptive { key, .. }) => Some(key),
            _ => None,
        }
    }
}

// ===== impl State =====

impl State {
    /// Creates an empty upgrade state for a normal connection checkout.
    #[inline]
    #[must_use]
    pub(super) const fn none() -> Self {
        Self {
            #[cfg(any(feature = "http2", feature = "http3"))]
            inner: StateInner::None,
        }
    }

    /// Returns whether this attempt uses HTTP/2 or HTTP/3 Extended CONNECT.
    #[inline]
    #[must_use]
    pub(super) const fn is_extended_connect(&self) -> bool {
        #[cfg(any(feature = "http2", feature = "http3"))]
        {
            !matches!(self.inner, StateInner::None)
        }
        #[cfg(not(any(feature = "http2", feature = "http3")))]
        {
            false
        }
    }

    /// Restores or clears upgrade mutations before retrying an unsent request.
    #[inline]
    pub(super) fn restore_unsent<B>(self, request: &mut http::Request<B>) {
        #[cfg(any(feature = "http2", feature = "http3"))]
        match self.inner {
            StateInner::None | StateInner::ExternalExtendedConnect => {}
            StateInner::ExtendedConnect => Protocol::clear_from(request),
            StateInner::Rewritten(rewritten) => rewritten.restore(request),
        }
        #[cfg(not(any(feature = "http2", feature = "http3")))]
        let _ = request;
    }

    /// Returns a clearer error if the peer disabled Extended CONNECT while sending.
    #[inline]
    #[must_use]
    pub(super) fn send_error(&self, extended_connect: Option<bool>) -> Option<error::Error> {
        #[cfg(any(feature = "http2", feature = "http3"))]
        if self.is_extended_connect() && extended_connect == Some(false) {
            return Some(extended_connect_disabled());
        }
        #[cfg(not(any(feature = "http2", feature = "http3")))]
        let _ = extended_connect;
        None
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
    fn try_rewrite<B>(
        request: &mut http::Request<B>,
        version: Version,
        protocol: &Protocol,
    ) -> Option<Box<Self>> {
        protocol.insert_into(request, version).ok()?;
        let method = mem::replace(request.method_mut(), Method::CONNECT);
        let orig_version = mem::replace(request.version_mut(), version);
        let headers = mem::take(request.headers_mut());
        // Connection-specific fields are malformed in HTTP/2 and HTTP/3, and RFC 8441 §5 /
        // RFC 9220 §3 omit Sec-WebSocket-Key; the remaining headers keep their order:
        // https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2
        // https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        let strip_ws_key = *protocol == Protocol::WEBSOCKET;
        let extended = request.headers_mut();
        extended.reserve(headers.len());
        for (name, value) in &headers {
            if name != UPGRADE && name != CONNECTION && !(strip_ws_key && name == SEC_WEBSOCKET_KEY)
            {
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
    fn restore<B>(self, request: &mut http::Request<B>) {
        *request.method_mut() = self.method;
        *request.version_mut() = self.version;
        Protocol::clear_from(request);
        *request.headers_mut() = self.headers;
    }
}

/// Validates protocol markers provided directly through request extensions.
#[cfg(any(feature = "http2", feature = "http3"))]
fn matched_extended_connect<B>(
    request: &http::Request<B>,
    version: Version,
) -> Result<bool, error::Error> {
    let extensions = request.extensions();
    let http2 = cfg_select! {
        feature = "http2" => extensions.get::<http2::ext::Protocol>().is_some(),
        _ => false,
    };
    let http3 = cfg_select! {
        feature = "http3" => extensions.get::<netty::http3::Protocol>().is_some(),
        _ => false,
    };
    let matched = match version {
        Version::HTTP_2 => http2,
        Version::HTTP_3 => http3,
        _ => false,
    };
    if (http2 || http3) && !matched {
        warn!("extended CONNECT protocol does not match the connection's HTTP version");
        return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion));
    }
    Ok(matched)
}

/// Rejects Extended CONNECT unless the peer enabled it (RFC 8441 §3, RFC 9220 §3).
#[cfg(any(feature = "http2", feature = "http3"))]
#[must_use]
fn extended_connect_disabled() -> error::Error {
    warn!("peer did not enable extended CONNECT");
    error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
        .with_context("peer did not enable extended CONNECT")
}

#[must_use]
fn requires_multiplexed() -> error::Error {
    warn!("extended CONNECT requires HTTP/2 or HTTP/3");
    error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
        .with_context("extended CONNECT requires HTTP/2 or HTTP/3")
}
