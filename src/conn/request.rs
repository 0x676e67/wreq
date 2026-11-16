//! Frozen connection inputs and the keys derived from them.
//!
//! [`ConnectRequest`] is constructed once before pool checkout, binding the request's local
//! [`ConnectConfig`] to the client's base configuration and precomputing its [`ConnectionKey`].
//! It travels immutably through the connection pool and into
//! [`Deadline`](super::layer::deadline::Deadline), which wraps each attempt in [`ConnectAttempt`]
//! alongside its optional connect deadline.

use std::{
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Instant,
};

use http::{Uri, uri::PathAndQuery};
use netty::http1::Http1Options;
#[cfg(feature = "http2")]
use netty::http2::Http2Options;
#[cfg(feature = "http3")]
use {crate::quic::QuicOptions, netty::http3::Http3Options};

use super::dialer::{Interface, SocketBindings};
use crate::{
    config::connect::{ConnectConfig, Full, HASHER, KeyScope},
    error::BoxError,
    group::Group,
    protocol::Protocol,
    proxy::Matcher,
    tls::TlsOptions,
};

/// The frozen destination, effective settings, and pool identity for a connection.
///
/// Serves as the immutable Tower request context across the connection pool and into the
/// [`Deadline`](super::layer::deadline::Deadline) layer.
#[derive(Clone)]
pub(crate) struct ConnectRequest {
    /// Target origin, selected protocol, and precomputed pool reuse identity.
    key: ConnectionKey,
    /// Request connection options bound to the client's defaults.
    config: ConnectConfig,
}

/// One connection attempt entering [`TransportConnector`](super::svc::TransportConnector), pairing
/// an immutable [`ConnectRequest`] with the optional deadline armed by
/// [`Deadline`](super::layer::deadline::Deadline).
#[derive(Clone)]
pub(crate) struct ConnectAttempt {
    request: ConnectRequest,
    deadline: Option<Instant>,
}

/// Reuse identity for pool entries, extended CONNECT probes and QUIC address tokens.
#[derive(Clone)]
pub(crate) struct ConnectionKey {
    origin: Uri,
    protocol: Protocol,
    identity: ConnectionIdentity,
}

/// Precomputed override projection and hash of a [`ConnectionKey`].
#[derive(Clone)]
struct ConnectionIdentity {
    /// Request-local settings that differ from the client's defaults, if any.
    overrides: Option<Arc<PoolOverrides>>,
    /// Hash of `(origin, protocol, overrides)`.
    hash: u64,
}

/// Request overrides that partition connection pool entries.
#[derive(Eq, PartialEq, Hash)]
struct PoolOverrides {
    common: Option<Arc<CommonOverrides>>,
    protocol: ProtocolOverrides,
}

/// Route and socket settings shared by the pool and session identities.
#[derive(Clone, Default, Eq, PartialEq, Hash)]
pub(crate) struct CommonOverrides {
    group: Option<Group>,
    matcher: Option<Full<Matcher>>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    interface: Option<Interface>,
}

/// Transport and HTTP protocol overrides relevant to the selected [`Protocol`].
#[derive(Eq, PartialEq, Hash)]
enum ProtocolOverrides {
    /// No protocol-specific options differ from the client's defaults.
    None,
    /// Overrides for TCP/Unix transports (TLS, HTTP/1, and HTTP/2 options).
    Stream {
        tls: Option<Full<TlsOptions>>,
        http1: Option<Full<Http1Options>>,
        #[cfg(feature = "http2")]
        http2: Option<Full<Http2Options>>,
    },
    /// Overrides for QUIC transports (QUIC and HTTP/3 options).
    #[cfg(feature = "http3")]
    Quic {
        quic: Option<Full<QuicOptions>>,
        http3: Option<Full<Http3Options>>,
    },
}

// ===== impl ConnectRequest =====

impl ConnectRequest {
    /// Validates the absolute target, binds `client_config`, and precomputes the pool identity.
    ///
    /// The origin keeps scheme and authority with `/` as the path.
    ///
    /// Returns an error if the URI lacks a scheme or authority.
    pub(crate) fn new(
        uri: &Uri,
        protocol: Protocol,
        config: ConnectConfig,
        client_config: &ConnectConfig,
    ) -> Result<Self, BoxError> {
        let origin = Uri::builder()
            .scheme(uri.scheme().ok_or("URI missing scheme")?.clone())
            .authority(uri.authority().ok_or("URI missing authority")?.clone())
            .path_and_query(PathAndQuery::from_static("/"))
            .build()?;
        let config = config.with_base(client_config);
        let key = ConnectionKey::new(origin, protocol, &config);
        Ok(Self { key, config })
    }

    /// Returns the original scheme and authority with `/` as the path.
    /// Proxy routing leaves it unchanged.
    #[inline]
    pub(crate) fn uri(&self) -> &Uri {
        &self.key.origin
    }

    /// Returns the protocol selection after inheriting the client's preference.
    /// Frozen before pool checkout.
    #[inline]
    pub(crate) fn protocol(&self) -> Protocol {
        self.key.protocol
    }

    /// Returns all request connection options, bound to the client's defaults.
    #[inline]
    pub(crate) fn config(&self) -> &ConnectConfig {
        &self.config
    }

    /// Returns the effective socket bindings configured on this request and its client defaults.
    #[inline]
    pub(crate) fn bindings(&self) -> SocketBindings {
        self.config.bindings()
    }

    /// Returns the precomputed route and socket overrides shared with TLS session keys.
    #[inline]
    pub(crate) fn common_overrides(&self) -> Option<Arc<CommonOverrides>> {
        self.key
            .identity
            .overrides
            .as_ref()
            .and_then(|overrides| overrides.common.clone())
    }

    /// Returns the precomputed pool key for this request's selected protocol.
    #[inline]
    pub(crate) fn key(&self) -> &ConnectionKey {
        &self.key
    }
}

// ===== impl ConnectAttempt =====

impl ConnectAttempt {
    /// Pairs an immutable [`ConnectRequest`] with an optional connect deadline.
    #[inline]
    pub(crate) fn new(request: ConnectRequest, deadline: Option<Instant>) -> Self {
        Self { request, deadline }
    }

    /// Borrows the frozen connection request for this attempt.
    #[inline]
    pub(crate) fn request(&self) -> &ConnectRequest {
        &self.request
    }

    /// Splits this attempt into its connection request and connect deadline.
    #[inline]
    pub(crate) fn into_parts(self) -> (ConnectRequest, Option<Instant>) {
        (self.request, self.deadline)
    }
}

// ===== impl ConnectionKey =====

impl ConnectionKey {
    /// Computes a pool or probe reuse key under `protocol` for a bound `config`.
    pub(crate) fn new(origin: Uri, protocol: Protocol, config: &ConnectConfig) -> Self {
        let identity = ConnectionIdentity::for_protocol(&origin, protocol, config);
        Self {
            origin,
            protocol,
            identity,
        }
    }
}

// ===== impl ConnectionIdentity =====

impl ConnectionIdentity {
    /// Projects the overrides relevant to `protocol` and hashes `(origin, protocol, overrides)`.
    fn for_protocol(origin: &Uri, protocol: Protocol, config: &ConnectConfig) -> Self {
        let overrides = (!config.is_empty())
            .then(|| {
                let common = CommonOverrides::new(config);
                let common = (!common.is_empty()).then(|| Arc::new(common));
                let protocol = ProtocolOverrides::new(protocol, config);
                (common.is_some() || !matches!(protocol, ProtocolOverrides::None))
                    .then_some(PoolOverrides { common, protocol })
            })
            .flatten();

        Self {
            hash: HASHER.hash_one((origin, protocol, &overrides)),
            overrides: overrides.map(Arc::new),
        }
    }
}

impl PartialEq for ConnectionKey {
    fn eq(&self, other: &Self) -> bool {
        self.identity.hash == other.identity.hash
            && self.protocol == other.protocol
            && self.origin == other.origin
            && match (&self.identity.overrides, &other.identity.overrides) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b) || a == b,
                _ => false,
            }
    }
}

impl Eq for ConnectionKey {}

impl Hash for ConnectionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.identity.hash);
    }
}

impl fmt::Debug for ConnectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionKey")
            .field("origin", &self.origin)
            .field("protocol", &self.protocol)
            .field("hash", &self.identity.hash)
            .finish()
    }
}

// ===== impl CommonOverrides =====

impl CommonOverrides {
    /// Captures route and socket bindings in `request_config` that differ from its bound base.
    fn new(request_config: &ConnectConfig) -> Self {
        if request_config.is_empty() {
            return Self::default();
        }

        Self {
            group: request_config.changed_value(),
            matcher: request_config
                .changed::<Matcher>(KeyScope::Full)
                .map(Full::new),
            ipv4: request_config.changed_value(),
            ipv6: request_config.changed_value(),
            interface: request_config.changed_value(),
        }
    }

    /// Returns whether no route or socket bindings differ from the client's defaults.
    fn is_empty(&self) -> bool {
        self.group.is_none()
            && self.matcher.is_none()
            && self.ipv4.is_none()
            && self.ipv6.is_none()
            && self.interface.is_none()
    }
}

// ===== impl ProtocolOverrides =====

impl ProtocolOverrides {
    /// Captures only the transport and HTTP options that `protocol` can use.
    fn new(protocol: Protocol, request_config: &ConnectConfig) -> Self {
        #[cfg(feature = "http3")]
        if protocol == Protocol::Http3 {
            let quic = request_config
                .changed::<QuicOptions>(KeyScope::Full)
                .map(Full::new);
            let http3 = request_config
                .changed::<Http3Options>(KeyScope::Full)
                .map(Full::new);
            return if quic.is_some() || http3.is_some() {
                Self::Quic { quic, http3 }
            } else {
                Self::None
            };
        }

        let tls = request_config
            .changed::<TlsOptions>(KeyScope::Full)
            .map(Full::new);
        let http1 = if matches!(protocol, Protocol::Auto | Protocol::Http1) {
            request_config
                .changed::<Http1Options>(KeyScope::Full)
                .map(Full::new)
        } else {
            None
        };
        #[cfg(feature = "http2")]
        let http2 = if matches!(protocol, Protocol::Auto | Protocol::Http2) {
            request_config
                .changed::<Http2Options>(KeyScope::Full)
                .map(Full::new)
        } else {
            None
        };

        let has_override = tls.is_some()
            || http1.is_some()
            || cfg_select! {
                feature = "http2" => http2.is_some(),
                _ => false,
            };
        if has_override {
            Self::Stream {
                tls,
                http1,
                #[cfg(feature = "http2")]
                http2,
            }
        } else {
            Self::None
        }
    }
}

#[cfg(test)]
impl ConnectRequest {
    /// Freezes `config` for a client without options in automatic mode.
    pub(crate) fn test(uri: Uri, protocol: Option<Protocol>, config: ConnectConfig) -> Self {
        Self::new(
            &uri,
            protocol.unwrap_or(Protocol::Auto),
            config,
            &ConnectConfig::default(),
        )
        .unwrap()
    }
}
