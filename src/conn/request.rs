//! Frozen connection inputs and the keys derived from them.
//!
//! [`ConnectRequest`] is constructed once before pool checkout, freezing the request options,
//! client defaults and precomputed [`ConnectionKey`].
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

use super::dialer::Interface;
use crate::{
    config::connect::{
        ConnectConfig, ConnectConfigRef, Full, HASHER, KeyScope, changed, changed_value,
    },
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
    request_config: ConnectConfig,
    client_config: ConnectConfig,
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
    common: Option<CommonOverrides>,
    protocol: ProtocolOverrides,
}

/// Route and socket settings shared by the pool and session identities.
#[derive(Eq, PartialEq, Hash)]
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
    /// Validates the absolute target, freezes the options, and precomputes the pool key.
    ///
    /// The origin keeps scheme and authority with `/` as the path.
    ///
    /// Returns an error if the URI lacks a scheme or authority.
    pub(crate) fn new(
        uri: &Uri,
        protocol: Protocol,
        request_config: ConnectConfig,
        client_config: &ConnectConfig,
    ) -> Result<Self, BoxError> {
        let origin = Uri::builder()
            .scheme(uri.scheme().ok_or("URI missing scheme")?.clone())
            .authority(uri.authority().ok_or("URI missing authority")?.clone())
            .path_and_query(PathAndQuery::from_static("/"))
            .build()?;
        let key = ConnectionKey::new(
            origin,
            protocol,
            ConnectConfigRef::new(&request_config, client_config),
        );
        Ok(Self {
            key,
            request_config,
            client_config: client_config.clone(),
        })
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

    /// Borrows the request options with the client's defaults.
    #[inline]
    pub(crate) fn config(&self) -> ConnectConfigRef<'_> {
        ConnectConfigRef::new(&self.request_config, &self.client_config)
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
    /// Computes a pool or probe key for `protocol` and the frozen options.
    pub(crate) fn new(origin: Uri, protocol: Protocol, config: ConnectConfigRef<'_>) -> Self {
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
    fn for_protocol(origin: &Uri, protocol: Protocol, config: ConnectConfigRef<'_>) -> Self {
        let overrides = (!config.local().is_empty())
            .then(|| {
                let common = CommonOverrides::new(config);
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
    /// Captures route and socket settings that differ from the client's defaults.
    pub(crate) fn new(config: ConnectConfigRef<'_>) -> Option<Self> {
        if config.local().is_empty() {
            return None;
        }

        let overrides = Self {
            group: changed_value(config),
            matcher: changed::<Matcher>(config, KeyScope::Full).map(Full::new),
            ipv4: changed_value(config),
            ipv6: changed_value(config),
            interface: changed_value(config),
        };
        (!overrides.is_empty()).then_some(overrides)
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
    fn new(protocol: Protocol, config: ConnectConfigRef<'_>) -> Self {
        #[cfg(feature = "http3")]
        if protocol == Protocol::Http3 {
            let quic = changed::<QuicOptions>(config, KeyScope::Full).map(Full::new);
            let http3 = changed::<Http3Options>(config, KeyScope::Full).map(Full::new);
            return if quic.is_some() || http3.is_some() {
                Self::Quic { quic, http3 }
            } else {
                Self::None
            };
        }

        let tls = changed::<TlsOptions>(config, KeyScope::Full).map(Full::new);
        let http1 = if matches!(protocol, Protocol::Auto | Protocol::Http1) {
            changed::<Http1Options>(config, KeyScope::Full).map(Full::new)
        } else {
            None
        };
        #[cfg(feature = "http2")]
        let http2 = if matches!(protocol, Protocol::Auto | Protocol::Http2) {
            changed::<Http2Options>(config, KeyScope::Full).map(Full::new)
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
