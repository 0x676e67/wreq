//! Pool compatibility and its shared route and socket identity.

use std::{
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use http::{Uri, uri::PathAndQuery};
use netty::http1::Http1Options;
#[cfg(feature = "http2")]
use netty::http2::Http2Options;
#[cfg(feature = "http3")]
use {crate::quic::QuicOptions, netty::http3::Http3Options};

use crate::{
    config::connect::{ConnectConfigRef, Full, HASHER, KeyScope, changed, changed_value},
    error::BoxError,
    group::Group,
    protocol::Protocol,
    proxy::Matcher,
    tls::TlsOptions,
};

/// Reuse identity for pool entries, extended CONNECT probes and QUIC address tokens.
#[derive(Clone)]
pub(crate) struct ConnectionKey {
    origin: Uri,
    protocol: Protocol,
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
#[derive(Clone, Eq, PartialEq, Hash)]
pub(crate) struct CommonOverrides {
    group: Option<Group>,
    matcher: Option<Full<Matcher>>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    interface: Option<Arc<str>>,
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

// ===== impl ConnectionKey =====

impl ConnectionKey {
    /// Validates the target and keys its origin independently of the request path and query.
    pub(crate) fn for_request(
        uri: &Uri,
        protocol: Protocol,
        config: ConnectConfigRef<'_>,
    ) -> Result<Self, BoxError> {
        let origin = Uri::builder()
            .scheme(uri.scheme().ok_or("URI missing scheme")?.clone())
            .authority(uri.authority().ok_or("URI missing authority")?.clone())
            .path_and_query(PathAndQuery::from_static("/"))
            .build()?;
        Ok(Self::with_common_overrides(
            origin,
            protocol,
            config,
            || CommonOverrides::new(config),
        ))
    }

    #[cfg(all(feature = "ws", any(feature = "http2", feature = "http3")))]
    pub(crate) fn with_protocol(&self, protocol: Protocol, config: ConnectConfigRef<'_>) -> Self {
        if self.protocol == protocol {
            return self.clone();
        }
        Self::with_common_overrides(self.origin.clone(), protocol, config, || {
            self.common_overrides().cloned()
        })
    }

    fn with_common_overrides(
        origin: Uri,
        protocol: Protocol,
        config: ConnectConfigRef<'_>,
        common: impl FnOnce() -> Option<CommonOverrides>,
    ) -> Self {
        let overrides = (!config.local().is_empty())
            .then(|| {
                let common = common();
                let protocol = ProtocolOverrides::new(protocol, config);
                (common.is_some() || !matches!(protocol, ProtocolOverrides::None))
                    .then_some(PoolOverrides { common, protocol })
            })
            .flatten();

        Self {
            hash: HASHER.hash_one((&origin, protocol, &overrides)),
            overrides: overrides.map(Arc::new),
            origin,
            protocol,
        }
    }

    #[inline]
    pub(crate) fn origin(&self) -> &Uri {
        &self.origin
    }

    #[inline]
    pub(crate) fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub(crate) fn common_overrides(&self) -> Option<&CommonOverrides> {
        self.overrides.as_deref()?.common.as_ref()
    }

    /// Borrows the HTTP/1 override included in this key's comparison.
    pub(crate) fn http1_options(&self) -> Option<&Http1Options> {
        let ProtocolOverrides::Stream { http1, .. } = &self.overrides.as_deref()?.protocol else {
            return None;
        };
        http1.as_ref().map(Full::get)
    }

    /// Borrows the HTTP/2 override included in this key's comparison.
    #[cfg(feature = "http2")]
    pub(crate) fn http2_options(&self) -> Option<&Http2Options> {
        let ProtocolOverrides::Stream { http2, .. } = &self.overrides.as_deref()?.protocol else {
            return None;
        };
        http2.as_ref().map(Full::get)
    }

    /// Borrows the HTTP/3 override included in this key's comparison.
    #[cfg(feature = "http3")]
    pub(crate) fn http3_options(&self) -> Option<&Http3Options> {
        let ProtocolOverrides::Quic { http3, .. } = &self.overrides.as_deref()?.protocol else {
            return None;
        };
        http3.as_ref().map(Full::get)
    }
}

impl PartialEq for ConnectionKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.protocol == other.protocol
            && self.origin == other.origin
            && match (&self.overrides, &other.overrides) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b) || a == b,
                _ => false,
            }
    }
}

impl Eq for ConnectionKey {}

impl Hash for ConnectionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl fmt::Debug for ConnectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionKey")
            .field("origin", &self.origin)
            .field("protocol", &self.protocol)
            .field("hash", &self.hash)
            .finish()
    }
}

// ===== impl CommonOverrides =====

impl CommonOverrides {
    /// Captures route and socket settings that differ from the client's defaults.
    fn new(config: ConnectConfigRef<'_>) -> Option<Self> {
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
