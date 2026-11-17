//! Type-erased connection configuration entries, targets, and scoped hash comparisons.

use std::{
    any::{Any, TypeId},
    hash::{BuildHasher, Hash, Hasher},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, LazyLock},
};

use lru::DefaultHasher;

use super::{ConnectConfig, collect};
use crate::protocol::Protocol;

/// Shares one process-wide seed across configuration, pool, context, and session hashes.
pub(crate) static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);

/// Selects the comparison scope for a reuse key; TLS and QUIC options distinguish scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyScope {
    /// Pool and handshake keys compare the full value.
    Full,
    /// Session keys exclude ALPN, ALPS, and QUIC transport parameters.
    Session,
    /// Context keys compare only settings compiled into the TLS context.
    Context,
}

/// Protocols and session scopes that a configuration type affects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyTarget(u8);

/// Configuration values stored in [`ConnectConfig`](super::ConnectConfig) and compared by reuse
/// keys.
///
/// Hashes are cached on insertion, so values must not change while stored, and
/// `hash_scopes` must agree with `eq_scope` for every [`KeyScope`].
pub(crate) trait ConnectConfigValue: Clone + Eq + Hash + Send + Sync + 'static {
    /// Protocols and session scopes this type partitions.
    const TARGET: KeyTarget;

    /// Hashes indexed by [`KeyScope`].
    #[must_use]
    fn hash_scopes(&self) -> [u64; 3] {
        [HASHER.hash_one(self); 3]
    }

    /// Compares the fields selected by `scope`.
    #[must_use]
    fn eq_scope(&self, other: &Self, scope: KeyScope) -> bool {
        let _ = scope;
        self == other
    }
}

/// Shared configuration entry carrying precomputed scoped hashes and typed equality.
#[derive(Clone)]
pub(super) struct Entry {
    id: TypeId,
    target: KeyTarget,
    value: Arc<dyn Any + Send + Sync>,
    hashes: [u64; 3],
    eq: fn(&dyn Any, &dyn Any, KeyScope) -> bool,
}

// ===== impl ConnectConfig =====

impl ConnectConfig {
    /// Returns a subset containing only entries applicable to `protocol` that differ from `client`.
    #[must_use]
    pub(crate) fn for_protocol(&self, protocol: Protocol, client: &Self) -> Self {
        self.select_overrides(client, KeyScope::Full, |target| {
            target.matches_protocol(protocol)
        })
    }

    /// Selects overrides that differ from `client` for TLS session reuse on this transport.
    #[must_use]
    pub(crate) fn for_session(&self, client: &Self, quic: bool) -> Self {
        self.select_overrides(client, KeyScope::Session, |target| {
            target.matches_session(quic)
        })
    }

    /// Returns the Context hash and shared options when they differ from the client.
    #[must_use]
    pub(crate) fn context_override<T: ConnectConfigValue>(
        &self,
        client: &Self,
    ) -> Option<(u64, Arc<T>)> {
        let entry = self.entry(TypeId::of::<T>())?;
        if client
            .entry(entry.id())
            .is_some_and(|other| entry.same(other, KeyScope::Context))
        {
            return None;
        }
        Some((entry.hash(KeyScope::Context), entry.downcast_arc()?))
    }

    /// Compares the entries at the given reuse scope.
    #[must_use]
    pub(crate) fn eq_scope(&self, other: &Self, scope: KeyScope) -> bool {
        match (&self.entries, &other.entries) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                Arc::ptr_eq(left, right)
                    || (left.len() == right.len()
                        && left.iter().zip(right.iter()).all(|(a, b)| a.same(b, scope)))
            }
            _ => false,
        }
    }

    /// Hashes the entries using the same scope as [`Self::eq_scope`].
    pub(crate) fn hash_scope(&self, scope: KeyScope, state: &mut impl Hasher) {
        let entries = self.entries();
        entries.len().hash(state);
        for entry in entries {
            state.write_u64(entry.hash(scope));
        }
    }

    fn select_overrides(
        &self,
        client: &Self,
        scope: KeyScope,
        applies: impl Fn(KeyTarget) -> bool,
    ) -> Self {
        let Some(entries) = &self.entries else {
            return Self::default();
        };
        if client
            .entries
            .as_ref()
            .is_some_and(|base| Arc::ptr_eq(entries, base))
        {
            return Self::default();
        }

        let keep = |entry: &Entry| {
            applies(entry.target())
                && !client
                    .entry(entry.id())
                    .is_some_and(|base| entry.same(base, scope))
        };
        let Some(skip) = entries.iter().position(|entry| !keep(entry)) else {
            return self.clone();
        };

        Self {
            entries: collect(
                entries[..skip]
                    .iter()
                    .chain(entries[skip + 1..].iter().filter(|entry| keep(entry)))
                    .cloned(),
            ),
        }
    }
}

// ===== impl KeyTarget =====

impl KeyTarget {
    pub(crate) const HTTP1: Self = Self(1 << 0);
    pub(crate) const HTTP2: Self = Self(1 << 1);
    pub(crate) const HTTP3: Self = Self(1 << 2);
    pub(crate) const SESSION: Self = Self(1 << 3);
    pub(crate) const COMMON: Self =
        Self(Self::HTTP1.0 | Self::HTTP2.0 | Self::HTTP3.0 | Self::SESSION.0);
    pub(crate) const STREAM: Self = Self(Self::HTTP1.0 | Self::HTTP2.0 | Self::SESSION.0);
    #[cfg(feature = "http3")]
    pub(crate) const QUIC: Self = Self(Self::HTTP3.0 | Self::SESSION.0);

    #[inline]
    #[must_use]
    const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Returns whether this configuration affects pool entries for `protocol`.
    #[must_use]
    pub(crate) const fn matches_protocol(self, protocol: Protocol) -> bool {
        let mask = match protocol {
            Protocol::Http1 => Self::HTTP1,
            #[cfg(feature = "http2")]
            Protocol::Http2 => Self::HTTP2,
            Protocol::Auto => Self(Self::HTTP1.0 | Self::HTTP2.0),
            #[cfg(feature = "http3")]
            Protocol::Http3 => Self::HTTP3,
        };
        self.intersects(mask)
    }

    /// Returns whether this configuration partitions TLS sessions.
    #[must_use]
    pub(crate) const fn matches_session(self, quic: bool) -> bool {
        if !self.intersects(Self::SESSION) {
            return false;
        }
        let mask = if quic {
            Self::HTTP3
        } else {
            Self(Self::HTTP1.0 | Self::HTTP2.0)
        };
        self.intersects(mask)
    }
}

// ===== impl Entry =====

impl Entry {
    /// Wraps `value` for shared storage, precomputing its scoped identity hashes.
    #[must_use]
    pub(crate) fn new<T: ConnectConfigValue>(value: T) -> Self {
        let id = TypeId::of::<T>();
        let hashes = value.hash_scopes().map(|hash| HASHER.hash_one((id, hash)));
        Self {
            id,
            target: T::TARGET,
            value: Arc::new(value),
            hashes,
            eq: |left, right, scope| match (left.downcast_ref::<T>(), right.downcast_ref::<T>()) {
                (Some(left), Some(right)) => left.eq_scope(right, scope),
                _ => false,
            },
        }
    }

    #[inline]
    #[must_use]
    pub(crate) fn id(&self) -> TypeId {
        self.id
    }

    #[inline]
    #[must_use]
    pub(crate) fn target(&self) -> KeyTarget {
        self.target
    }

    #[inline]
    #[must_use]
    pub(crate) fn hash(&self, scope: KeyScope) -> u64 {
        self.hashes[scope as usize]
    }

    /// Returns whether `self` and `other` hold the same value under `scope`.
    #[inline]
    #[must_use]
    pub(crate) fn same(&self, other: &Self, scope: KeyScope) -> bool {
        Arc::ptr_eq(&self.value, &other.value)
            || (self.id == other.id
                && self.hash(scope) == other.hash(scope)
                && (self.eq)(&*self.value, &*other.value, scope))
    }

    #[inline]
    #[must_use]
    pub(crate) fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.value.downcast_ref::<T>()
    }

    #[inline]
    #[must_use]
    pub(crate) fn downcast_arc<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.value.clone().downcast::<T>().ok()
    }
}

super::macros::impl_connect_config_value!(Ipv4Addr, COMMON);
super::macros::impl_connect_config_value!(Ipv6Addr, COMMON);
super::macros::impl_connect_config_value!(Arc<str>, COMMON);
