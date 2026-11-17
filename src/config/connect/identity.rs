//! Type-erased connection configuration entries, targets, and scoped hash comparisons.

use std::{
    any::{Any, TypeId},
    hash::{BuildHasher, Hash},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, LazyLock},
};

use lru::DefaultHasher;

use super::ConnectConfig;
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

/// Configuration values stored in [`ConnectConfig`] and compared by reuse keys.
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
pub(crate) struct Entry {
    id: TypeId,
    target: KeyTarget,
    value: Arc<dyn Any + Send + Sync>,
    hashes: [u64; 3],
    eq: fn(&dyn Any, &dyn Any, KeyScope) -> bool,
}

/// Cache key wrapping an [`Entry`] compared at a fixed [`KeyScope`].
#[derive(Clone)]
pub(crate) struct ScopedEntry {
    entry: Entry,
    scope: KeyScope,
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

// ===== impl ScopedEntry =====

impl ScopedEntry {
    /// Creates a cache key comparing `entry` at `scope`.
    #[inline]
    #[must_use]
    pub(crate) fn new(entry: Entry, scope: KeyScope) -> Self {
        Self { entry, scope }
    }

    /// Borrows the underlying value as `T`.
    #[inline]
    #[must_use]
    pub(crate) fn get<T: 'static>(&self) -> Option<&T> {
        self.entry.downcast_ref::<T>()
    }
}

impl PartialEq for ScopedEntry {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope && self.entry.same(&other.entry, self.scope)
    }
}

impl Eq for ScopedEntry {}

impl Hash for ScopedEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.entry.hash(self.scope));
    }
}

/// Selects request overrides matching `predicate` that differ from `client` under `scope`.
#[must_use]
pub(crate) fn select_overrides(
    request: &ConnectConfig,
    client: &ConnectConfig,
    scope: KeyScope,
    predicate: impl Fn(KeyTarget) -> bool,
) -> Option<Arc<[Entry]>> {
    if request.is_empty() || request.ptr_eq(client) {
        return None;
    }

    let entries = request.entries();
    let mut kept = 0usize;
    let mut selected = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let keep = predicate(entry.target())
            && !client
                .entry(entry.id())
                .is_some_and(|base| entry.same(base, scope));
        if !keep {
            continue;
        }
        if selected.is_empty() {
            if kept == index {
                kept += 1;
                continue;
            }
            selected.reserve(entries.len() - index + kept);
            selected.extend_from_slice(&entries[..kept]);
        }
        selected.push(entry.clone());
    }

    if !selected.is_empty() {
        Some(Arc::from(selected))
    } else if kept == entries.len() {
        request.clone_entries()
    } else if kept > 0 {
        Some(Arc::from(&entries[..kept]))
    } else {
        None
    }
}

/// Compares two optional override slices under `scope`.
#[must_use]
pub(crate) fn same_overrides(
    left: &Option<Arc<[Entry]>>,
    right: &Option<Arc<[Entry]>>,
    scope: KeyScope,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            Arc::ptr_eq(left, right)
                || (left.len() == right.len()
                    && left.iter().zip(right.iter()).all(|(a, b)| a.same(b, scope)))
        }
        _ => false,
    }
}

/// Folds the hashes of `overrides` under `scope` into `state`.
pub(crate) fn hash_overrides(
    overrides: Option<&[Entry]>,
    scope: KeyScope,
    state: &mut impl std::hash::Hasher,
) {
    if let Some(entries) = overrides {
        entries.len().hash(state);
        for entry in entries {
            state.write_u64(entry.hash(scope));
        }
    } else {
        0usize.hash(state);
    }
}

super::macros::impl_connect_config_value!(Ipv4Addr, COMMON);
super::macros::impl_connect_config_value!(Ipv6Addr, COMMON);
super::macros::impl_connect_config_value!(Arc<str>, COMMON);
