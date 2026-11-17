//! Value comparisons used by connection, TLS context and session keys.

use std::{
    hash::{BuildHasher, Hash, Hasher},
    sync::{Arc, LazyLock},
};

use lru::DefaultHasher;

use super::{ConnectConfig, ConnectConfigRef};

/// Shares one process-wide seed across configuration, pool and session identity hashes.
pub(crate) static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);

/// Selects the comparison scope for a reuse key; TLS and QUIC options distinguish scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyScope {
    /// Pool and handshake keys compare the full value.
    Full,

    /// Session keys exclude ALPN, ALPS and QUIC transport parameters.
    Session,

    /// Context keys compare only settings compiled into the TLS context.
    Context,
}

/// Configuration values compared by connection reuse keys.
///
/// Hashes are cached on insertion, so values must not change while stored, and
/// `hash_scopes` must agree with `eq_scope` for every [`KeyScope`].
pub(crate) trait ConnectConfigValue: Clone + Eq + Hash + Send + Sync + 'static {
    /// Hashes indexed by [`KeyScope`].
    fn hash_scopes(&self) -> [u64; 3] {
        [HASHER.hash_one(self); 3]
    }

    /// Compares the fields selected by `scope`.
    fn eq_scope(&self, other: &Self, scope: KeyScope) -> bool {
        let _ = scope;
        self == other
    }
}

/// Projects a TLS or QUIC option value into its context-scoped and session-scoped identities.
pub(crate) trait ScopedConfig: ConnectConfigValue {
    /// Subset of fields compiled into a reusable TLS context.
    type Context: Clone + Eq + Hash;

    /// Subset of fields that partition TLS session resumption tickets.
    type Session: Clone + Eq + Hash;

    /// Extracts the identity of fields that affect the compiled TLS context.
    fn context_identity(&self) -> Self::Context;

    /// Extracts the identity of fields that affect TLS session resumption.
    fn session_identity(&self) -> Self::Session;
}

/// A shared option and the hashes computed when it is stored.
#[derive(Clone)]
pub(crate) struct Cached<T> {
    value: Arc<T>,
    hashes: [u64; 3],
}

/// A key that compares the full option value using its precomputed hash.
#[derive(Clone)]
pub(crate) struct Full<T> {
    value: Arc<T>,
    hash: u64,
}

// ===== impl Cached =====

impl<T> Cached<T> {
    /// Borrows the underlying option value.
    pub(crate) fn get(&self) -> &T {
        &self.value
    }

    /// Clones the shared handle to the underlying option value.
    pub(crate) fn arc(&self) -> Arc<T> {
        self.value.clone()
    }

    /// Returns the precomputed hash for `scope`.
    pub(crate) fn hash(&self, scope: KeyScope) -> u64 {
        self.hashes[scope as usize]
    }
}

impl<T: ConnectConfigValue> Cached<T> {
    /// Wraps `value` for shared storage, precomputing its scoped identity hashes.
    pub(crate) fn new(value: T) -> Self {
        let hashes = value.hash_scopes();
        Self {
            value: Arc::new(value),
            hashes,
        }
    }

    /// Returns whether `self` and `other` are equal on the fields selected by `scope`.
    pub(super) fn same(&self, other: &Self, scope: KeyScope) -> bool {
        Arc::ptr_eq(&self.value, &other.value)
            || (self.hash(scope) == other.hash(scope) && self.value.eq_scope(&other.value, scope))
    }
}

// ===== impl Full =====

impl<T> Full<T> {
    /// Wraps a cached option for full-value key comparisons.
    pub(crate) fn new(value: &Cached<T>) -> Self {
        Self {
            value: value.arc(),
            hash: value.hash(KeyScope::Full),
        }
    }

    /// Borrows the selected option shared with the pool key.
    pub(crate) fn get(&self) -> &T {
        &self.value
    }
}

impl<T: ConnectConfigValue> PartialEq for Full<T> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && (Arc::ptr_eq(&self.value, &other.value)
                || self.value.eq_scope(&other.value, KeyScope::Full))
    }
}

impl<T: ConnectConfigValue> Eq for Full<T> {}

impl<T> Hash for Full<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

/// Borrows a request option if it differs from the client default within `scope`.
pub(crate) fn changed<T: ConnectConfigValue>(
    config: ConnectConfigRef<'_>,
    scope: KeyScope,
) -> Option<&Cached<T>> {
    let value = config.local().get_ref::<Cached<T>>()?;
    (!config
        .base
        .and_then(ConnectConfig::get_ref::<Cached<T>>)
        .is_some_and(|other| value.same(other, scope)))
    .then_some(value)
}

/// Clones a request value if it differs from the client default.
pub(crate) fn changed_value<T: Clone + Eq + Send + Sync + 'static>(
    config: ConnectConfigRef<'_>,
) -> Option<T> {
    let value = config.local().get_ref::<T>()?;
    (config.base.and_then(ConnectConfig::get_ref::<T>) != Some(value)).then(|| value.clone())
}
