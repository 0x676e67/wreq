//! Connection options and scoped key comparisons.

mod identity;
mod macros;

use std::{
    any::TypeId,
    fmt,
    hash::{Hash, Hasher},
    iter,
    sync::Arc,
};

pub(crate) use self::{
    identity::{ConnectConfigValue, Entry, HASHER, KeyScope, KeyTarget, ScopedEntry},
    macros::{derive_deftly_template_ConfigKey, impl_connect_config_value},
};
use crate::protocol::Protocol;

/// One set of connection options, shared until edited.
/// Entries are sorted by `TypeId` and cache their scoped identity hashes on insertion.
#[derive(Clone, Default)]
pub(crate) struct ConnectConfig {
    entries: Option<Arc<[Entry]>>,
}

// ===== impl ConnectConfig =====

impl ConnectConfig {
    /// Stores a setting, replacing any previous value of the same type.
    pub(crate) fn insert<T: ConnectConfigValue>(&mut self, value: T) -> &mut Self {
        let entry = Entry::new(value);
        let entries = self.entries();
        let (index, replaced) = match search(entries, entry.id()) {
            Ok(index) => (index, 1),
            Err(index) => (index, 0),
        };
        self.entries = collect(
            entries[..index]
                .iter()
                .cloned()
                .chain(iter::once(entry))
                .chain(entries[index + replaced..].iter().cloned()),
        );
        self
    }

    /// Inserts a setting when supplied, leaving the previous value intact for `None`.
    pub(crate) fn insert_if_some<T: ConnectConfigValue>(&mut self, value: Option<T>) -> &mut Self {
        if let Some(value) = value {
            self.insert(value);
        }
        self
    }

    /// Sets the value of a type, or removes it when given `None`.
    pub(crate) fn set<T: ConnectConfigValue>(&mut self, value: Option<T>) -> &mut Self {
        if let Some(value) = value {
            return self.insert(value);
        }
        if let Some(entries) = self.entries.as_deref()
            && let Ok(index) = search(entries, TypeId::of::<T>())
        {
            self.entries = collect(
                entries[..index]
                    .iter()
                    .chain(&entries[index + 1..])
                    .cloned(),
            );
        }
        self
    }

    /// Overlays the settings from `other`, leaving unmentioned types intact.
    pub(crate) fn extend(&mut self, other: Self) {
        let (Some(left), Some(right)) = (self.entries.as_deref(), other.entries.as_deref()) else {
            if self.entries.is_none() {
                self.entries = other.entries;
            }
            return;
        };
        let mut merged = Vec::with_capacity(left.len() + right.len());
        let (mut left, mut right) = (left.iter().peekable(), right.iter().peekable());
        while let (Some(l), Some(r)) = (left.peek().map(|e| e.id()), right.peek().map(|e| e.id())) {
            if l == r {
                left.next();
            }
            let next = if l < r { left.next() } else { right.next() };
            merged.extend(next.cloned());
        }
        merged.extend(left.chain(right).cloned());
        self.entries = Some(merged.into());
    }

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

    /// Returns whether this set has no options.
    #[inline]
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_none()
    }

    /// Borrows the setting stored for `T`.
    #[inline]
    #[must_use]
    pub(crate) fn get_ref<T: 'static>(&self) -> Option<&T> {
        self.entry(TypeId::of::<T>())?.downcast_ref::<T>()
    }

    /// Returns the reference to `T` from `self`, falling back to `default`.
    #[inline]
    #[must_use]
    pub(crate) fn get_or<'a, T: 'static>(&'a self, default: &'a Self) -> Option<&'a T> {
        self.get_ref().or_else(|| default.get_ref())
    }

    /// Clones the shared handle stored for `T`.
    #[inline]
    #[must_use]
    pub(crate) fn get_arc<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.entry(TypeId::of::<T>())?.downcast_arc::<T>()
    }

    /// Returns the entry for `T` if it differs from `base` under `scope`.
    #[must_use]
    pub(crate) fn changed_entry<T: 'static>(&self, base: &Self, scope: KeyScope) -> Option<&Entry> {
        let entry = self.entry(TypeId::of::<T>())?;
        (!base
            .entry(entry.id())
            .is_some_and(|other| entry.same(other, scope)))
        .then_some(entry)
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

    #[inline]
    fn entries(&self) -> &[Entry] {
        self.entries.as_deref().unwrap_or_default()
    }

    #[inline]
    fn entry(&self, id: TypeId) -> Option<&Entry> {
        let entries = self.entries();
        search(entries, id).ok().map(|index| &entries[index])
    }

    #[inline]
    fn ptr_eq(&self, other: &Self) -> bool {
        match (&self.entries, &other.entries) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            (None, None) => true,
            _ => false,
        }
    }

    fn select_overrides(
        &self,
        client: &Self,
        scope: KeyScope,
        predicate: impl Fn(KeyTarget) -> bool,
    ) -> Self {
        if self.is_empty() || self.ptr_eq(client) {
            return Self::default();
        }

        let entries = self.entries();
        let mut kept = 0;
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

        let entries = if !selected.is_empty() {
            Some(Arc::from(selected))
        } else if kept == entries.len() {
            return self.clone();
        } else if kept > 0 {
            Some(Arc::from(&entries[..kept]))
        } else {
            None
        };
        Self { entries }
    }
}

impl PartialEq for ConnectConfig {
    fn eq(&self, other: &Self) -> bool {
        self.eq_scope(other, KeyScope::Full)
    }
}

impl Eq for ConnectConfig {}

impl Hash for ConnectConfig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_scope(KeyScope::Full, state);
    }
}

impl fmt::Debug for ConnectConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectConfig")
            .field("len", &self.entries().len())
            .finish()
    }
}

fn search(entries: &[Entry], id: TypeId) -> Result<usize, usize> {
    entries.binary_search_by_key(&id, Entry::id)
}

#[must_use]
fn collect(entries: impl Iterator<Item = Entry>) -> Option<Arc<[Entry]>> {
    let entries: Vec<_> = entries.collect();
    (!entries.is_empty()).then(|| entries.into())
}
