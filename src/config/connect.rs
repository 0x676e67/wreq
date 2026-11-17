//! Type-indexed client and request connection options.

mod identity;
mod macros;

use std::{any::TypeId, fmt, iter, sync::Arc};

use self::identity::Entry;
pub(crate) use self::{
    identity::{ConnectConfigValue, HASHER, KeyScope, KeyTarget},
    macros::{derive_deftly_template_ConfigKey, impl_connect_config_value},
};

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

    /// Borrows the setting stored for `T`.
    #[inline]
    #[must_use]
    pub(crate) fn get_ref<T: 'static>(&self) -> Option<&T> {
        self.entry(TypeId::of::<T>())?.downcast_ref::<T>()
    }

    /// Borrows `T` from the request, falling back to the client's configuration.
    #[inline]
    #[must_use]
    pub(crate) fn get_or<'a, T: 'static>(&'a self, client_config: &'a Self) -> Option<&'a T> {
        self.get_ref().or_else(|| client_config.get_ref())
    }

    /// Clones the shared handle stored for `T`.
    #[inline]
    #[must_use]
    pub(crate) fn get_arc<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.entry(TypeId::of::<T>())?.downcast_arc::<T>()
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
