//! Connection options shared by client defaults and request overrides.
//!
//! [`ConnectConfig`] stores connection-scoped settings in a type-keyed extension table rather
//! than a closed struct. Request configurations bind the client's defaults as a fallback layer
//! through [`ConnectConfig::with_base`], so downstream services can read effective values or
//! compute request overrides from a single handle.

mod identity;
mod macros;

use std::{
    any::{Any, TypeId, type_name},
    fmt,
    sync::Arc,
};

pub(crate) use self::{
    identity::{Cached, ConnectConfigValue, Full, HASHER, KeyScope, ScopedConfig},
    macros::{derive_deftly_template_ConfigKey, impl_connect_extension},
};
#[cfg(feature = "http2")]
use crate::http2::Http2Options;
#[cfg(feature = "http3")]
use crate::http3::Http3Options;
use crate::{conn::dialer::SocketBindings, http1::Http1Options};

/// Connection settings stored on a client or an individual request.
///
/// Request configurations bind the client's defaults via [`ConnectConfig::with_base`], allowing
/// effective lookups and override diffs without passing `(request_config, client_config)` pairs.
#[derive(Clone, Default)]
pub(crate) struct ConnectConfig {
    /// Settings explicitly configured on this builder or request.
    local: Option<Arc<Vec<Entry>>>,
    /// Client-wide defaults bound behind a request configuration.
    base: Option<Arc<Vec<Entry>>>,
}

/// Maps a connection option type to how [`ConnectConfig`] stores and borrows it.
///
/// Plain settings store themselves directly, while pool- and session-scoped option types store
/// [`Cached<Self>`] so identity hashes are computed once on insertion.
pub(crate) trait ConnectExtension: Send + Sync + 'static {
    /// Representation held inside [`ConnectConfig`], such as `Self` or [`Cached<Self>`].
    type Stored: Send + Sync + 'static;

    /// Converts `value` into its stored representation.
    fn store(value: Self) -> Self::Stored;

    /// Borrows `Self` back from its stored representation.
    fn borrow(stored: &Self::Stored) -> &Self;
}

/// One type-erased extension slot shared inside [`ConnectConfig`].
#[derive(Clone)]
struct Entry {
    type_id: TypeId,
    type_name: &'static str,
    value: Arc<dyn Any + Send + Sync>,
}

// ===== impl ConnectExtension for foreign netty options =====

impl_connect_extension! {
    cached:
    Http1Options,
    #[cfg(feature = "http2")]
    Http2Options,
    #[cfg(feature = "http3")]
    Http3Options,
}

// ===== impl ConnectConfig =====

impl ConnectConfig {
    /// Stores a setting in the local layer, replacing any previous value of the same type.
    pub(crate) fn insert<T: ConnectExtension>(&mut self, value: T) -> &mut Self {
        let entries = Arc::make_mut(self.local.get_or_insert_with(Arc::default));
        upsert(entries, Entry::new::<T>(value));
        self
    }

    /// Sets or clears a setting in the local layer; `None` removes only this type's local value.
    pub(crate) fn set<T: ConnectExtension>(&mut self, value: Option<T>) -> &mut Self {
        if let Some(value) = value {
            return self.insert(value);
        }
        let Some(entries) = &mut self.local else {
            return self;
        };
        let Some(index) = entries
            .iter()
            .position(|entry| entry.type_id == TypeId::of::<T>())
        else {
            return self;
        };
        if entries.len() == 1 {
            self.local = None;
        } else {
            Arc::make_mut(entries).swap_remove(index);
        }
        self
    }

    /// Overlays all populated local settings from `other`, leaving unmentioned types intact.
    pub(crate) fn extend(&mut self, other: Self) {
        let Some(other) = other.local else {
            return;
        };
        match &mut self.local {
            Some(entries) => {
                let entries = Arc::make_mut(entries);
                for entry in other.iter() {
                    upsert(entries, entry.clone());
                }
            }
            None => self.local = Some(other),
        }
    }

    /// Binds the client defaults behind this request overlay without merging or copying either set.
    pub(crate) fn with_base(mut self, base_config: &Self) -> Self {
        self.base = base_config
            .local
            .clone()
            .or_else(|| base_config.base.clone());
        self
    }

    /// Returns whether no local settings have been inserted.
    pub(crate) fn is_empty(&self) -> bool {
        self.local.is_none()
    }

    /// Returns the effective setting, preferring the local value over the bound base.
    pub(crate) fn get_ref<T: ConnectExtension>(&self) -> Option<&T> {
        self.get::<T>().map(T::borrow)
    }

    /// Returns a shared handle to the effective cached option.
    pub(crate) fn get_arc<T: ConnectExtension<Stored = Cached<T>>>(&self) -> Option<Arc<T>> {
        self.get::<T>().map(Cached::arc)
    }

    /// Returns the local cached option only when it differs from the bound base for `scope`.
    pub(crate) fn changed<T>(&self, scope: KeyScope) -> Option<&Cached<T>>
    where
        T: ConnectExtension<Stored = Cached<T>> + ConnectConfigValue,
    {
        let value = self.local_get::<T>()?;
        (!self
            .base_get::<T>()
            .is_some_and(|other| value.same(other, scope)))
        .then_some(value)
    }

    /// Clones the local setting only when it differs from the bound base.
    pub(crate) fn changed_value<T: ConnectExtension + Clone + Eq>(&self) -> Option<T> {
        let value = self.local_get::<T>().map(T::borrow)?;
        (self.base_get::<T>().map(T::borrow) != Some(value)).then(|| value.clone())
    }

    /// Extracts the effective socket bindings from this configuration.
    pub(crate) fn bindings(&self) -> SocketBindings {
        SocketBindings::from_config(self)
    }

    /// Looks up the stored representation in the local layer, falling back to the bound base.
    fn get<T: ConnectExtension>(&self) -> Option<&T::Stored> {
        self.local_get::<T>().or_else(|| self.base_get::<T>())
    }

    /// Looks up the stored representation in the local layer only.
    fn local_get<T: ConnectExtension>(&self) -> Option<&T::Stored> {
        find::<T>(self.local.as_deref()?)
    }

    /// Looks up the stored representation in the bound base layer only.
    fn base_get<T: ConnectExtension>(&self) -> Option<&T::Stored> {
        find::<T>(self.base.as_deref()?)
    }
}

impl fmt::Debug for ConnectConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut set = f.debug_set();
        if let Some(entries) = &self.local {
            for entry in entries.iter() {
                set.entry(&entry.type_name);
            }
        }
        set.finish()
    }
}

// ===== impl Entry =====

impl Entry {
    /// Boxes `T::store(value)` under `T`'s `TypeId` and display name.
    fn new<T: ConnectExtension>(value: T) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            type_name: type_name::<T>(),
            value: Arc::new(T::store(value)),
        }
    }
}

/// Inserts or replaces the slot matching `entry.type_id`.
fn upsert(entries: &mut Vec<Entry>, entry: Entry) {
    if let Some(slot) = entries
        .iter_mut()
        .find(|existing| existing.type_id == entry.type_id)
    {
        *slot = entry;
    } else {
        entries.push(entry);
    }
}

/// Finds and downcasts the stored representation of `T`.
fn find<T: ConnectExtension>(entries: &[Entry]) -> Option<&T::Stored> {
    let type_id = TypeId::of::<T>();
    entries
        .iter()
        .find(|entry| entry.type_id == type_id)?
        .value
        .downcast_ref::<T::Stored>()
}
