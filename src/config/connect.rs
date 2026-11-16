//! Connection options and the read-only view used to inherit client defaults.

mod identity;
mod macros;

use std::{
    any::{Any, TypeId, type_name},
    fmt,
    sync::Arc,
};

pub(crate) use self::{
    identity::{
        Cached, ConnectConfigValue, Full, HASHER, KeyScope, ScopedConfig, changed, changed_value,
    },
    macros::{derive_deftly_template_ConfigKey, impl_connect_extension},
};
use crate::http1::Http1Options;
#[cfg(feature = "http2")]
use crate::http2::Http2Options;
#[cfg(feature = "http3")]
use crate::http3::Http3Options;

/// One set of connection options, shared until edited.
#[derive(Clone, Default)]
pub(crate) struct ConnectConfig {
    entries: Option<Arc<Vec<Entry>>>,
}

/// Reads connection options with the request's values taking precedence over client defaults.
#[derive(Clone, Copy)]
pub(crate) struct ConnectConfigRef<'a> {
    local: &'a ConnectConfig,
    base: Option<&'a ConnectConfig>,
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
    /// Stores a setting, replacing any previous value of the same type.
    pub(crate) fn insert<T: ConnectExtension>(&mut self, value: T) -> &mut Self {
        let entries = Arc::make_mut(self.entries.get_or_insert_with(Arc::default));
        upsert(entries, Entry::new::<T>(value));
        self
    }

    /// Sets the value of a type, or removes it when given `None`.
    pub(crate) fn set<T: ConnectExtension>(&mut self, value: Option<T>) -> &mut Self {
        if let Some(value) = value {
            return self.insert(value);
        }
        let Some(entries) = &mut self.entries else {
            return self;
        };
        let Some(index) = entries
            .iter()
            .position(|entry| entry.type_id == TypeId::of::<T>())
        else {
            return self;
        };
        if entries.len() == 1 {
            self.entries = None;
        } else {
            Arc::make_mut(entries).swap_remove(index);
        }
        self
    }

    /// Overlays the settings from `other`, leaving unmentioned types intact.
    pub(crate) fn extend(&mut self, other: Self) {
        let Some(other) = other.entries else {
            return;
        };
        match &mut self.entries {
            Some(entries) => {
                let entries = Arc::make_mut(entries);
                for entry in other.iter() {
                    upsert(entries, entry.clone());
                }
            }
            None => self.entries = Some(other),
        }
    }

    /// Returns whether this set has no options.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_none()
    }

    /// Borrows the setting stored for `T`.
    pub(crate) fn get_ref<T: ConnectExtension>(&self) -> Option<&T> {
        self.get::<T>().map(T::borrow)
    }

    /// Returns a shared handle to the cached option.
    pub(crate) fn get_arc<T: ConnectExtension<Stored = Cached<T>>>(&self) -> Option<Arc<T>> {
        self.get::<T>().map(Cached::arc)
    }

    /// Looks up the stored representation of an option.
    fn get<T: ConnectExtension>(&self) -> Option<&T::Stored> {
        find::<T>(self.entries.as_deref()?)
    }
}

impl fmt::Debug for ConnectConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut set = f.debug_set();
        if let Some(entries) = &self.entries {
            for entry in entries.iter() {
                set.entry(&entry.type_name);
            }
        }
        set.finish()
    }
}

// ===== impl ConnectConfigRef =====

impl<'a> ConnectConfigRef<'a> {
    /// Reads the request's options with the client's options as defaults.
    pub(crate) fn new(request_config: &'a ConnectConfig, client_config: &'a ConnectConfig) -> Self {
        Self {
            local: request_config,
            base: Some(client_config),
        }
    }

    /// Returns the options set on the request itself.
    pub(crate) fn local(&self) -> &'a ConnectConfig {
        self.local
    }

    /// Borrows the effective value of `T`, checking the request first.
    pub(crate) fn get_ref<T: ConnectExtension>(&self) -> Option<&'a T> {
        self.local
            .get_ref::<T>()
            .or_else(|| self.base.and_then(ConnectConfig::get_ref::<T>))
    }
}

impl<'a> From<&'a ConnectConfig> for ConnectConfigRef<'a> {
    fn from(config: &'a ConnectConfig) -> Self {
        Self {
            local: config,
            base: None,
        }
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
