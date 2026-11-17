//! Connection options and the read-only view used to inherit client defaults.

mod identity;
mod macros;

use std::sync::Arc;

use http::Extensions;

pub(crate) use self::{
    identity::{
        Cached, ConnectConfigValue, Full, HASHER, KeyScope, ScopedConfig, changed, changed_value,
    },
    macros::{derive_deftly_template_ConfigKey, impl_connect_config_value},
};

/// One set of connection options, shared until edited.
/// A setting's type is its key, so adding settings requires no change to the store.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectConfig {
    extensions: Option<Arc<Extensions>>,
}

/// Reads connection options with the request's values taking precedence over client defaults.
#[derive(Clone, Copy)]
pub(crate) struct ConnectConfigRef<'a> {
    local: &'a ConnectConfig,
    base: Option<&'a ConnectConfig>,
}

// ===== impl ConnectConfig =====

impl ConnectConfig {
    /// Stores a setting, replacing any previous value of the same type.
    pub(crate) fn insert<T: Clone + Send + Sync + 'static>(&mut self, value: T) -> &mut Self {
        Arc::make_mut(self.extensions.get_or_insert_with(Arc::default)).insert(value);
        self
    }

    /// Inserts a setting when supplied, leaving the previous value intact for `None`.
    pub(crate) fn insert_if_some<T: Clone + Send + Sync + 'static>(
        &mut self,
        value: Option<T>,
    ) -> &mut Self {
        if let Some(value) = value {
            self.insert(value);
        }
        self
    }

    /// Sets the value of a type, or removes it when given `None`.
    pub(crate) fn set<T: Clone + Send + Sync + 'static>(&mut self, value: Option<T>) -> &mut Self {
        if let Some(value) = value {
            return self.insert(value);
        }
        if let Some(extensions) = &mut self.extensions
            && extensions.get::<T>().is_some()
        {
            if extensions.len() == 1 {
                self.extensions = None;
            } else {
                Arc::make_mut(extensions).remove::<T>();
            }
        }
        self
    }

    /// Overlays the settings from `other`, leaving unmentioned types intact.
    pub(crate) fn extend(&mut self, other: Self) {
        let Some(other) = other.extensions else {
            return;
        };
        match &mut self.extensions {
            Some(extensions) => Arc::make_mut(extensions).extend(Arc::unwrap_or_clone(other)),
            None => self.extensions = Some(other),
        }
    }

    /// Returns whether this set has no options.
    pub(crate) fn is_empty(&self) -> bool {
        self.extensions.is_none()
    }

    /// Borrows the setting stored for `T`.
    pub(crate) fn get_ref<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions.as_deref()?.get::<T>()
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
    pub(crate) fn get_ref<T: Send + Sync + 'static>(&self) -> Option<&'a T> {
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

impl Default for ConnectConfigRef<'_> {
    fn default() -> Self {
        static EMPTY: ConnectConfig = ConnectConfig { extensions: None };
        Self::from(&EMPTY)
    }
}
