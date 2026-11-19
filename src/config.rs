//! Type-indexed connection and request configuration.
//!
//! [`ConnectConfig`] stores connection options with client-wide defaults, while
//! [`RequestConfig`] stores per-request overrides inside [`http::Extensions`].

use std::sync::Arc;

use http::Extensions;

/// Type-indexed connection options with optional client defaults.
///
/// Both tables are shared via `Arc`; mutations copy-on-write only the local layer.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectConfig {
    local: Option<Arc<Extensions>>,
    base: Option<Arc<Extensions>>,
}

// ===== impl ConnectConfig =====

impl ConnectConfig {
    /// Attaches `base`'s local settings as defaults without chaining nested bases.
    #[must_use]
    pub(crate) fn with_base(mut self, base: &Self) -> Self {
        self.base = base.local.clone();
        self
    }

    /// Returns the local setting for `T`, falling back to the client default.
    #[inline]
    #[must_use]
    pub(crate) fn get_ref<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.get_arc_ref().map(Arc::as_ref)
    }

    /// Returns the client default for `T`, ignoring any local override.
    #[inline]
    #[must_use]
    pub(crate) fn base_ref<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.base.as_ref()?.get::<Arc<T>>().map(Arc::as_ref)
    }

    /// Returns the local override for `T` unless `same` considers it equal to the default.
    #[inline]
    #[must_use]
    pub(crate) fn override_if_different<T: Send + Sync + 'static>(
        &self,
        same: impl FnOnce(&T, &T) -> bool,
    ) -> Option<&Arc<T>> {
        let value = self.local.as_ref()?.get::<Arc<T>>()?;
        (!self.base_ref().is_some_and(|base| same(value, base))).then_some(value)
    }

    /// Clones the effective `Arc<T>` handle.
    #[cfg(feature = "http3")]
    #[inline]
    #[must_use]
    pub(crate) fn get_arc<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.get_arc_ref().cloned()
    }

    /// Borrows the effective `Arc<T>` handle.
    #[inline]
    #[must_use]
    fn get_arc_ref<T: Send + Sync + 'static>(&self) -> Option<&Arc<T>> {
        self.local
            .as_ref()
            .and_then(|local| local.get::<Arc<T>>())
            .or_else(|| self.base.as_ref()?.get::<Arc<T>>())
    }

    /// Inserts `value` into the local layer, replacing any previous value of type `T`.
    #[inline]
    pub(crate) fn insert<T: Send + Sync + 'static>(&mut self, value: T) -> &mut Self {
        self.insert_arc(Arc::new(value))
    }

    /// Inserts a shared `Arc<T>` into the local layer, replacing any previous value.
    #[inline]
    pub(crate) fn insert_arc<T: Send + Sync + 'static>(&mut self, value: Arc<T>) -> &mut Self {
        Arc::make_mut(self.local.get_or_insert_with(Arc::default)).insert(value);
        self
    }

    /// Inserts `value` if `Some`, leaving any existing value unchanged for `None`.
    #[inline]
    pub(crate) fn insert_if_some<T: Send + Sync + 'static>(
        &mut self,
        value: Option<T>,
    ) -> &mut Self {
        if let Some(value) = value {
            self.insert(value);
        }
        self
    }

    /// Sets `T` in the local layer, or removes it when `value` is `None`.
    pub(crate) fn set<T: Send + Sync + 'static>(&mut self, value: Option<T>) {
        if let Some(value) = value {
            self.insert(value);
            return;
        }
        if let Some(extensions) = &mut self.local
            && extensions.get::<Arc<T>>().is_some()
        {
            let extensions = Arc::make_mut(extensions);
            extensions.remove::<Arc<T>>();
            if extensions.is_empty() {
                self.local = None;
            }
        }
    }

    /// Merges `other`'s local settings into `self`, leaving defaults untouched.
    pub(crate) fn extend(&mut self, other: Self) {
        if let Some(other) = other.local {
            match &mut self.local {
                Some(extensions) => Arc::make_mut(extensions).extend(Arc::unwrap_or_clone(other)),
                empty => *empty = Some(other),
            }
        }
    }
}

/// Maps a marker key type to the value type stored inside [`http::Extensions`].
///
/// Implement directly or via [`impl_request_config_value!`] to pair a key with
/// [`RequestConfig`].
pub(crate) trait RequestConfigValue: Clone + 'static {
    type Value: Clone + Send + Sync + 'static;
}

/// Optional per-request setting for marker key `T`, stored inside [`http::Extensions`].
///
/// Used by client layers to hold a default setting and look up, move, or override the
/// request-specific value from `http::Request::extensions`.
#[derive(Clone, Copy)]
pub(crate) struct RequestConfig<T: RequestConfigValue>(Option<T::Value>);

// ===== impl RequestConfig =====

impl<T: RequestConfigValue> Default for RequestConfig<T> {
    #[inline]
    fn default() -> Self {
        RequestConfig(None)
    }
}

impl<T> RequestConfig<T>
where
    T: RequestConfigValue,
{
    /// Creates a config holding `v`.
    #[must_use]
    pub(crate) const fn new(v: Option<T::Value>) -> Self {
        RequestConfig(v)
    }

    /// Borrows the stored value, if set.
    #[must_use]
    pub(crate) const fn as_ref(&self) -> Option<&T::Value> {
        self.0.as_ref()
    }

    /// Returns the request override in `extensions`, falling back to `self`.
    #[must_use]
    pub(crate) fn fetch<'a>(&'a self, extensions: &'a Extensions) -> Option<&'a T::Value> {
        Self::get(extensions).or(self.as_ref())
    }

    /// Moves any override out of `extensions` into `self` and returns the effective value.
    #[must_use]
    pub(crate) fn load(&mut self, extensions: &mut Extensions) -> Option<&T::Value> {
        if let Some(value) = RequestConfig::<T>::remove(extensions) {
            self.0.replace(value);
        }
        self.as_ref()
    }

    /// Removes the [`RequestConfig<T>`] entry from `extensions`, falling back to a clone of `self`.
    #[must_use]
    pub(crate) fn take<'a>(&'a self, extensions: &'a mut Extensions) -> Option<T::Value> {
        extensions.remove().unwrap_or_else(|| self.clone()).0
    }

    /// Borrows the override for `T` from `extensions`, if present.
    #[must_use]
    pub(crate) fn get(extensions: &Extensions) -> Option<&T::Value> {
        extensions.get::<RequestConfig<T>>()?.0.as_ref()
    }

    /// Returns a mutable slot for `T` in `extensions`, inserting `None` if absent.
    #[must_use]
    pub(crate) fn get_mut(extensions: &mut Extensions) -> &mut Option<T::Value> {
        &mut extensions.get_or_insert_default::<RequestConfig<T>>().0
    }

    /// Removes and returns the override for `T` from `extensions`.
    #[must_use]
    pub(crate) fn remove(extensions: &mut Extensions) -> Option<T::Value> {
        extensions.remove::<RequestConfig<T>>()?.0
    }
}

/// Implements [`RequestConfigValue`] for a key type (defaulting `Value` to `Self`).
macro_rules! impl_request_config_value {
    ($type:ty) => {
        impl $crate::config::RequestConfigValue for $type {
            type Value = Self;
        }
    };
    ($type:ty, $value:ty) => {
        impl $crate::config::RequestConfigValue for $type {
            type Value = $value;
        }
    };
}

pub(crate) use impl_request_config_value;
