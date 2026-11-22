//! Type-indexed client and request connection options.

use std::sync::Arc;

use http::Extensions;

/// Connection options with local values and optional client defaults.
/// Each table is shared; edits only affect the local values.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectConfig {
    local: Option<Arc<Extensions>>,
    base: Option<Arc<Extensions>>,
}

impl ConnectConfig {
    /// Uses the client's local settings as defaults, without creating an inheritance chain.
    #[must_use]
    pub(crate) fn with_base(mut self, base: &Self) -> Self {
        self.base = base.local.clone();
        self
    }

    /// Borrows the local setting for `T`, or the client's default when absent.
    #[inline]
    #[must_use]
    pub(crate) fn get_ref<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.get_arc_ref().map(Arc::as_ref)
    }

    /// Borrows the default even if the request supplies an override.
    #[inline]
    #[must_use]
    pub(crate) fn base_ref<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.base.as_ref()?.get::<Arc<T>>().map(Arc::as_ref)
    }

    /// Borrows a local override unless it is equivalent to the client's setting.
    #[inline]
    #[must_use]
    pub(crate) fn override_if_different<T: Send + Sync + 'static>(
        &self,
        same: impl FnOnce(&T, &T) -> bool,
    ) -> Option<&Arc<T>> {
        let value = self.local.as_ref()?.get::<Arc<T>>()?;
        (!self.base_ref().is_some_and(|base| same(value, base))).then_some(value)
    }

    /// Clones the shared handle stored for `T`.
    #[cfg(feature = "http3")]
    #[inline]
    #[must_use]
    pub(crate) fn get_arc<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.get_arc_ref().cloned()
    }

    /// Borrows the shared handle of the effective setting.
    #[inline]
    #[must_use]
    fn get_arc_ref<T: Send + Sync + 'static>(&self) -> Option<&Arc<T>> {
        self.local
            .as_ref()
            .and_then(|local| local.get::<Arc<T>>())
            .or_else(|| self.base.as_ref()?.get::<Arc<T>>())
    }

    /// Stores a setting, replacing any previous value of the same type.
    #[inline]
    pub(crate) fn insert<T: Send + Sync + 'static>(&mut self, value: T) -> &mut Self {
        self.insert_arc(Arc::new(value))
    }

    /// Stores an existing shared setting.
    #[inline]
    pub(crate) fn insert_arc<T: Send + Sync + 'static>(&mut self, value: Arc<T>) -> &mut Self {
        Arc::make_mut(self.local.get_or_insert_with(Arc::default)).insert(value);
        self
    }

    /// Inserts a setting when supplied, leaving the previous value intact for `None`.
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

    /// Sets the value of a type, or removes it when given `None`.
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

    /// Overlays the local settings from `other`, leaving defaults intact.
    pub(crate) fn extend(&mut self, other: Self) {
        if let Some(other) = other.local {
            match &mut self.local {
                Some(extensions) => Arc::make_mut(extensions).extend(Arc::unwrap_or_clone(other)),
                empty => *empty = Some(other),
            }
        }
    }
}
