//! Type-indexed client and request connection options.

use std::sync::Arc;

use http::Extensions;

/// Connection options shared until edited.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectConfig(Option<Arc<Extensions>>);

impl ConnectConfig {
    /// Borrows the setting stored for `T`.
    #[inline]
    #[must_use]
    pub(crate) fn get_ref<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.get_arc_ref().map(Arc::as_ref)
    }

    /// Borrows `T` from the request, falling back to the client's configuration.
    #[inline]
    #[must_use]
    pub(crate) fn get_or<'a, T: Send + Sync + 'static>(
        &'a self,
        client_config: &'a Self,
    ) -> Option<&'a T> {
        self.get_ref().or_else(|| client_config.get_ref())
    }

    /// Clones the shared handle stored for `T`.
    #[inline]
    #[must_use]
    pub(crate) fn get_arc<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.get_arc_ref().cloned()
    }

    /// Borrows the shared handle stored for `T`.
    #[inline]
    #[must_use]
    pub(crate) fn get_arc_ref<T: Send + Sync + 'static>(&self) -> Option<&Arc<T>> {
        self.0.as_ref()?.get::<Arc<T>>()
    }

    /// Stores a setting, replacing any previous value of the same type.
    #[inline]
    pub(crate) fn insert<T: Send + Sync + 'static>(&mut self, value: T) -> &mut Self {
        self.insert_arc(Arc::new(value))
    }

    /// Stores an existing shared setting.
    #[inline]
    pub(crate) fn insert_arc<T: Send + Sync + 'static>(&mut self, value: Arc<T>) -> &mut Self {
        Arc::make_mut(self.0.get_or_insert_with(Arc::default)).insert(value);
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
        if let Some(extensions) = &mut self.0
            && extensions.get::<Arc<T>>().is_some()
        {
            let extensions = Arc::make_mut(extensions);
            extensions.remove::<Arc<T>>();
            if extensions.is_empty() {
                self.0 = None;
            }
        }
    }

    /// Overlays the settings from `other`, leaving unmentioned types intact.
    pub(crate) fn extend(&mut self, other: Self) {
        if let Some(other) = other.0 {
            match &mut self.0 {
                Some(extensions) => Arc::make_mut(extensions).extend(Arc::unwrap_or_clone(other)),
                empty => *empty = Some(other),
            }
        }
    }
}
