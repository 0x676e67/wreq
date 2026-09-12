//! Type-indexed connection configuration and response metadata.
//! Configuration participates in reuse identity; ordinary metadata does not.
//! Both share the same storage and copy-on-write ownership rules.

use std::{
    any::{Any, TypeId, type_name},
    collections::BTreeMap,
    fmt,
    hash::{Hash, Hasher},
    sync::Arc,
};

/// Typed values retained during connection setup and response dispatch.
/// Clones share storage; mutations leave frozen connection requests unchanged.
/// Configuration defines reuse identity, while metadata is copied to responses.
/// Equality and hashing compare configuration only, ignoring ordinary metadata.
#[derive(Clone, Default)]
pub(crate) struct Extra(Option<Arc<BTreeMap<TypeId, Entry>>>);

/// One shared value and its optional connection-identity operations.
/// Replacement determines whether this type is configuration or metadata.
/// Cloning an entry shares its value without invoking the value's Clone.
#[derive(Clone)]
struct Entry {
    value: Arc<dyn Value>,
    identity: Option<Identity>,
}

/// Type-specific comparison and hashing captured on configuration insertion.
/// Both functions are paired with the same concrete type as the stored value.
/// Metadata has no identity operations and needs no Eq or Hash implementation.
#[derive(Clone, Copy)]
struct Identity {
    equals: fn(&dyn Any, &dyn Any) -> bool,
    hash: fn(&dyn Any, &mut dyn Hasher),
}

trait Value: Any + Send + Sync {
    fn copy_to(&self, extensions: &mut http::Extensions);
    fn type_name(&self) -> &'static str;
}

// ===== impl Extra =====

impl Extra {
    /// Inserts response metadata, discarding the previous value without cloning it.
    /// Replacing configuration with metadata removes that type from reuse identity.
    pub(crate) fn insert<T>(&mut self, value: T)
    where
        T: Clone + Send + Sync + 'static,
    {
        self.insert_entry(value, None);
    }

    /// Inserts configuration whose complete value participates in reuse identity.
    /// Eq and Hash must remain stable while any connection request retains it.
    /// Configuration is never copied into response extensions as metadata.
    pub(crate) fn insert_config<T>(&mut self, value: T)
    where
        T: Clone + Eq + Hash + Send + Sync + 'static,
    {
        self.insert_entry(value, Some(Identity::of::<T>()));
    }

    /// Returns the value stored for this exact Rust type, regardless of its role.
    pub(crate) fn get<T: 'static>(&self) -> Option<&T> {
        self.0
            .as_ref()?
            .get(&TypeId::of::<T>())
            .and_then(|entry| (entry.value.as_ref() as &dyn Any).downcast_ref())
    }

    /// Removes configuration or metadata, returning its shared value without cloning it.
    /// Missing types leave shared storage unchanged.
    pub(crate) fn remove<T: Send + Sync + 'static>(&mut self) -> Option<Arc<T>> {
        let entries = self.0.as_mut()?;
        let id = TypeId::of::<T>();
        // Unique maps need one lookup; shared maps are copied only for an existing type.
        let entry = if let Some(entries) = Arc::get_mut(entries) {
            entries.remove(&id)
        } else if entries.contains_key(&id) {
            Arc::make_mut(entries).remove(&id)
        } else {
            None
        }?;
        let value: Arc<dyn Any + Send + Sync> = entry.value;
        value.downcast().ok()
    }

    /// Sets configuration or removes the existing value when absent.
    /// Discarded shared values are released without cloning them.
    pub(crate) fn set_config<T>(&mut self, value: Option<T>) -> &mut Self
    where
        T: Clone + Eq + Hash + Send + Sync + 'static,
    {
        match value {
            Some(value) => self.insert_config(value),
            None => {
                self.remove::<T>();
            }
        }
        self
    }

    /// Returns mutable configuration, inserting its default value when absent.
    /// Shared values are cloned before mutation to preserve frozen keys.
    /// An existing metadata value becomes configuration before it is returned.
    pub(crate) fn config_or_default<T>(&mut self) -> &mut T
    where
        T: Default + Clone + Eq + Hash + Send + Sync + 'static,
    {
        let entry = self
            .entries_mut()
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Entry {
                value: Arc::new(T::default()),
                identity: None,
            });
        entry.identity = Some(Identity::of::<T>());
        if Arc::get_mut(&mut entry.value).is_none() {
            // Detach only the requested value; other entries keep their shared handles.
            entry.value = Arc::new(
                (entry.value.as_ref() as &dyn Any)
                    .downcast_ref::<T>()
                    .expect("entry type must match its TypeId")
                    .clone(),
            );
        }
        // Every insertion pairs TypeId::of::<T>() with T, and this Arc is now unique.
        Arc::get_mut(&mut entry.value)
            .and_then(|value| (value as &mut dyn Any).downcast_mut::<T>())
            .expect("entry must contain a uniquely owned value of its indexed type")
    }

    /// Copies only ordinary metadata into a response, preserving concrete types.
    /// Connection configuration stays private even when both roles share storage.
    pub(crate) fn copy_metadata_to(&self, extensions: &mut http::Extensions) {
        for entry in self.0.iter().flat_map(|entries| entries.values()) {
            if entry.identity.is_none() {
                entry.value.as_ref().copy_to(extensions);
            }
        }
    }

    fn config_entries(&self) -> impl Iterator<Item = (&TypeId, &Arc<dyn Value>, Identity)> {
        self.0
            .iter()
            .flat_map(|entries| entries.iter())
            .filter_map(|(id, entry)| entry.identity.map(|identity| (id, &entry.value, identity)))
    }

    fn entries_mut(&mut self) -> &mut BTreeMap<TypeId, Entry> {
        Arc::make_mut(self.0.get_or_insert_default())
    }

    fn insert_entry<T>(&mut self, value: T, identity: Option<Identity>)
    where
        T: Clone + Send + Sync + 'static,
    {
        self.entries_mut().insert(
            TypeId::of::<T>(),
            Entry {
                value: Arc::new(value),
                identity,
            },
        );
    }
}

impl PartialEq for Extra {
    fn eq(&self, other: &Self) -> bool {
        if let (Some(left), Some(right)) = (&self.0, &other.0)
            && Arc::ptr_eq(left, right)
        {
            return true;
        }
        let mut left = self.config_entries();
        let mut right = other.config_entries();
        loop {
            match (left.next(), right.next()) {
                (None, None) => return true,
                (Some((a, left, identity)), Some((b, right, _)))
                    if a == b
                        && (Arc::ptr_eq(left, right)
                            || (identity.equals)(left.as_ref(), right.as_ref())) => {}
                _ => return false,
            }
        }
    }
}

impl Eq for Extra {}

impl Hash for Extra {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // TypeId order makes configuration hashing independent of insertion order.
        let mut count = 0_usize;
        for (id, value, identity) in self.config_entries() {
            id.hash(state);
            (identity.hash)(value.as_ref(), state);
            count += 1;
        }
        count.hash(state);
    }
}

impl fmt::Debug for Extra {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(
                self.0
                    .iter()
                    .flat_map(|entries| entries.values())
                    .map(|entry| entry.value.as_ref().type_name()),
            )
            .finish()
    }
}

// ===== impl Identity =====

impl Identity {
    fn of<T: Eq + Hash + 'static>() -> Self {
        Self {
            equals: |left, right| left.downcast_ref::<T>() == right.downcast_ref::<T>(),
            hash: |value, mut state| {
                if let Some(value) = value.downcast_ref::<T>() {
                    value.hash(&mut state);
                }
            },
        }
    }
}

// ===== impl Value =====

impl<T: Clone + Send + Sync + 'static> Value for T {
    fn copy_to(&self, extensions: &mut http::Extensions) {
        extensions.insert(self.clone());
    }

    fn type_name(&self) -> &'static str {
        type_name::<T>()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Counts metadata copies without providing equality or hashing.
    /// Shared container clones must not invoke its Clone implementation.
    /// Response export copies values; removal only releases their shared handles.
    struct Copies(Arc<AtomicUsize>);

    impl Clone for Copies {
        fn clone(&self) -> Self {
            self.0.fetch_add(1, Ordering::Relaxed);
            Self(self.0.clone())
        }
    }

    #[test]
    fn shares_values_and_keeps_configuration_out_of_responses() {
        let copies = Arc::new(AtomicUsize::new(0));
        let mut extra = Extra::default();
        assert!(extra.0.is_none());
        assert!(extra.remove::<u32>().is_none());
        extra.set_config::<u32>(None);
        assert!(extra.0.is_none());

        extra.insert(Copies(copies.clone()));
        extra.insert(String::from("private metadata"));
        extra.insert_config(7_u32);
        let frozen = extra.clone();
        assert!(extra.remove::<u64>().is_none());
        extra.set_config::<u64>(None);
        assert!(Arc::ptr_eq(
            extra.0.as_ref().unwrap(),
            frozen.0.as_ref().unwrap()
        ));
        *extra.config_or_default::<u32>() += 1;
        extra.insert(String::from("replacement"));
        assert_eq!(copies.load(Ordering::Relaxed), 0);
        assert_eq!(frozen.get::<u32>(), Some(&7));
        assert_eq!(extra.get::<u32>(), Some(&8));
        assert_eq!(frozen.get::<String>().unwrap(), "private metadata");
        let debug = format!("{frozen:?}");
        assert!(debug.contains(type_name::<Copies>()));
        assert!(debug.contains(type_name::<String>()));
        assert!(debug.contains(type_name::<u32>()));
        assert!(!debug.contains("private metadata"));

        for extra in [&frozen, &extra] {
            let mut response = http::Extensions::new();
            extra.copy_metadata_to(&mut response);
            assert!(response.get::<Copies>().is_some());
            assert_eq!(response.get::<String>(), extra.get::<String>());
            assert!(response.get::<u32>().is_none());
        }
        assert_eq!(copies.load(Ordering::Relaxed), 2);
        let removed = extra.remove::<Copies>().unwrap();
        assert!(Arc::ptr_eq(&removed.0, &copies));
        assert!(extra.get::<Copies>().is_none());
        assert!(frozen.get::<Copies>().is_some());
        assert_eq!(copies.load(Ordering::Relaxed), 2);
        drop(extra);
        frozen.clone().remove::<Copies>();
        assert_eq!(copies.load(Ordering::Relaxed), 2);

        let mut extra = Extra::default();
        extra.insert(3_u32);
        *extra.config_or_default::<u32>() += 1;
        let config = extra.clone();
        assert_ne!(config, Extra::default());
        extra.insert(5_u32);
        assert_eq!(extra.get::<u32>(), Some(&5));
        assert_eq!(extra, Extra::default());
        extra.insert_config(6_u32);
        assert_eq!(extra.get::<u32>(), Some(&6));
        let mut response = http::Extensions::new();
        extra.copy_metadata_to(&mut response);
        assert!(response.get::<u32>().is_none());
        assert_eq!(extra.remove::<u32>().as_deref(), Some(&6));
        assert!(extra.get::<u32>().is_none());
        assert_eq!(extra, Extra::default());
        assert_eq!(config.get::<u32>(), Some(&4));

        let mut extra = Extra::default();
        extra.config_or_default::<String>().push_str("first");
        let buffer = extra.get::<String>().unwrap().as_ptr();
        assert_eq!(extra.config_or_default::<String>().as_ptr(), buffer);
        let frozen = extra.clone();
        extra.config_or_default::<String>().push_str(" second");
        assert_eq!(frozen.get::<String>().unwrap(), "first");
        assert_eq!(extra.get::<String>().unwrap(), "first second");
        let shared = extra.0.as_ref().unwrap().clone();
        let sibling = frozen.0.as_ref().unwrap().clone();
        assert!(!Arc::ptr_eq(&shared, &sibling));
    }
}
