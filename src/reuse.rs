//! Reuse partitions and comparison keys for connections, TLS tickets, and QUIC address tokens.

use std::{
    any::{Any, TypeId},
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    sync::{Arc, LazyLock},
};

use lru::DefaultHasher;

/// A user-defined partition that restricts reuse without changing connection compatibility.
///
/// Requests in different groups do not share pooled connections, TLS session tickets, or
/// QUIC address tokens, even when their connection settings otherwise match.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Group(GroupRepr);

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum GroupRepr {
    Name(Arc<str>),
    Number(u64),
}

/// Type-erased, pre-hashed key with concrete-type and value equality.
///
/// Used for pool entries, QUIC address tokens, and TLS session keys. Clones share the
/// underlying key via [`Arc`] and reuse its precomputed hash.
#[derive(Clone)]
pub(crate) struct Key {
    key: Arc<dyn ErasedKey>,
    hash: u64,
}

/// Object-safe equality for an owned key whose concrete type is erased.
///
/// Implemented automatically for every `Eq + Hash + Send + Sync + 'static` type.
trait ErasedKey: Any + Send + Sync {
    /// Returns `true` if `other` has the same concrete type and compares equal to `self`.
    #[must_use]
    fn eq_key(&self, other: &dyn Any) -> bool;
}

// ===== impl Group =====

impl Group {
    /// Creates a group from a string or numeric identifier.
    #[inline]
    pub fn new<G: Into<Self>>(group: G) -> Self {
        group.into()
    }
}

impl From<&str> for Group {
    #[inline]
    fn from(value: &str) -> Self {
        Self(GroupRepr::Name(Arc::from(value)))
    }
}

impl From<String> for Group {
    #[inline]
    fn from(value: String) -> Self {
        Self(GroupRepr::Name(Arc::from(value)))
    }
}

impl From<Box<str>> for Group {
    #[inline]
    fn from(value: Box<str>) -> Self {
        Self(GroupRepr::Name(Arc::from(value)))
    }
}

impl From<u64> for Group {
    #[inline]
    fn from(value: u64) -> Self {
        Self(GroupRepr::Number(value))
    }
}

// ===== impl Key =====

impl Key {
    /// Hashes the key's concrete type and value before erasing its type.
    #[must_use]
    pub(crate) fn new<K: Eq + Hash + Send + Sync + 'static>(key: K) -> Self {
        static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);
        let hash = HASHER.hash_one((TypeId::of::<K>(), &key));
        Self {
            key: Arc::new(key),
            hash,
        }
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("hash", &self.hash)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && (Arc::ptr_eq(&self.key, &other.key) || self.key.eq_key(other.key.as_ref()))
    }
}

impl Eq for Key {}

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl<T: Eq + Hash + Send + Sync + 'static> ErasedKey for T {
    fn eq_key(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<T>() == Some(self)
    }
}

#[cfg(test)]
mod tests {
    use std::hash::BuildHasherDefault;

    use super::*;

    #[test]
    fn textual_groups_have_one_identity() {
        let borrowed = Group::new("worker");
        let owned = Group::new(String::from("worker"));
        let hasher = BuildHasherDefault::<std::hash::DefaultHasher>::default();

        assert_eq!(borrowed, owned);
        assert_eq!(hasher.hash_one(&borrowed), hasher.hash_one(&owned));
        assert_ne!(borrowed, Group::new(1));
    }

    #[test]
    fn erased_keys_compare_type_and_value() {
        #[derive(PartialEq, Eq)]
        struct Colliding(u8);

        impl Hash for Colliding {
            fn hash<H: Hasher>(&self, state: &mut H) {
                0u8.hash(state);
            }
        }

        let key = Key::new((Colliding(1),));
        let equal = Key::new((Colliding(1),));
        let collision = Key::new((Colliding(2),));
        let hasher = BuildHasherDefault::<std::hash::DefaultHasher>::default();
        assert!(key == equal);
        assert_eq!(hasher.hash_one(&key), hasher.hash_one(&equal));
        assert_eq!(hasher.hash_one(&key), hasher.hash_one(&collision));
        assert!(key != collision);
        assert!(Key::new((1u8,)) != Key::new((1u16,)));
    }
}
