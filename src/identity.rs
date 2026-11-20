//! Type-erased, pre-hashed keys for connection pools, QUIC tokens, and TLS sessions.

use std::{
    any::{Any, TypeId},
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    sync::{Arc, LazyLock},
};

use lru::DefaultHasher;

/// Type-erased, pre-hashed key with concrete-type and value equality.
///
/// Used for pool entries, QUIC address tokens, and TLS session keys. Clones share the
/// underlying key via [`Arc`] and reuse its precomputed hash.
#[derive(Clone)]
pub(crate) struct Identity {
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

// ===== impl Identity =====

impl Identity {
    /// Hashes `(TypeId::of::<K>(), &key)` once and erases `key` into an [`Identity`].
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

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("hash", &self.hash)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && (Arc::ptr_eq(&self.key, &other.key) || self.key.eq_key(other.key.as_ref()))
    }
}

impl Eq for Identity {}

impl Hash for Identity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl<T: Eq + Hash + Send + Sync + 'static> ErasedKey for T {
    fn eq_key(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<T>() == Some(self)
    }
}

#[test]
fn erased_keys_compare_type_and_value() {
    use std::hash::BuildHasherDefault;

    #[derive(PartialEq, Eq)]
    struct Colliding(u8);

    impl Hash for Colliding {
        fn hash<H: Hasher>(&self, state: &mut H) {
            0u8.hash(state);
        }
    }

    let key = Identity::new((Colliding(1),));
    let equal = Identity::new((Colliding(1),));
    let collision = Identity::new((Colliding(2),));
    let hasher = BuildHasherDefault::<std::hash::DefaultHasher>::default();
    assert!(key == equal);
    assert_eq!(hasher.hash_one(&key), hasher.hash_one(&equal));
    assert_eq!(hasher.hash_one(&key), hasher.hash_one(&collision));
    assert!(key != collision);
    assert!(Identity::new((1u8,)) != Identity::new((1u16,)));
}
