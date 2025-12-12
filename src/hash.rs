use std::{
    borrow::Borrow,
    hash::{BuildHasher, Hash, Hasher},
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};

use ahash::RandomState;
use schnellru::ByLength;

/// Pre-seeded [`RandomState`] for consistent internal hashing.
///
/// Uses fixed seeds to ensure deterministic hashing behavior across
/// program runs. Primarily used for connection pools and internal caches.
///
/// **Note**: Not cryptographically secure due to fixed seeds.
pub const HASHER: RandomState = RandomState::with_seeds(
    0x6b68_d618_a4b5_3c57,
    0xadc8_c4d5_82bb_1313,
    0x2f72_c2c1_9b04_2d4c,
    0x94e5_8d83_a26c_3f28,
);

/// A type alias for a hash set using `ahash` with a pre-seeded `RandomState`.
pub type HashSet<T> = std::collections::HashSet<T, RandomState>;

/// A type alias for a hash map using `ahash` with a pre-seeded `RandomState`.
pub type HashMap<K, V> = std::collections::HashMap<K, V, RandomState>;

/// A specialized LRU cache using `schnellru` with a fixed capacity
pub type LruMap<K, V> = schnellru::LruMap<K, V, ByLength, RandomState>;

/// A wrapper that memoizes the hash value of its contained data.
#[derive(Debug)]
pub struct HashMemo<T, H: BuildHasher = RandomState>
where
    T: Eq + PartialEq + Hash,
{
    value: T,
    hash: AtomicU64,
    hasher: H,
}

impl<T, H> HashMemo<T, H>
where
    T: Eq + Hash,
    H: BuildHasher,
{
    /// Creates a new `HashMemo` with a custom hasher.
    ///
    /// This allows you to specify a custom `BuildHasher` implementation for
    /// controlling how hash values are computed.
    pub const fn with_hasher(value: T, hasher: H) -> Self {
        Self {
            value,
            hash: AtomicU64::new(u64::MIN),
            hasher,
        }
    }
}

impl<T, H> Hash for HashMemo<T, H>
where
    T: Eq + Hash,
    H: BuildHasher,
{
    fn hash<H2: Hasher>(&self, state: &mut H2) {
        let hash = self.hash.load(Ordering::Relaxed);
        if hash != 0 {
            state.write_u64(hash);
            return;
        }

        let computed_hash = NonZeroU64::new(self.hasher.hash_one(&self.value))
            .map(NonZeroU64::get)
            .unwrap_or(1);

        let _ = self.hash.compare_exchange(
            u64::MIN,
            computed_hash,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        state.write_u64(computed_hash);
    }
}

impl<T, H> PartialOrd for HashMemo<T, H>
where
    T: Eq + Hash + PartialOrd,
    H: BuildHasher,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl<T, H> Ord for HashMemo<T, H>
where
    T: Eq + Hash + Ord,
    H: BuildHasher,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl<T, H> PartialEq for HashMemo<T, H>
where
    T: Eq + Hash,
    H: BuildHasher,
{
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T, H> Eq for HashMemo<T, H>
where
    T: Eq + Hash,
    H: BuildHasher,
{
}

impl<T, H> AsRef<T> for HashMemo<T, H>
where
    T: Eq + Hash,
    H: BuildHasher,
{
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl<T, H> Borrow<T> for HashMemo<T, H>
where
    T: Eq + Hash,
    H: BuildHasher,
{
    fn borrow(&self) -> &T {
        &self.value
    }
}
