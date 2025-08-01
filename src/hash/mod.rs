mod memo;

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

/// A type alias for a hash memoization structure using `ahash` with a pre-seeded `RandomState`.
pub type HashMemo<K> = memo::HashMemo<K, RandomState>;

/// A type alias for a hash set using `ahash` with a pre-seeded `RandomState`.
pub type HashSet<T> = std::collections::HashSet<T, RandomState>;

/// A type alias for a hash map using `ahash` with a pre-seeded `RandomState`.
pub type HashMap<K, V> = std::collections::HashMap<K, V, RandomState>;

/// A specialized LRU cache using `schnellru` with a fixed capacity
pub type LruMap<K, V> = schnellru::LruMap<K, V, ByLength, RandomState>;
