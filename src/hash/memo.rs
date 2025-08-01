use std::{
    borrow::Borrow,
    hash::{BuildHasher, BuildHasherDefault, Hash, Hasher},
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};

use ahash::RandomState;

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
            .unwrap_or(u64::MIN | 1);

        let _ = self.hash.compare_exchange(
            u64::MIN,
            computed_hash,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        state.write_u64(computed_hash);
    }
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

impl<T, H> From<T> for HashMemo<T, BuildHasherDefault<H>>
where
    T: Eq + Hash,
    H: Hasher + Default,
{
    fn from(value: T) -> Self {
        Self::with_hasher(value, BuildHasherDefault::<H>::default())
    }
}

impl<T, H> Clone for HashMemo<T, H>
where
    T: Eq + Hash + Clone,
    H: BuildHasher + Clone,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            hash: AtomicU64::new(self.hash.load(Ordering::Relaxed)),
            hasher: self.hasher.clone(),
        }
    }
}
