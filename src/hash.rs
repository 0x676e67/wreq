use std::{
    borrow::Borrow,
    hash::{BuildHasher, Hash, Hasher},
    num::NonZeroU64,
    sync::{
        LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};

use lru::DefaultHasher;

/// A wrapper that memoizes the hash value of its contained data.
#[derive(Debug)]
pub struct HashMemo<T>
where
    T: Eq + PartialEq + Hash,
{
    value: T,
    hash: AtomicU64,
}

impl<T> HashMemo<T>
where
    T: Eq + Hash,
{
    /// Creates a new [`HashMemo`].
    pub fn new(value: T) -> Self {
        Self {
            value,
            hash: AtomicU64::new(u64::MIN),
        }
    }
}

impl<T> Hash for HashMemo<T>
where
    T: Eq + Hash,
{
    fn hash<H2: Hasher>(&self, state: &mut H2) {
        let hash = self.hash.load(Ordering::Relaxed);
        if hash != 0 {
            state.write_u64(hash);
            return;
        }

        static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);

        let computed_hash = NonZeroU64::new(HASHER.hash_one(&self.value))
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

impl<T> PartialOrd for HashMemo<T>
where
    T: Eq + Hash + PartialOrd,
{
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl<T> Ord for HashMemo<T>
where
    T: Eq + Hash + Ord,
{
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl<T> PartialEq for HashMemo<T>
where
    T: Eq + Hash,
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T> Eq for HashMemo<T> where T: Eq + Hash {}

impl<T> AsRef<T> for HashMemo<T>
where
    T: Eq + Hash,
{
    #[inline]
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl<T> Borrow<T> for HashMemo<T>
where
    T: Eq + Hash,
{
    #[inline]
    fn borrow(&self) -> &T {
        &self.value
    }
}
