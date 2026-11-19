use std::{
    hash::{BuildHasher, Hasher},
    num::NonZeroUsize,
    sync::{Arc, LazyLock},
};

use lru::{DefaultHasher, LruCache};

use super::KeyIdentity;
use crate::{Result, sync::Mutex};

const REQUEST_CONTEXTS: NonZeroUsize =
    NonZeroUsize::new(16).expect("request context capacity must be non-zero");
static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);

/// Compiled base TLS context paired with a bounded LRU cache for per-request overrides.
///
/// Shared by both stream and QUIC TLS contexts so identical request overrides reuse a single
/// compiled BoringSSL context instead of rebuilding it on every connection.
pub(crate) struct TlsContext<O, T> {
    inner: T,
    cache: Mutex<LruCache<u64, (Arc<O>, T)>>,
}

impl<O: KeyIdentity, T: Clone> TlsContext<O, T> {
    /// Creates a cache around the compiled base context.
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            cache: Mutex::new(LruCache::sparse(REQUEST_CONTEXTS)),
        }
    }

    /// Returns the base context when `options` is `None`, or looks up (and compiles on miss)
    /// a cached override context.
    ///
    /// Compilation runs outside the lock, so concurrent misses may compile redundantly.
    pub(crate) fn get_or_compile(
        &self,
        options: Option<&Arc<O>>,
        compile: impl FnOnce(&O) -> Result<T>,
    ) -> Result<T> {
        let Some(value) = options else {
            return Ok(self.inner.clone());
        };

        let mut hasher = HASHER.build_hasher();
        value.hash_key(&mut hasher);
        let hash = hasher.finish();
        // Guard against hash collisions by checking equality on hit.
        if let Some((cached, context)) = self.cache.lock().get(&hash)
            && cached.same(value)
        {
            return Ok(context.clone());
        }

        let context = compile(value)?;
        let entry = (value.clone(), context.clone());
        // Drop any evicted context after releasing the lock.
        let _evicted = self.cache.lock().push(hash, entry);
        Ok(context)
    }
}
