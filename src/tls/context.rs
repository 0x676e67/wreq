use std::{
    hash::{BuildHasher, Hasher},
    num::NonZeroUsize,
    sync::{Arc, LazyLock},
};

use lru::{DefaultHasher, LruCache};

use super::Config;
use crate::{Result, config::connect::ConnectConfig, sync::Mutex, tls_key::ContextOptions};

const REQUEST_CONTEXTS: NonZeroUsize =
    NonZeroUsize::new(16).expect("request context capacity must be non-zero");
static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);

/// One transport's TLS policy, client configuration, and compiled contexts.
/// A connection configures its own copy of a compiled context for the handshake.
pub(super) struct TlsContext<O, T> {
    pub(super) tls: Config,
    context: T,
    requests: Mutex<LruCache<u64, (Arc<O>, T)>>,
}

impl<O: ContextOptions, T: Clone> TlsContext<O, T> {
    pub(super) fn new(
        tls: Config,
        config: &ConnectConfig,
        compile: impl FnOnce(&Config, Option<&O>) -> Result<T>,
    ) -> Result<Self> {
        let context = compile(&tls, config.get_ref())?;
        Ok(Self {
            tls,
            context,
            requests: Mutex::new(LruCache::sparse(REQUEST_CONTEXTS)),
        })
    }

    /// Reuses the client's context when the request has equivalent context options.
    /// Compilation runs outside the lock, so concurrent misses can compile the same context.
    pub(super) fn for_config(
        &self,
        config: &ConnectConfig,
        compile: impl FnOnce(&Config, Option<&O>) -> Result<T>,
    ) -> Result<T> {
        let Some(value) = config.override_if_different(O::same_context) else {
            return Ok(self.context.clone());
        };

        let mut hasher = HASHER.build_hasher();
        value.hash_context(&mut hasher);
        let hash = hasher.finish();
        // A fingerprint collision is a cache miss, so compare the compiled options on a hit.
        if let Some((cached, context)) = self.requests.lock().get(&hash)
            && cached.same_context(value)
        {
            return Ok(context.clone());
        }

        let context = compile(&self.tls, Some(value))?;
        let entry = (value.clone(), context.clone());
        // An evicted context is freed after the lock is released.
        let _evicted = self.requests.lock().push(hash, entry);
        Ok(context)
    }
}
