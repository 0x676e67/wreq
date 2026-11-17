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
    pub(super) client_config: ConnectConfig,
    pub(super) options: Option<Arc<O>>,
    client_context: T,
    requests: Mutex<LruCache<u64, (Arc<O>, T)>>,
}

impl<O: ContextOptions, T: Clone> TlsContext<O, T> {
    pub(super) fn new(
        tls: Config,
        client_config: &ConnectConfig,
        compile: impl FnOnce(&Config, Option<&O>) -> Result<T>,
    ) -> Result<Self> {
        let options = client_config.get_arc::<O>();
        let client_context = compile(&tls, options.as_deref())?;
        Ok(Self {
            tls,
            client_config: client_config.clone(),
            options,
            client_context,
            requests: Mutex::new(LruCache::sparse(REQUEST_CONTEXTS)),
        })
    }

    /// Reuses the client's context when the request has equivalent context options.
    /// Compilation runs outside the lock, so concurrent misses can compile the same context.
    pub(super) fn for_config(
        &self,
        overrides: &ConnectConfig,
        compile: impl FnOnce(&Config, Option<&O>) -> Result<T>,
    ) -> Result<T> {
        let Some(options) = overrides.get_arc::<O>() else {
            return Ok(self.client_context.clone());
        };
        if self
            .options
            .as_ref()
            .is_some_and(|client| client.same_context(&options))
        {
            return Ok(self.client_context.clone());
        }

        let mut hasher = HASHER.build_hasher();
        options.hash_context(&mut hasher);
        let hash = hasher.finish();
        // A fingerprint collision is a cache miss, so compare the compiled options on a hit.
        if let Some((cached, context)) = self.requests.lock().get(&hash)
            && cached.same_context(&options)
        {
            return Ok(context.clone());
        }

        let context = compile(&self.tls, Some(&options))?;
        // An evicted context is freed after the lock is released.
        let _evicted = self.requests.lock().push(hash, (options, context.clone()));
        Ok(context)
    }
}
