use std::{num::NonZeroUsize, sync::Arc};

use lru::LruCache;

use super::Config;
use crate::{
    Result,
    config::connect::{ConnectConfig, ConnectConfigValue, KeyScope},
    sync::Mutex,
};

const REQUEST_CONTEXTS: NonZeroUsize =
    NonZeroUsize::new(16).expect("request context capacity must be non-zero");

/// One transport's TLS policy, client configuration, and compiled contexts.
/// A connection configures its own copy of a compiled context for the handshake.
pub(super) struct TlsContext<O, T> {
    pub(super) tls: Config,
    pub(super) client_config: ConnectConfig,
    pub(super) options: Option<Arc<O>>,
    client_context: T,
    requests: Mutex<LruCache<u64, (Arc<O>, T)>>,
}

// ===== impl TlsContext =====

impl<O: ConnectConfigValue, T: Clone> TlsContext<O, T> {
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
        let Some((hash, options)) = overrides.context_override::<O>(&self.client_config) else {
            return Ok(self.client_context.clone());
        };
        // A fingerprint collision is a cache miss, so compare the compiled options on a hit.
        if let Some((cached, context)) = self.requests.lock().get(&hash)
            && (Arc::ptr_eq(cached, &options) || cached.eq_scope(&options, KeyScope::Context))
        {
            return Ok(context.clone());
        }

        let context = compile(&self.tls, Some(&options))?;
        // An evicted context is freed after the lock is released.
        let _evicted = self.requests.lock().push(hash, (options, context.clone()));
        Ok(context)
    }
}
