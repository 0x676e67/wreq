//! Client TLS construction settings and compiled contexts for TCP, Unix and QUIC.

use std::{num::NonZeroUsize, sync::Arc};

use btls::ssl::{SslContextBuilder, SslVerifyMode};
use lru::LruCache;

use super::{
    TlsVersion, connector,
    ext::SslContextBuilderExt,
    keylog::KeyLog,
    session::Tickets,
    trust::{CertStore, Identity},
};
use crate::{
    Error,
    conn::config::{ConfigSet, Overrides},
    sync::Mutex,
};

/// Client-wide TLS policy, fixed at build and compiled into TCP/Unix and QUIC contexts.
/// The minimum version applies to TCP/Unix. QUIC checks the maximum version against TLS 1.3
/// and uses its own ALPN. Clones share one session store across both transports.
#[derive(Clone)]
pub(crate) struct TlsConfig {
    pub(crate) min_version: Option<TlsVersion>,
    pub(crate) max_version: Option<TlsVersion>,
    pub(crate) sni: bool,
    pub(crate) verify_hostname: bool,
    pub(crate) cert_verification: bool,
    pub(crate) keylog: Option<KeyLog>,
    pub(crate) identity: Option<Identity>,
    pub(crate) cert_store: Option<CertStore>,
    pub(crate) tickets: Arc<Tickets>,
    pub(crate) tls_info: bool,
}

/// The client's compiled TLS context and the most recently used request contexts, keyed by
/// the request's context [`Overrides`].
///
/// Contexts are stored without per-connection callbacks or session caches; each connection
/// sets its own on a copy.
pub(super) struct ContextCache<T> {
    client: T,
    requests: Mutex<LruCache<Overrides, T>>,
}

/// Request contexts kept per client, least recently used evicted first.
const REQUEST_CONTEXTS: NonZeroUsize =
    NonZeroUsize::new(16).expect("request context capacity must be non-zero");

// ===== impl TlsConfig =====

impl TlsConfig {
    /// Applies the client's identity, trust roots, verification and key log to a context.
    pub(super) fn configure(&self, builder: &mut SslContextBuilder) -> crate::Result<()> {
        builder.set_identity(self.identity.as_ref())?;
        builder.set_root_store(self.cert_store.as_ref())?;
        builder.set_cert_verification(self.cert_verification);

        if let Some(policy) = self.keylog.clone()
            && let Some(handle) = policy.handle().map_err(Error::tls)?
        {
            builder.set_keylog_callback(move |_, line| {
                handle.write(line);
            });
        }

        Ok(())
    }

    /// Shares this client's session scope across contexts and, when verification is enabled,
    /// re-verifies the server certificate chain on resumption.
    pub(super) fn enable_resumption(&self, builder: &mut SslContextBuilder) -> crate::Result<()> {
        // Resumption skips certificate checks unless a custom verifier runs them again; this
        // one keeps the built-in X.509 checks. Verification off uses VERIFY_NONE, which
        // re-verification does not support.
        if self.cert_verification {
            builder.set_custom_verify_callback(SslVerifyMode::PEER, |ssl| {
                Ok(ssl.verify_peer_cert_chain()?)
            });
            builder.set_reverify_on_resume(true);
        }
        let scope = self.tickets.session_id_context().map_err(Error::tls)?;
        builder.set_session_id_context(&scope).map_err(Error::tls)?;
        // This limits TLS 1.2 sessions; TLS 1.3 also obeys the server's ticket lifetime.
        builder.set_session_timeout(60 * 60);
        Ok(())
    }

    /// Compiles the client's TCP/Unix context from its TLS options.
    /// Missing options leave TLS customization to the backend's defaults; the client-wide
    /// trust, version, and ALPN policy still applies.
    pub(crate) fn build(self, config_set: &ConfigSet) -> crate::Result<connector::HttpsLayer> {
        connector::HttpsLayer::new(self, config_set.clone())
    }

    /// Compiles the client's QUIC context from its QUIC options.
    #[cfg(feature = "http3")]
    pub(crate) fn build_quic(
        self,
        config_set: &ConfigSet,
    ) -> crate::Result<super::quic::TlsConfig> {
        super::quic::TlsConfig::new(self, config_set.clone())
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: None,
            max_version: None,
            sni: true,
            verify_hostname: true,
            cert_verification: true,
            keylog: None,
            identity: None,
            cert_store: None,
            tickets: Arc::new(Tickets::new(None)),
            tls_info: false,
        }
    }
}

// ===== impl ContextCache =====

impl<T: Clone> ContextCache<T> {
    /// Starts with the client's context and no request contexts.
    pub(super) fn new(client: T) -> Self {
        Self {
            client,
            requests: Mutex::new(LruCache::sparse(REQUEST_CONTEXTS)),
        }
    }

    /// Returns the client's context when `overrides` is empty, and otherwise the request's.
    /// A missing request context is compiled outside the lock, so concurrent misses may
    /// compile it more than once.
    pub(super) fn get(
        &self,
        overrides: Overrides,
        compile: impl FnOnce(&Overrides) -> crate::Result<T>,
    ) -> crate::Result<T> {
        if overrides.is_empty() {
            return Ok(self.client.clone());
        }
        if let Some(context) = self.requests.lock().get(&overrides) {
            return Ok(context.clone());
        }
        let context = compile(&overrides)?;
        // An evicted context is freed after the lock is released.
        let _evicted = self.requests.lock().push(overrides, context.clone());
        Ok(context)
    }
}
