use std::{
    borrow::Borrow,
    collections::{HashMap, hash_map::Entry},
    hash::{Hash, Hasher},
    num::NonZeroUsize,
    sync::Arc,
};

use lru::LruCache;

use crate::{client::ConnectionId, sync::Mutex, tls::TlsVersion};

/// An opaque key identifying a TLS session cache entry.
#[derive(Clone)]
pub struct TlsSessionKey(pub(crate) ConnectionId);

/// A TLS session that can be stored and retrieved from a session cache.
#[derive(Clone)]
pub struct TlsSession(pub(crate) btls::ssl::SslSession);

/// A trait for storing and retrieving TLS sessions.
///
/// # TLS 1.3 Session Handling
///
/// For TLS 1.3 sessions, implementations **should** remove the session after
/// retrieval to comply with [RFC 8446 Appendix C.4](https://tools.ietf.org/html/rfc8446#appendix-C.4),
/// which requires that session tickets are used at most once to prevent
/// concurrent handshakes from reusing the same session.
pub trait TlsSessionStore: Send + Sync {
    /// Store a TLS session associated with the given key.
    fn insert(&self, key: TlsSessionKey, session: TlsSession);

    /// Retrieve a TLS session for the given key.
    ///
    /// For TLS 1.3, the session should be removed from the cache upon retrieval
    /// to ensure single-use semantics (see [RFC 8446 Appendix C.4]).
    fn get(&self, key: &TlsSessionKey) -> Option<TlsSession>;
}

impl_into_shared!(
    /// Trait for converting types into a shared [`TlsSessionStore`].
    ///
    /// This allows accepting bare types, `Arc<T>`, or `Arc<dyn TlsSessionStore>`.
    pub trait IntoTlsSessionStore => TlsSessionStore
);

/// The default two-level LRU session cache.
///
/// Maintains both forward (key → sessions) and reverse (session → key) lookups
/// for efficient session storage, retrieval, and cleanup operations.
///
/// This is the built-in implementation of [`TlsSessionStore`] used when no
/// custom session store is configured.
pub struct LruSessionStore {
    inner: Mutex<Inner>,
    per_host_session_capacity: usize,
}

struct Inner {
    reverse: HashMap<TlsSession, TlsSessionKey>,
    per_host_sessions: HashMap<TlsSessionKey, LruCache<TlsSession, ()>>,
}

// ===== impl SessionKey =====

impl Eq for TlsSessionKey {}

impl PartialEq for TlsSessionKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Hash for TlsSessionKey {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// ===== impl TlsSession =====

impl TlsSession {
    /// Returns the session ID as a byte slice.
    #[inline]
    pub fn id(&self) -> &[u8] {
        self.0.id()
    }

    /// Returns the TLS protocol version negotiated for this session.
    #[inline]
    pub fn protocol_version(&self) -> TlsVersion {
        TlsVersion(self.0.protocol_version())
    }

    /// Returns the session establishment time as seconds since the Unix epoch.
    #[inline]
    pub fn time(&self) -> u64 {
        self.0.time()
    }

    /// Returns the session timeout in seconds.
    #[inline]
    pub fn timeout(&self) -> u32 {
        self.0.timeout()
    }
}

impl Eq for TlsSession {}

impl PartialEq for TlsSession {
    #[inline]
    fn eq(&self, other: &TlsSession) -> bool {
        self.0.id() == other.0.id()
    }
}

impl Hash for TlsSession {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.id().hash(state);
    }
}

impl Borrow<[u8]> for TlsSession {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.0.id()
    }
}

// ===== impl LruSessionStore =====

impl LruSessionStore {
    /// Creates a new [`LruSessionStore`] with the given per-host capacity.
    pub fn new(per_host_session_capacity: usize) -> Self {
        LruSessionStore {
            inner: Mutex::new(Inner {
                reverse: HashMap::new(),
                per_host_sessions: HashMap::new(),
            }),
            per_host_session_capacity,
        }
    }
}

impl TlsSessionStore for LruSessionStore {
    fn insert(&self, key: TlsSessionKey, session: TlsSession) {
        let mut inner = self.inner.lock();

        let evicted = {
            let per_host_sessions =
                inner
                    .per_host_sessions
                    .entry(key.clone())
                    .or_insert_with(|| {
                        NonZeroUsize::new(self.per_host_session_capacity)
                            .map_or_else(LruCache::unbounded, LruCache::new)
                    });

            // Enforce per-key capacity limit by evicting the least recently used session
            let evicted = if per_host_sessions.len() >= self.per_host_session_capacity {
                per_host_sessions.pop_lru().map(|(s, _)| s)
            } else {
                None
            };

            per_host_sessions.put(session.clone(), ());
            evicted
        };

        if let Some(evicted_session) = evicted {
            inner.reverse.remove(&evicted_session);
        }
        inner.reverse.insert(session, key);
    }

    fn get(&self, key: &TlsSessionKey) -> Option<TlsSession> {
        let mut inner = self.inner.lock();
        let session = {
            let per_host_sessions = inner.per_host_sessions.get_mut(key)?;
            per_host_sessions.peek_lru()?.0.clone()
        };

        // https://tools.ietf.org/html/rfc8446#appendix-C.4
        // OpenSSL will remove the session from its cache after the handshake completes anyway, but
        // this ensures that concurrent handshakes don't end up with the same session.
        if session.protocol_version() == TlsVersion::TLS_1_3 {
            if let Some(key) = inner.reverse.remove(&session) {
                if let Entry::Occupied(mut entry) = inner.per_host_sessions.entry(key) {
                    entry.get_mut().pop(&session);
                    if entry.get().is_empty() {
                        entry.remove();
                    }
                }
            }
        }

        Some(session)
    }
}
