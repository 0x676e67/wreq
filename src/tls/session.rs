//! TLS session storage for ticket-based connection resumption.
//!
//! The built-in cache is bounded and in-memory. Applications can provide a
//! session cache when they need a different ticket retention policy.

pub(super) mod cache;
pub(super) mod entry;

use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::{Hash, Hasher},
    num::NonZeroUsize,
    sync::Arc,
};

use btls::ssl::SslSession;
pub(crate) use cache::SessionCache;
use lru::LruCache;

use crate::{conn::descriptor::ConnectionId, sync::Mutex, tls::TlsVersion};

const SESSION_ID_CONTEXT_LENGTH: usize = 32;

/// An opaque key identifying a TLS session cache entry.
///
/// It contains the client session scope and complete connection identity. This
/// prevents a cache shared by multiple clients from returning a foreign ticket.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Key(
    pub(super) ConnectionId,
    pub(super) [u8; SESSION_ID_CONTEXT_LENGTH],
);

/// A TLS session that can be stored and retrieved from a session cache.
///
/// The originating key is retained so sessions returned by configured caches can
/// be validated before resumption.
#[derive(Clone)]
pub struct TlsSession {
    pub(super) inner: SslSession,
    pub(super) key: Key,
}

/// Stores sessions used for ticket-based TLS resumption.
pub trait TlsSessionCache: Send + Sync {
    /// Store a TLS session associated with the given key.
    ///
    /// This method runs from BoringSSL's new-session callback. Implementations
    /// should return quickly and must not rely on a panic propagating to the
    /// caller. Panics are caught before they can cross the FFI boundary.
    fn put(&self, key: Key, session: TlsSession);

    /// Retrieve the newest TLS session for the given key.
    ///
    /// Implementations should remove a session when
    /// [`TlsSession::should_be_single_use`] returns `true`. This prevents one
    /// TLS 1.3 ticket from being used by concurrent handshakes, as recommended
    /// by [RFC 8446 Appendix C.4](https://datatracker.ietf.org/doc/html/rfc8446#appendix-C.4).
    fn pop(&self, key: &Key) -> Option<TlsSession>;
}

impl_into_shared!(
    /// Converts a session cache into a shared trait object.
    pub trait IntoTlsSessionCache => TlsSessionCache
);

/// A configurable per-key LRU session cache.
///
/// This type preserves the public cache policy used by earlier releases. The
/// client default instead uses a globally bounded two-ticket cache.
pub struct LruTlsSessionCache {
    inner: Mutex<LruState>,
    per_key_capacity: usize,
}

/// Per-key session LRUs protected by the cache lock.
struct LruState {
    keys: HashMap<Key, LruCache<TlsSession, ()>>,
}

// ===== impl TlsSession =====

impl TlsSession {
    /// Returns the TLS session ID.
    #[inline]
    pub fn id(&self) -> &[u8] {
        self.inner.id()
    }

    /// Returns the establishment time in seconds since the Unix epoch.
    #[inline]
    pub fn time(&self) -> u64 {
        self.inner.time()
    }

    /// Returns the session lifetime in seconds.
    #[inline]
    pub fn timeout(&self) -> u32 {
        self.inner.timeout()
    }

    /// Returns whether BoringSSL requires this session to be consumed on lookup.
    #[inline]
    pub fn should_be_single_use(&self) -> bool {
        self.inner.should_be_single_use()
    }

    /// Returns the negotiated TLS version.
    #[inline]
    pub fn protocol_version(&self) -> TlsVersion {
        TlsVersion(self.inner.protocol_version())
    }
}

impl PartialEq for TlsSession {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        // Preserve the session-ID equality used by existing session caches.
        // The full originating key is checked before resumption.
        self.inner.id() == other.inner.id()
    }
}

impl Eq for TlsSession {}

impl Hash for TlsSession {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.id().hash(state);
    }
}

impl Borrow<[u8]> for TlsSession {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.inner.id()
    }
}

// ===== impl LruTlsSessionCache =====

impl LruTlsSessionCache {
    /// Creates a cache retaining up to `per_key_capacity` sessions for each key.
    pub fn new(per_key_capacity: usize) -> Self {
        Self {
            inner: Mutex::new(LruState {
                keys: HashMap::new(),
            }),
            per_key_capacity,
        }
    }
}

impl TlsSessionCache for LruTlsSessionCache {
    fn put(&self, key: Key, session: TlsSession) {
        if self.per_key_capacity == 0 {
            return;
        }

        let evicted = {
            let mut state = self.inner.lock();
            let sessions = state.keys.entry(key).or_insert_with(|| {
                NonZeroUsize::new(self.per_key_capacity)
                    .map_or_else(LruCache::unbounded, LruCache::new)
            });
            sessions.push(session, ()).map(|(session, ())| session)
        };
        drop(evicted);
    }

    fn pop(&self, key: &Key) -> Option<TlsSession> {
        let (session, retired_session, retired_entry) = {
            let mut state = self.inner.lock();
            let sessions = state.keys.get_mut(key)?;
            let session = sessions.peek_mru()?.0.clone();
            let retired_session = session
                .should_be_single_use()
                .then(|| sessions.pop_entry(&session))
                .flatten();
            let empty = sessions.is_empty();
            let retired_entry = empty.then(|| state.keys.remove_entry(key)).flatten();
            (session, retired_session, retired_entry)
        };

        drop(retired_session);
        drop(retired_entry);
        Some(session)
    }
}
