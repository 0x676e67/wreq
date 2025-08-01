use std::{
    borrow::Borrow,
    collections::hash_map::Entry,
    hash::{Hash, Hasher},
};

use boring2::ssl::{SslSession, SslSessionRef, SslVersion};
use schnellru::ByLength;

use crate::hash::{HASHER, HashMap, LruMap};

/// A typed key for indexing TLS sessions in the cache.
///
/// This wrapper provides type safety and allows different key types
/// (e.g., hostname, connection parameters) to be used for session lookup.
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct SessionKey<T>(pub T);

/// A hashable wrapper around `SslSession` for use in hash-based collections.
///
/// Uses the session ID for hashing and equality, enabling efficient
/// storage and lookup in HashMap/HashSet while maintaining session semantics.
#[derive(Clone)]
struct HashSession(SslSession);

impl PartialEq for HashSession {
    fn eq(&self, other: &HashSession) -> bool {
        self.0.id() == other.0.id()
    }
}

impl Eq for HashSession {}

impl Hash for HashSession {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.0.id().hash(state);
    }
}

impl Borrow<[u8]> for HashSession {
    fn borrow(&self) -> &[u8] {
        self.0.id()
    }
}

/// A two-level cache for TLS sessions organized by host keys with LRU eviction.
///
/// Maintains both forward (key → sessions) and reverse (session → key) lookups
/// for efficient session storage, retrieval, and cleanup operations.
pub struct SessionCache<T> {
    reverse: HashMap<HashSession, SessionKey<T>>,
    per_host_sessions: HashMap<SessionKey<T>, LruMap<HashSession, ()>>,
    per_host_session_capacity: usize,
}

impl<T> SessionCache<T>
where
    T: Hash + Eq + Clone,
{
    pub fn with_capacity(per_host_session_capacity: usize) -> SessionCache<T> {
        SessionCache {
            per_host_sessions: HashMap::with_hasher(HASHER),
            reverse: HashMap::with_hasher(HASHER),
            per_host_session_capacity,
        }
    }

    pub fn insert(&mut self, key: SessionKey<T>, session: SslSession) {
        let per_host_sessions = self
            .per_host_sessions
            .entry(key.clone())
            .or_insert_with(|| {
                LruMap::with_hasher(ByLength::new(self.per_host_session_capacity as _), HASHER)
            });

        // Enforce per-key capacity limit by evicting the least recently used session
        if per_host_sessions.len() >= self.per_host_session_capacity {
            if let Some((evicted_session, _)) = per_host_sessions.pop_oldest() {
                // Remove from reverse lookup to maintain consistency
                self.reverse.remove(&evicted_session);
            }
        }

        let session = HashSession(session);
        per_host_sessions.insert(session.clone(), ());
        self.reverse.insert(session, key);
    }

    pub fn get(&mut self, key: &SessionKey<T>) -> Option<SslSession> {
        let session = {
            let per_host_sessions = self.per_host_sessions.get_mut(key)?;
            per_host_sessions.peek_oldest()?.0.clone().0
        };

        // https://tools.ietf.org/html/rfc8446#appendix-C.4
        // OpenSSL will remove the session from its cache after the handshake completes anyway, but
        // this ensures that concurrent handshakes don't end up with the same session.
        if session.protocol_version() == SslVersion::TLS1_3 {
            self.remove(&session);
        }

        Some(session)
    }

    fn remove(&mut self, session: &SslSessionRef) {
        let key = match self.reverse.remove(session.id()) {
            Some(key) => key,
            None => return,
        };

        if let Entry::Occupied(mut per_host_sessions) = self.per_host_sessions.entry(key) {
            per_host_sessions
                .get_mut()
                .remove(&HashSession(session.to_owned()));
            if per_host_sessions.get().is_empty() {
                per_host_sessions.remove();
            }
        }
    }
}
