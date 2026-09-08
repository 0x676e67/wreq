//! Bounded TLS session-ticket storage for one client.
//!
//! The built-in store keeps two tickets per full session key. Caller store
//! callbacks and native destruction remain outside its lock.

use std::{
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use btls::{error::ErrorStack, rand::rand_bytes, ssl::SslSession};
use lru::LruCache;

use super::{
    Key, SESSION_ID_CONTEXT_LENGTH, TlsSession, TlsSessionStore,
    entry::{self, SessionEntry},
};
use crate::sync::Mutex;

const SESSION_ENTRY_CAPACITY: usize = 8;
const EXPIRATION_CHECK_INTERVAL: usize = 256;
/// Stores session tickets for one client and an optional caller-provided store.
///
/// The session ID context is copied into every per-request `SSL_CTX`. BoringSSL
/// then accepts tickets across those contexts but rejects tickets from another client.
pub(crate) struct SessionStore {
    state: Mutex<State>,
    tls_session_store: Option<Arc<dyn TlsSessionStore>>,
    session_id_context: OnceLock<[u8; SESSION_ID_CONTEXT_LENGTH]>,
}

/// Lazily allocated ticket storage and its expiration counter.
/// Allocated entries remain bounded by the client store's key capacity.
/// The store lock serializes insertion, consumption, and expiration bookkeeping.
#[derive(Default)]
struct State {
    sessions: Option<LruCache<Key, SessionEntry>>,
    lookups_since_sweep: usize,
}

// ===== impl SessionStore =====

impl SessionStore {
    /// Creates an empty store with an optional caller-provided store.
    /// The built-in LRU is allocated on first insertion.
    pub(crate) fn new(tls_session_store: Option<Arc<dyn TlsSessionStore>>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            tls_session_store,
            session_id_context: OnceLock::new(),
        }
    }

    /// Returns the stable BoringSSL session ID context for this store.
    /// It is generated only when a connector first enables session resumption.
    pub(in crate::tls) fn session_id_context(
        &self,
    ) -> Result<[u8; SESSION_ID_CONTEXT_LENGTH], ErrorStack> {
        if let Some(context) = self.session_id_context.get() {
            return Ok(*context);
        }

        let mut context = [0; SESSION_ID_CONTEXT_LENGTH];
        rand_bytes(&mut context)?;
        Ok(*self.session_id_context.get_or_init(|| context))
    }

    /// Stores a session emitted by BoringSSL's new-session callback.
    pub(crate) fn insert(&self, key: Key, inner: SslSession) {
        if let Some(store) = &self.tls_session_store {
            let session = TlsSession {
                inner,
                key: key.clone(),
            };
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| store.put(key, session))) {
                // Dropping an arbitrary panic payload may itself panic. This callback crosses an
                // FFI boundary, so leak this exceptional value instead of unwinding into BoringSSL.
                std::mem::forget(payload);
            }
            return;
        }

        let mut pending = Some(inner);
        let mut retired_ticket = None;
        let mut evicted_entry = None;

        {
            let mut state = self.state.lock();
            let sessions = state.sessions.get_or_insert_with(entries);
            if let Some(entry) = sessions.get_mut(&key) {
                if let Some(session) = pending.take() {
                    retired_ticket = entry.push(session);
                }
            } else if let Some(session) = pending.take() {
                evicted_entry = sessions.push(key, SessionEntry::new(session));
            }
        }

        drop(pending);
        drop(retired_ticket);
        drop(evicted_entry);
    }

    /// Retrieves a session only for its complete connection identity.
    pub(crate) fn pop(&self, key: &Key) -> Option<SslSession> {
        if let Some(store) = &self.tls_session_store {
            let session = store.pop(key)?;
            return (session.key == *key && !entry::is_expired(&session.inner, unix_time()))
                .then_some(session.inner);
        }

        let mut retired_entries = Vec::new();
        let mut retired_keys = Vec::new();
        let mut retired_tickets = Vec::new();
        let mut session = None;
        let now = unix_time();

        {
            let mut state = self.state.lock();
            let sweep = state.note_lookup();
            let sessions = state.sessions.as_mut()?;
            if sweep {
                sweep_expired(
                    sessions,
                    now,
                    &mut retired_entries,
                    &mut retired_keys,
                    &mut retired_tickets,
                );
            }

            let mut remove_entry = false;
            if let Some(entry) = sessions.get_mut(key) {
                // Match Chromium's Lookup: consume first, then expire the remaining slots.
                session = entry.pop();
                retired_tickets.extend(entry.expire(now).into_iter().flatten());
                remove_entry = entry.is_empty();
            }

            if remove_entry && let Some(entry) = sessions.pop_entry(key) {
                retired_entries.push(entry);
            }
        }

        drop(retired_tickets);
        drop(retired_keys);
        drop(retired_entries);
        session.filter(|session| !entry::is_expired(session, now))
    }
}

// ===== impl State =====

impl State {
    /// Requests a full expiration sweep every 256 built-in lookups.
    fn note_lookup(&mut self) -> bool {
        self.lookups_since_sweep = self.lookups_since_sweep.saturating_add(1);
        if self.lookups_since_sweep < EXPIRATION_CHECK_INTERVAL {
            return false;
        }

        self.lookups_since_sweep = 0;
        true
    }
}

fn sweep_expired(
    sessions: &mut LruCache<Key, SessionEntry>,
    now: Option<u64>,
    retired_entries: &mut Vec<(Key, SessionEntry)>,
    retired_keys: &mut Vec<Key>,
    retired_tickets: &mut Vec<SslSession>,
) {
    let mut empty_keys = Vec::new();
    for (key, entry) in sessions.iter_mut() {
        retired_tickets.extend(entry.expire(now).into_iter().flatten());
        if entry.is_empty() {
            empty_keys.push(key.clone());
        }
    }

    for key in empty_keys {
        if let Some(entry) = sessions.pop_entry(&key) {
            retired_entries.push(entry);
        }
        retired_keys.push(key);
    }
}

fn entries() -> LruCache<Key, SessionEntry> {
    let capacity = NonZeroUsize::new(SESSION_ENTRY_CAPACITY).unwrap_or(NonZeroUsize::MIN);
    LruCache::new(capacity)
}

fn unix_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_is_lazy_bounded_and_sweeps_periodically() {
        let store = SessionStore::new(None);
        assert!(store.state.lock().sessions.is_none());
        assert!(store.session_id_context.get().is_none());

        let sessions = entries();
        assert_eq!(sessions.cap().get(), SESSION_ENTRY_CAPACITY);

        let mut state = State::default();
        for _ in 1..EXPIRATION_CHECK_INTERVAL {
            assert!(!state.note_lookup());
        }
        assert!(state.note_lookup());
        assert!(!state.note_lookup());
    }
}
