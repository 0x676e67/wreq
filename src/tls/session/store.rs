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

#[cfg(feature = "http3")]
use btls::ssl::SslSession;
use btls::{
    error::ErrorStack,
    rand::rand_bytes,
    ssl::{ClientSession, SslCipherRef},
};
use lru::LruCache;
#[cfg(feature = "http3")]
use quic::crypto::btls::Zeroizing;

use super::{
    Key, SESSION_ENTRY_CAPACITY, SESSION_ID_CONTEXT_LENGTH, SessionTarget, Ticket, TlsSession,
    TlsSessionStore,
    entry::{self, SessionEntry},
};
use crate::sync::Mutex;

const EXPIRATION_CHECK_INTERVAL: usize = 256;

/// Stores session tickets for one client and an optional caller-provided store.
///
/// Contexts with resumption enabled share this client's session ID context. Compatible tickets
/// remain usable when a request context is rebuilt; tickets from other clients are rejected.
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

    /// Stores a TCP session emitted by BoringSSL's new-session callback.
    pub(crate) fn insert_stream(&self, target: &SessionTarget, session: ClientSession) {
        let kx = session
            .session()
            .cipher()
            .and_then(SslCipherRef::cipher_kx_nid);
        if let Some(key) = target.key_for(kx) {
            self.put(key, Ticket::Stream(session));
        }
    }

    /// Retrieves a TCP session for the connection, then one bound to its remote IP.
    pub(crate) fn pop_stream(&self, target: &SessionTarget) -> Option<ClientSession> {
        let stream = |ticket| match ticket {
            Ticket::Stream(session) => Some(session),
            #[cfg(feature = "http3")]
            Ticket::Quic { .. } => None,
        };
        self.pop(&target.key)
            .and_then(stream)
            .or_else(|| self.pop(&target.rsa_key()?).and_then(stream))
    }

    /// Stores a QUIC session with the encoded state the QUIC stack resumes from and the
    /// expiry of its verified certificate path.
    #[cfg(feature = "http3")]
    pub(crate) fn insert_quic(
        &self,
        key: Key,
        session: SslSession,
        state: Zeroizing<Vec<u8>>,
        not_after: Option<i64>,
    ) {
        let ticket = Ticket::Quic {
            session,
            state: Arc::new(state),
            not_after,
        };
        self.put(key, ticket);
    }

    /// Takes the encoded state of a QUIC session for `key`.
    ///
    /// With `verify_peer`, a session whose verified certificate path has expired is dropped:
    /// resumption re-verifies the path and would fail the handshake.
    #[cfg(feature = "http3")]
    pub(crate) fn pop_quic(&self, key: &Key, verify_peer: bool) -> Option<Zeroizing<Vec<u8>>> {
        let Ticket::Quic {
            state, not_after, ..
        } = self.pop(key)?
        else {
            return None;
        };
        let now = unix_time().and_then(|now| i64::try_from(now).ok());
        let expired = matches!((not_after, now), (Some(not_after), Some(now)) if now >= not_after);
        (!(verify_peer && expired)).then(|| Arc::unwrap_or_clone(state))
    }

    fn put(&self, key: Key, ticket: Ticket) {
        if let Some(tls_session_store) = &self.tls_session_store {
            let session = TlsSession {
                ticket,
                key: key.clone(),
            };
            guarded(|| tls_session_store.put(key, session));
            return;
        }

        let mut state = self.state.lock();
        let sessions = state.sessions.get_or_insert_with(entries);
        let (retired_ticket, evicted_entry) = match sessions.get_mut(&key) {
            Some(entry) => (entry.push(ticket), None),
            None => (None, sessions.push(key, SessionEntry::new(ticket))),
        };
        drop(state);
        drop(retired_ticket);
        drop(evicted_entry);
    }

    /// Takes a ticket only for its complete connection identity; results with another key or
    /// an expired lifetime are dropped.
    fn pop(&self, key: &Key) -> Option<Ticket> {
        if let Some(tls_session_store) = &self.tls_session_store {
            let session = guarded(|| tls_session_store.pop(key)).flatten()?;
            return (session.key == *key
                && !entry::is_expired(session.ticket.session(), unix_time()))
            .then_some(session.ticket);
        }

        let mut retired_entries = Vec::new();
        let mut retired_keys = Vec::new();
        let mut retired_tickets = Vec::new();
        let now = unix_time();

        let ticket = {
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

            let entry = sessions.get_mut(key)?;
            // Consume the ticket first, then expire the remaining slots.
            let ticket = entry.pop();
            retired_tickets.extend(entry.expire(now).into_iter().flatten());

            if entry.is_empty()
                && let Some(entry) = sessions.pop_entry(key)
            {
                retired_entries.push(entry);
            }
            ticket
        };

        drop(retired_tickets);
        drop(retired_keys);
        drop(retired_entries);
        ticket.filter(|ticket| !entry::is_expired(ticket.session(), now))
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
    retired_tickets: &mut Vec<Ticket>,
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

/// Runs a caller store callback; a panic counts as a miss and never unwinds further.
fn guarded<T>(callback: impl FnOnce() -> T) -> Option<T> {
    match catch_unwind(AssertUnwindSafe(callback)) {
        Ok(value) => Some(value),
        Err(payload) => {
            // Dropping an arbitrary panic payload may itself panic. Store callbacks may run
            // inside BoringSSL callbacks, so leak this exceptional value instead.
            std::mem::forget(payload);
            None
        }
    }
}

fn entries() -> LruCache<Key, SessionEntry> {
    let capacity = NonZeroUsize::new(SESSION_ENTRY_CAPACITY).unwrap_or(NonZeroUsize::MIN);
    LruCache::sparse(capacity)
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
