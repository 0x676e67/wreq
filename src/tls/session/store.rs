//! Per-client TLS session ticket storage.
//!
//! The built-in store keeps up to two tickets per key. Custom store callbacks and native
//! session destructors always run outside the internal lock.

use std::{
    any::Any,
    hash::Hasher,
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use btls::{error::ErrorStack, rand::rand_bytes};
use http::Uri;
use lru::LruCache;

use super::{
    Key, SESSION_ENTRY_CAPACITY, SESSION_ID_CONTEXT_LENGTH, SessionKey, Ticket, TlsSession,
    TlsSessionStore,
    entry::{self, SessionEntry},
};
use crate::{config::ConnectConfig, sync::Mutex, tls::KeyIdentity};

const EXPIRATION_CHECK_INTERVAL: usize = 256;

/// Manages session tickets for a client, backed by either the built-in LRU or a custom store.
///
/// All resuming contexts on a client share the same BoringSSL session ID context, so
/// compatible tickets remain valid across per-request contexts while tickets from other
/// clients are rejected.
pub(crate) struct Tickets {
    state: Mutex<State>,
    store: Option<Arc<dyn TlsSessionStore>>,
    session_id_context: OnceLock<[u8; SESSION_ID_CONTEXT_LENGTH]>,
}

/// Lazily allocated built-in LRU cache and periodic expiration counter.
///
/// Protected by [`Tickets::state`]; the LRU map is allocated on first insertion and swept
/// every `EXPIRATION_CHECK_INTERVAL` lookups.
#[derive(Default)]
struct State {
    sessions: Option<LruCache<Key, SessionEntry>>,
    lookups_since_sweep: usize,
}

// ===== impl Tickets =====

impl Tickets {
    /// Creates a ticket store backed by `store`, or a lazily allocated built-in LRU if `None`.
    pub(crate) fn new(store: Option<Arc<dyn TlsSessionStore>>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            store,
            session_id_context: OnceLock::new(),
        }
    }

    /// Returns this client's BoringSSL session ID context, generating it on first use.
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

    /// Builds a session key scoped to this client and ticket type `T`.
    pub(crate) fn key<O: for<'h> KeyIdentity<dyn Any, dyn Hasher + 'h>, T: 'static>(
        &self,
        origin: &Uri,
        peer: &Uri,
        connect_config: &ConnectConfig,
    ) -> Result<Key, ErrorStack> {
        let session_id_context = self.session_id_context()?;
        Ok(Key {
            session: SessionKey::new::<O, T>(origin, connect_config, peer),
            remote_ip: None,
            session_id_context,
        })
    }

    /// Stores a ticket under `key`.
    pub(crate) fn put(&self, key: Key, ticket: Ticket) {
        if let Some(tls_session_store) = &self.store {
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

    /// Pops a non-expired ticket matching `key`, discarding mismatches or expired entries.
    pub(crate) fn pop(&self, key: &Key) -> Option<Ticket> {
        if let Some(tls_session_store) = &self.store {
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
    /// Returns `true` every 256 lookups to trigger a full expiration sweep.
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

/// Runs a custom store callback, catching panics so they never unwind across FFI.
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
        let tickets = Tickets::new(None);
        assert!(tickets.state.lock().sessions.is_none());
        assert!(tickets.session_id_context.get().is_none());

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
