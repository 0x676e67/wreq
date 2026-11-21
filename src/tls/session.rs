//! TLS session storage for ticket-based connection resumption.
//!
//! The built-in store is bounded and in-memory. Applications can provide a
//! session store when they need a different ticket retention policy.

pub(super) mod entry;
pub(super) mod store;

use std::{
    any::{Any, TypeId},
    borrow::Borrow,
    hash::{Hash, Hasher},
    net::IpAddr,
    num::NonZeroUsize,
    sync::Arc,
};

use btls::ssl::{ClientSession, SslSession, SslSessionRef};
use http::Uri;
use lru::LruCache;
pub(crate) use store::Tickets;

use super::{KeyIdentity, TlsVersion};
use crate::{config::ConnectConfig, conn::Request, reuse, sync::Mutex};

const SESSION_ENTRY_CAPACITY: usize = 1024;
const SESSION_ID_CONTEXT_LENGTH: usize = 32;

/// Type-erased [`KeyIdentity`] storing stream or QUIC options that affect session reuse.
type ErasedOptions = dyn for<'h> KeyIdentity<dyn Any, dyn Hasher + 'h>;

/// An opaque key identifying a TLS session store entry.
///
/// Keys are scoped to the client, transport, and TLS identity so a client only resumes
/// tickets stored under the same key, even when multiple clients share a store. TLS 1.2
/// RSA sessions also include the remote socket's IP (the proxy's IP for tunneled connections).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Key {
    reuse: reuse::Key,
    remote_ip: Option<IpAddr>,
    session_id_context: [u8; SESSION_ID_CONTEXT_LENGTH],
}

/// A stored TLS session used for ticket-based resumption.
///
/// Carries its originating [`Key`] so sessions returned by custom stores can be validated
/// before being offered.
#[derive(Clone)]
pub struct TlsSession {
    ticket: Ticket,
    key: Key,
}

/// Underlying resumption state stored inside a [`TlsSession`].
///
/// Stream connections store a native BoringSSL [`ClientSession`], while QUIC stores
/// decoded metadata alongside an opaque serialized session payload.
#[derive(Clone)]
pub(crate) enum Ticket {
    /// Native BoringSSL session for TCP/Unix connections.
    Native(ClientSession),
    /// Decoded session metadata paired with a transport-specific resumption payload.
    #[allow(
        dead_code,
        reason = "Not every transport uses an opaque resumption payload"
    )]
    Opaque {
        session: SslSession,
        payload: Arc<dyn Any + Send + Sync>,
    },
}

/// Custom storage backend for TLS session tickets used in ticket-based resumption.
///
/// Installed via [`ClientBuilder::tls_session_store`](crate::ClientBuilder::tls_session_store)
/// to replace the built-in in-memory LRU store.
pub trait TlsSessionStore: Send + Sync {
    /// Stores a TLS session under the given key.
    ///
    /// Runs inside BoringSSL's new-session callback. Implementations should return quickly
    /// and must not rely on panics propagating; panics are caught before crossing FFI.
    fn put(&self, key: Key, session: TlsSession);

    /// Retrieves the newest TLS session for the given key.
    ///
    /// Implementations should remove the session when [`TlsSession::should_be_single_use`]
    /// returns `true`, preventing concurrent handshakes from reusing the same TLS 1.3 ticket
    /// ([RFC 8446 Appendix C.4](https://datatracker.ietf.org/doc/html/rfc8446#appendix-C.4)).
    ///
    /// Runs during handshake setup (each QUIC address attempt performs its own lookup).
    /// Implementations should return quickly; panics are caught and treated as a miss.
    fn pop(&self, key: &Key) -> Option<TlsSession>;
}

impl_into_shared!(
    /// Converts a session store into a shared trait object.
    pub trait IntoTlsSessionStore => TlsSessionStore
);

/// In-memory LRU session store.
///
/// Keeps up to `per_key_capacity` tickets for each of 1024 keys by default (configurable via
/// [`with_key_capacity`](Self::with_key_capacity)), evicting least recently used keys first.
/// Single-use tickets are removed on lookup; reusable tickets stay cached.
pub struct LruTlsSessionStore {
    inner: Mutex<LruCache<Key, LruCache<TlsSession, ()>>>,
    key_capacity: Option<NonZeroUsize>,
    per_key_capacity: Option<NonZeroUsize>,
}

// ===== impl Key =====

impl Key {
    /// Builds a key for the authenticated TLS peer and ticket type `T`.
    ///
    /// Differences in ALPN, ALPS, or HTTP framing do not split the ticket cache.
    #[must_use]
    fn new<O: for<'h> KeyIdentity<dyn Any, dyn Hasher + 'h>, T: 'static>(
        origin: &Uri,
        peer: &Uri,
        config: &ConnectConfig,
        session_id_context: [u8; SESSION_ID_CONTEXT_LENGTH],
    ) -> Self {
        let scope = Request::reuse_scope(config);
        let namespace = const { &TypeId::of::<T>() };
        let options = config
            .override_if_different::<O>(|options, base| options.same(base))
            .cloned()
            .map(|options| options as Arc<ErasedOptions>);
        Self {
            reuse: reuse::Key::new((origin.clone(), peer.clone(), scope, namespace, options)),
            remote_ip: None,
            session_id_context,
        }
    }

    /// Restricts a copy of this session key to the remote socket's IP.
    pub(super) fn with_remote_ip(&self, remote_ip: IpAddr) -> Self {
        Self {
            remote_ip: Some(remote_ip),
            ..self.clone()
        }
    }
}

// ===== impl ErasedOptions =====

impl PartialEq for ErasedOptions {
    fn eq(&self, other: &Self) -> bool {
        self.same(other)
    }
}

impl Eq for ErasedOptions {}

impl Hash for ErasedOptions {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_key(state);
    }
}

// ===== impl TlsSession =====

impl TlsSession {
    /// Returns the TLS session ID.
    #[inline]
    pub fn id(&self) -> &[u8] {
        self.ticket.session().id()
    }

    /// Returns the establishment time in seconds since the Unix epoch.
    #[inline]
    pub fn time(&self) -> u64 {
        self.ticket.session().time()
    }

    /// Returns the session lifetime in seconds.
    #[inline]
    pub fn timeout(&self) -> u32 {
        self.ticket.session().timeout()
    }

    /// Returns whether BoringSSL requires this session to be consumed on lookup.
    #[inline]
    pub fn should_be_single_use(&self) -> bool {
        self.ticket.session().should_be_single_use()
    }

    /// Returns the negotiated TLS version.
    #[inline]
    pub fn protocol_version(&self) -> TlsVersion {
        TlsVersion(self.ticket.session().protocol_version())
    }
}

impl PartialEq for TlsSession {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        // Entries compare session IDs; resumption separately checks the full originating key.
        self.id() == other.id()
    }
}

impl Eq for TlsSession {}

impl Hash for TlsSession {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}

impl Borrow<[u8]> for TlsSession {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.id()
    }
}

// ===== impl Ticket =====

impl Ticket {
    /// Returns the decoded session metadata (lifetime and single-use flag).
    fn session(&self) -> &SslSessionRef {
        match self {
            Ticket::Native(session) => session.session(),
            Ticket::Opaque { session, .. } => session,
        }
    }
}

// ===== impl LruTlsSessionStore =====

impl LruTlsSessionStore {
    /// Creates a store keeping up to `per_key_capacity` tickets per key.
    ///
    /// A capacity of `0` disables storage. Backing storage grows lazily as sessions arrive.
    pub fn new(per_key_capacity: usize) -> Self {
        Self {
            inner: Mutex::new(LruCache::sparse(NonZeroUsize::MIN)),
            key_capacity: None,
            per_key_capacity: NonZeroUsize::new(per_key_capacity),
        }
        .with_key_capacity(SESSION_ENTRY_CAPACITY)
    }

    /// Sets the maximum number of session keys to keep (default: 1024).
    ///
    /// A capacity of `0` disables storage.
    #[must_use]
    pub fn with_key_capacity(self, key_capacity: usize) -> Self {
        let key_capacity = NonZeroUsize::new(key_capacity);
        Self {
            inner: Mutex::new(LruCache::sparse(key_capacity.unwrap_or(NonZeroUsize::MIN))),
            key_capacity,
            ..self
        }
    }
}

impl TlsSessionStore for LruTlsSessionStore {
    fn put(&self, key: Key, session: TlsSession) {
        let (Some(_), Some(capacity)) = (self.key_capacity, self.per_key_capacity) else {
            return;
        };

        let mut keys = self.inner.lock();
        let (retired_session, evicted_entry) = match keys.get_mut(&key) {
            Some(sessions) => (sessions.push(session, ()), None),
            None => {
                let mut sessions = LruCache::sparse(capacity);
                sessions.push(session, ());
                (None, keys.push(key, sessions))
            }
        };
        drop(keys);
        drop(retired_session);
        drop(evicted_entry);
    }

    fn pop(&self, key: &Key) -> Option<TlsSession> {
        let mut keys = self.inner.lock();
        let sessions = keys.get_mut(key)?;
        let session = sessions.peek_mru()?.0;
        let session = if session.should_be_single_use() {
            sessions.pop_mru()?.0
        } else {
            session.clone()
        };
        let retired_entry = if sessions.is_empty() {
            keys.pop_entry(key)
        } else {
            None
        };
        drop(keys);
        drop(retired_entry);
        Some(session)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{reuse::Group, tls::TlsOptions};

    #[test]
    fn session_keys_keep_distinct_sessions_isolated() {
        let origin = Uri::from_static("https://example.com/");
        let mut config = ConnectConfig::default();
        config.insert(TlsOptions::builder().pre_shared_key(true).build());
        let mut grouped_config = config.clone();
        grouped_config.insert(Group::new("isolated"));
        let mut overrides = ConnectConfig::default();
        overrides.insert(
            TlsOptions::builder()
                .pre_shared_key(true)
                .key_shares(Vec::new())
                .build(),
        );

        let context = [0; SESSION_ID_CONTEXT_LENGTH];
        let key = |config: &ConnectConfig, peer: &Uri| {
            Key::new::<TlsOptions, ClientSession>(&origin, peer, config, context)
        };
        let baseline = key(&config, &origin);
        let cases = [
            (
                "TLS peer",
                key(&config, &Uri::from_static("https://proxy:8443")),
            ),
            (
                "ticket type",
                Key::new::<TlsOptions, ()>(&origin, &origin, &config, context),
            ),
            ("TLS options", key(&overrides, &origin)),
            ("reuse scope", key(&grouped_config, &origin)),
        ];
        for (field, other) in cases {
            assert!(baseline != other, "key must distinguish {field}");
        }

        config.insert(Ipv4Addr::LOCALHOST);
        let mut overrides = ConnectConfig::default().with_base(&config);
        let inherited = key(&overrides, &origin);
        overrides.insert(Ipv4Addr::LOCALHOST);
        assert!(inherited == key(&overrides, &origin));
        overrides.insert(Ipv4Addr::UNSPECIFIED);
        assert!(inherited != key(&overrides, &origin));
    }
}
