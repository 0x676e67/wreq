//! TLS session storage for ticket-based connection resumption.
//!
//! The built-in store is bounded and in-memory. Applications can provide a
//! session store when they need a different ticket retention policy.

pub(super) mod entry;
pub(super) mod store;

use std::{
    any::{Any, TypeId},
    borrow::Borrow,
    hash::{BuildHasher, Hash, Hasher},
    net::IpAddr,
    num::NonZeroUsize,
    sync::{Arc, LazyLock},
};

use btls::ssl::{ClientSession, SslSession, SslSessionRef};
use http::Uri;
use lru::{DefaultHasher, LruCache};
pub(crate) use store::Tickets;

use super::{KeyIdentity, TlsVersion};
use crate::{config::ConnectConfig, conn::CommonIdentity, sync::Mutex};

const SESSION_ENTRY_CAPACITY: usize = 1024;
const SESSION_ID_CONTEXT_LENGTH: usize = 32;
static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);

/// Type-erased [`KeyIdentity`] used by [`SessionKey`] to store stream or QUIC options.
type ErasedIdentity = dyn for<'h> KeyIdentity<dyn Any, dyn Hasher + 'h>;

/// An opaque key identifying a TLS session store entry.
///
/// Keys are scoped to the client, transport, and TLS identity so a client only resumes
/// tickets stored under the same key, even when multiple clients share a store. TLS 1.2
/// RSA sessions also include the remote socket's IP (the proxy's IP for tunneled connections).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Key {
    session: SessionKey,
    remote_ip: Option<IpAddr>,
    session_id_context: [u8; SESSION_ID_CONTEXT_LENGTH],
}

/// Connection identity for session resumption: transport, origin, TLS peer, and any
/// request-level options that differ from the client's defaults.
///
/// Differences in ALPN, ALPS, or HTTP framing share tickets; transport, proxy, socket
/// bindings, and pool group partition the cache.
#[derive(Clone)]
struct SessionKey {
    origin: Uri,
    route: Uri,
    common: CommonIdentity,
    namespace: &'static TypeId,
    options: Option<Arc<ErasedIdentity>>,
    hash: u64,
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
    /// Restricts a copy of this session key to the remote socket's IP.
    pub(super) fn with_remote_ip(&self, remote_ip: IpAddr) -> Self {
        Self {
            remote_ip: Some(remote_ip),
            ..self.clone()
        }
    }
}

// ===== impl SessionKey =====

impl SessionKey {
    /// Derives the session identity for a connection, where `route` is the authenticated
    /// TLS peer (the origin itself or a proxy hop).
    #[must_use]
    fn new<O: for<'h> KeyIdentity<dyn Any, dyn Hasher + 'h>, T: 'static>(
        origin: &Uri,
        connect_config: &ConnectConfig,
        route: &Uri,
    ) -> Self {
        let common = CommonIdentity::new(connect_config);
        let namespace = const { &TypeId::of::<T>() };
        let options = connect_config
            .override_if_different::<O>(|options, base| options.same(base))
            .cloned()
            .map(|options| options as Arc<ErasedIdentity>);
        let origin = origin.clone();
        let route = route.clone();
        let hash = HASHER.hash_one((&origin, &route, &common, namespace, &options));
        Self {
            origin,
            route,
            common,
            namespace,
            options,
            hash,
        }
    }
}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.origin == other.origin
            && self.route == other.route
            && self.common == other.common
            && self.namespace == other.namespace
            && self.options == other.options
    }
}

impl Eq for SessionKey {}

impl Hash for SessionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

// ===== impl ErasedIdentity =====

impl PartialEq for ErasedIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.same(other)
    }
}

impl Eq for ErasedIdentity {}

impl Hash for ErasedIdentity {
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::{
        group::Group,
        http1::Http1Options,
        tls::{AlpnProtocol, AlpsProtocol, TlsOptions, TlsOptionsBuilder},
    };

    fn tls(options: TlsOptionsBuilder) -> ConnectConfig {
        let mut connect_config = ConnectConfig::default();
        connect_config.insert(options.pre_shared_key(true).build());
        connect_config
    }

    #[test]
    fn session_keys_ignore_negotiation_and_inherit_client_options() {
        let connect_config = tls(TlsOptions::builder());
        let origin = Uri::from_static("https://example.com/");
        let key = |overrides: ConnectConfig| {
            SessionKey::new::<TlsOptions, ClientSession>(
                &origin,
                &overrides.with_base(&connect_config),
                &origin,
            )
        };
        let inherited = ConnectConfig::default().with_base(&connect_config);
        let plain = key(ConnectConfig::default());

        // ALPN, ALPS, HTTP options and equal client options share tickets.
        let mut negotiation = tls(TlsOptions::builder()
            .alpn_protocols([AlpnProtocol::HTTP1])
            .alps_protocols([AlpsProtocol::HTTP1])
            .alps_use_new_codepoint(false));
        negotiation.insert(Http1Options::builder().max_headers(8).build());
        for connect_config in [negotiation, tls(TlsOptions::builder())] {
            assert!(plain == key(connect_config));
        }

        let mut grouped = ConnectConfig::default();
        grouped.insert(Group::new("tenant"));
        let mut proxied = ConnectConfig::default();
        proxied.insert(
            crate::Proxy::all("http://localhost:8080")
                .unwrap()
                .into_matcher(),
        );
        let others = [
            key(tls(
                TlsOptions::builder().max_tls_version(TlsVersion::TLS_1_2)
            )),
            key(tls(TlsOptions::builder().key_shares(Vec::new()))),
            key(grouped),
            key(proxied),
            SessionKey::new::<TlsOptions, ClientSession>(
                &origin,
                &inherited,
                &Uri::from_static("https://proxy:8443"),
            ),
            SessionKey::new::<TlsOptions, ()>(&origin, &inherited, &origin),
        ];
        for mut other in others {
            assert!(plain != other);
            other.hash = plain.hash;
            assert!(plain != other);
        }

        let mut connect_config = connect_config;
        connect_config.insert(Ipv4Addr::LOCALHOST);
        connect_config.insert(Ipv6Addr::LOCALHOST);
        let inherited = ConnectConfig::default().with_base(&connect_config);
        let mut partial = inherited.clone();
        partial.insert(Ipv4Addr::LOCALHOST);
        let mut changed = inherited.clone();
        changed.insert(Ipv4Addr::UNSPECIFIED);
        let key = |connect_config| {
            SessionKey::new::<TlsOptions, ClientSession>(&origin, connect_config, &origin)
        };
        let inherited_key = key(&inherited);
        assert!(inherited_key == key(&partial));
        assert!(inherited_key != key(&changed));
    }
}
