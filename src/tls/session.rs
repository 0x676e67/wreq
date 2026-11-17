//! TLS session storage for ticket-based connection resumption.
//!
//! The built-in store is bounded and in-memory. Applications can provide a
//! session store when they need a different ticket retention policy.

pub(super) mod entry;
pub(super) mod store;

use std::{
    borrow::Borrow,
    hash::{BuildHasher, Hash, Hasher},
    net::IpAddr,
    num::NonZeroUsize,
    sync::Arc,
};

use btls::{
    nid::Nid,
    ssl::{ClientSession, SslSessionRef},
};
use http::Uri;
use lru::LruCache;
pub(crate) use store::Tickets;
#[cfg(feature = "http3")]
use {btls::ssl::SslSession, quic::crypto::btls::Zeroizing};

use crate::{
    config::connect::{ConnectConfig, HASHER, KeyScope},
    sync::Mutex,
    tls::TlsVersion,
};

const SESSION_ID_CONTEXT_LENGTH: usize = 32;
// Bounds the session keys kept by the built-in and default LRU stores.
const SESSION_ENTRY_CAPACITY: usize = 1024;

/// An opaque key identifying a TLS session store entry.
///
/// It contains the client session scope and the connection's TLS identity. This
/// prevents a store shared by multiple clients from returning a foreign ticket.
/// Sessions using TLS 1.2 RSA key exchange also carry the remote socket's IP address, which is
/// the proxy's for tunneled connections.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Key {
    session: SessionKey,
    remote_ip: Option<IpAddr>,
    session_id_context: [u8; SESSION_ID_CONTEXT_LENGTH],
}

/// Session identity for a TLS connection and its optional remote IP.
/// TCP handshakes retain it in `Ssl` ex data; QUIC uses its address-independent key.
///
/// A session using RSA key exchange is cached under the remote IP as well, and is not cached
/// when the IP is unknown.
pub(crate) struct SessionTarget {
    key: Key,
    remote_ip: Option<IpAddr>,
}

/// TLS identity of one connection: transport, origin, TLS peer, and the request
/// configuration that differs from the client's.
///
/// Connections with different ALPN, ALPS or HTTP framing options can share tickets.
/// The transport, proxy, socket bindings and group partition the session cache.
#[derive(Clone)]
struct SessionKey {
    origin: Uri,
    route: Uri,
    quic: bool,
    overrides: ConnectConfig,
    hash: u64,
}

/// A TLS session that can be stored and retrieved from a session store.
///
/// The originating key is retained so sessions returned by configured stores can
/// be validated before resumption.
#[derive(Clone)]
pub struct TlsSession {
    ticket: Ticket,
    key: Key,
}

/// Resumption state of a stored session.
#[derive(Clone)]
pub(super) enum Ticket {
    /// Checked by btls against each TCP connection before it is offered.
    Stream(ClientSession),
    /// A QUIC session, kept decoded for its metadata.
    #[cfg(feature = "http3")]
    Quic {
        session: SslSession,
        /// Encoded state the QUIC stack resumes from, with the server's transport parameters.
        state: Arc<Zeroizing<Vec<u8>>>,
        /// Earliest expiry on the verified certificate path, as POSIX time.
        not_after: Option<i64>,
    },
}

/// Stores sessions used for ticket-based TLS resumption.
pub trait TlsSessionStore: Send + Sync {
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
    /// Called during handshake setup when resumption is enabled, once for each QUIC connection
    /// attempt. Return quickly; a panic counts as a miss.
    fn pop(&self, key: &Key) -> Option<TlsSession>;
}

impl_into_shared!(
    /// Converts a session store into a shared trait object.
    pub trait IntoTlsSessionStore => TlsSessionStore
);

/// Stores up to the configured number of tickets for each session key, keeping 1024 keys by
/// default (see [`with_key_capacity`](Self::with_key_capacity)). The least recently used key is
/// evicted first. Single-use tickets are consumed on lookup, while reusable tickets remain stored.
pub struct LruTlsSessionStore {
    inner: Mutex<LruCache<Key, LruCache<TlsSession, ()>>>,
    key_capacity: Option<NonZeroUsize>,
    per_key_capacity: Option<NonZeroUsize>,
}

// ===== impl SessionKey =====

impl SessionKey {
    /// Derives the TLS identity of a connection request (`quic` vs stream), authenticating
    /// `route`: the origin itself, or the proxy hop that carries it.
    #[must_use]
    fn new(
        origin: &Uri,
        request_config: &ConnectConfig,
        client_config: &ConnectConfig,
        route: &Uri,
        quic: bool,
    ) -> Self {
        let overrides = request_config.for_session(client_config, quic);
        let origin = origin.clone();
        let route = route.clone();
        let mut state = HASHER.build_hasher();
        origin.hash(&mut state);
        route.hash(&mut state);
        quic.hash(&mut state);
        overrides.hash_scope(KeyScope::Session, &mut state);
        Self {
            origin,
            route,
            quic,
            overrides,
            hash: state.finish(),
        }
    }
}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.quic == other.quic
            && self.origin == other.origin
            && self.route == other.route
            && self.overrides.eq_scope(&other.overrides, KeyScope::Session)
    }
}

impl Eq for SessionKey {}

impl Hash for SessionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

// ===== impl SessionTarget =====

impl SessionTarget {
    /// Identifies a connection for `origin` that authenticates `route` at `remote_ip`, within a
    /// client's session scope.
    #[must_use]
    pub(crate) fn new(
        origin: &Uri,
        request_config: &ConnectConfig,
        client_config: &ConnectConfig,
        route: &Uri,
        quic: bool,
        remote_ip: Option<IpAddr>,
        session_id_context: [u8; SESSION_ID_CONTEXT_LENGTH],
    ) -> Self {
        Self {
            key: Key {
                session: SessionKey::new(origin, request_config, client_config, route, quic),
                remote_ip: None,
                session_id_context,
            },
            remote_ip,
        }
    }

    /// Returns the key shared by every remote address.
    #[cfg(feature = "http3")]
    pub(crate) fn into_key(self) -> Key {
        self.key
    }

    /// Returns the key that also binds the remote IP, if it is known.
    fn rsa_key(&self) -> Option<Key> {
        self.remote_ip.map(|ip| Key {
            remote_ip: Some(ip),
            ..self.key.clone()
        })
    }

    /// Returns the store key for a session using key exchange `kx`, or `None` when the session
    /// must not be cached.
    fn key_for(&self, kx: Option<Nid>) -> Option<Key> {
        if kx == Some(Nid::KX_RSA) {
            self.rsa_key()
        } else {
            Some(self.key.clone())
        }
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
    /// Returns the decoded session, for its lifetime and single-use policy.
    fn session(&self) -> &SslSessionRef {
        match self {
            Ticket::Stream(session) => session.session(),
            #[cfg(feature = "http3")]
            Ticket::Quic { session, .. } => session,
        }
    }
}

// ===== impl LruTlsSessionStore =====

impl LruTlsSessionStore {
    /// Creates a store retaining up to `per_key_capacity` sessions for each key.
    /// A zero capacity disables storage. Storage grows as sessions arrive.
    pub fn new(per_key_capacity: usize) -> Self {
        Self {
            inner: Mutex::new(LruCache::sparse(NonZeroUsize::MIN)),
            key_capacity: None,
            per_key_capacity: NonZeroUsize::new(per_key_capacity),
        }
        .with_key_capacity(SESSION_ENTRY_CAPACITY)
    }

    /// Sets how many session keys are kept, 1024 by default.
    /// A zero capacity disables storage.
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
        ext::UriExt,
        group::Group,
        http1::Http1Options,
        protocol::Protocol,
        tls::{AlpnProtocol, AlpsProtocol, TlsOptions, TlsOptionsBuilder},
    };

    fn request(
        protocol: Option<Protocol>,
        config: ConnectConfig,
        client_config: &ConnectConfig,
    ) -> (Uri, ConnectConfig) {
        let uri = Uri::from_static("https://example.com/a");
        let protocol = protocol.unwrap_or(Protocol::Auto);
        (
            uri.origin().unwrap(),
            config.for_protocol(protocol, client_config),
        )
    }

    fn tls(options: TlsOptionsBuilder) -> ConnectConfig {
        let mut config = ConnectConfig::default();
        config.insert(options.pre_shared_key(true).build());
        config
    }

    #[test]
    fn rsa_key_exchange_sessions_are_keyed_by_remote_ip() {
        let config = ConnectConfig::default();
        let (origin, body) = request(None, ConnectConfig::default(), &config);
        let context = [1; SESSION_ID_CONTEXT_LENGTH];
        let target = |ip| SessionTarget::new(&origin, &body, &config, &origin, false, ip, context);
        let known = target(Some(IpAddr::from([192, 0, 2, 1])));

        let rsa = known.key_for(Some(Nid::KX_RSA)).unwrap();
        assert!(rsa != known.key);
        for kx in [Some(Nid::KX_ECDHE), Some(Nid::KX_ANY), None] {
            assert!(known.key_for(kx).is_some_and(|key| key == known.key));
        }
        assert!(target(None).key_for(Some(Nid::KX_RSA)).is_none());
    }

    #[test]
    fn session_keys_ignore_negotiation_and_inherit_client_options() {
        let client_config = tls(TlsOptions::builder());
        let key = |protocol, request_config: ConnectConfig| {
            let (origin, body) = request(protocol, request_config, &client_config);
            SessionKey::new(&origin, &body, &client_config, &origin, false)
        };
        let plain = key(None, ConnectConfig::default());

        // ALPN, ALPS, HTTP options and equal client options share tickets.
        let mut negotiation = tls(TlsOptions::builder()
            .alpn_protocols([AlpnProtocol::HTTP1])
            .alps_protocols([AlpsProtocol::HTTP1])
            .alps_use_new_codepoint(false));
        negotiation.insert(Http1Options::builder().max_headers(8).build());
        for request_config in [negotiation, tls(TlsOptions::builder())] {
            assert!(plain == key(Some(Protocol::Http1), request_config));
        }

        let mut grouped = ConnectConfig::default();
        grouped.insert(Group::new("tenant"));
        let mut proxied = ConnectConfig::default();
        proxied.insert(
            crate::Proxy::all("http://localhost:8080")
                .unwrap()
                .into_matcher(),
        );
        let (origin_uri, origin_body) = request(None, ConnectConfig::default(), &client_config);
        let others = [
            key(
                None,
                tls(TlsOptions::builder().max_tls_version(TlsVersion::TLS_1_2)),
            ),
            key(None, tls(TlsOptions::builder().key_shares(Vec::new()))),
            key(None, grouped),
            key(None, proxied),
            SessionKey::new(
                &origin_uri,
                &origin_body,
                &client_config,
                &Uri::from_static("https://proxy:8443"),
                false,
            ),
            #[cfg(feature = "http3")]
            SessionKey::new(&origin_uri, &origin_body, &client_config, &origin_uri, true),
        ];
        for other in others {
            assert!(plain != other);
        }

        #[cfg(feature = "http3")]
        {
            let quic_key = |request_config| {
                let (origin, body) = request(Some(Protocol::Http3), request_config, &client_config);
                SessionKey::new(&origin, &body, &client_config, &origin, true)
            };
            let quic_origin = quic_key(ConnectConfig::default());
            let stream_config = tls(TlsOptions::builder().key_shares(Vec::new()));
            assert!(quic_origin == quic_key(stream_config));

            let mut quic_config = ConnectConfig::default();
            quic_config.insert(
                crate::quic::QuicOptions::builder()
                    .pre_shared_key(true)
                    .build(),
            );
            assert!(quic_origin != quic_key(quic_config.clone()));
            assert!(plain == key(None, quic_config));
        }

        let mut client_config = client_config;
        client_config.insert(Ipv4Addr::LOCALHOST);
        client_config.insert(Ipv6Addr::LOCALHOST);
        let uri = Uri::from_static("https://example.com/");
        let frozen = |config: ConnectConfig| config.for_protocol(Protocol::Auto, &client_config);
        let inherited = frozen(ConnectConfig::default());
        let mut partial = ConnectConfig::default();
        partial.insert(Ipv4Addr::LOCALHOST);
        let partial = frozen(partial);
        let mut changed = ConnectConfig::default();
        changed.insert(Ipv4Addr::UNSPECIFIED);
        let changed = frozen(changed);
        let assert_bindings = |quic: bool| {
            let key =
                |body: &ConnectConfig| SessionKey::new(&uri, body, &client_config, &uri, quic);
            let inherited_key = key(&inherited);
            assert!(inherited_key == key(&partial));
            assert!(inherited_key != key(&changed));
        };
        assert_bindings(false);
        #[cfg(feature = "http3")]
        assert_bindings(true);
    }
}
