//! Type-indexed connection configuration and reuse identity.
//!
//! Configuration values cache their identity hashes on insertion. Edits copy shared handles;
//! [`Overrides`] selects the entries compared by pool, session and TLS context keys.

use std::{
    any::{Any, TypeId, type_name},
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    iter,
    sync::{Arc, LazyLock},
};

use lru::DefaultHasher;

use crate::{Protocol, protocol::TransportKind};

/// Implements whole-value identity for one protocol configuration type.
macro_rules! impl_connect_config {
    ($type:ty, $scope:ident) => {
        impl ConnectConfig for $type {
            const SCOPE: ConfigScope = ConfigScope::$scope;
        }
    };
}

derive_deftly::define_derive_deftly! {
    /// Derives full and scoped equality/hashing, requiring exactly one group per field.
    /// Context fields also belong to sessions; connection fields also belong to pools.
    /// Negotiation and transport fields affect only pools. `map` compares an optional slice
    /// by its mapped elements, in order, treating absent and empty slices as equal.
    ConfigKey for struct:

    ${for fields {
        ${select1
            fmeta(config_key(context)) {}
            fmeta(config_key(connection)) {}
            fmeta(config_key(negotiation)) {}
            fmeta(config_key(transport)) {}
        }
        ${if all(fmeta(config_key(transport)), not(tmeta(config_key(transport)))) {
            ${error "transport fields require config_key(transport) on the type"}
        }}
    }}

    ${define HASH_FIELD {
        ${if fmeta(config_key(map)) {
            let values = self.$fname.as_deref().unwrap_or_default();
            Hash::hash(&values.len(), state);
            for value in values.iter().map(${fmeta(config_key(map)) as expr}) {
                Hash::hash(&value, state);
            }
        } else {
            Hash::hash(&self.$fname, state);
        }}
    }}
    ${define SAME_FIELD {
        ${if fmeta(config_key(map)) {
            self.$fname.as_deref().unwrap_or_default().iter()
                .map(${fmeta(config_key(map)) as expr})
                .eq(other.$fname.as_deref().unwrap_or_default().iter()
                    .map(${fmeta(config_key(map)) as expr}))
        } else {
            self.$fname == other.$fname
        }}
    }}

    impl PartialEq for $ttype {
        fn eq(&self, other: &Self) -> bool {
            true ${for fields { && $SAME_FIELD }}
        }
    }

    impl Eq for $ttype {}

    impl std::hash::Hash for $ttype {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            use std::hash::Hash;

            ${for fields { $HASH_FIELD }}
        }
    }

    impl $crate::conn::config::ConnectConfig for $ttype {
        const SCOPE: $crate::conn::config::ConfigScope = ${tmeta(config_key(scope)) as expr};

        fn hash_parts(&self) -> [u64; 3] {
            use std::hash::{BuildHasher, Hash, Hasher};
            use $crate::conn::config::HASHER;

            let mut hash = HASHER.build_hasher();
            let state = &mut hash;
            ${for fields { ${when fmeta(config_key(context))} $HASH_FIELD }}
            let context = hash.finish();

            let mut hash = HASHER.build_hasher();
            let state = &mut hash;
            context.hash(state);
            ${for fields { ${when fmeta(config_key(connection))} $HASH_FIELD }}
            let session = hash.finish();

            let mut hash = HASHER.build_hasher();
            let state = &mut hash;
            session.hash(state);
            ${for fields { ${when any(fmeta(config_key(negotiation)), fmeta(config_key(transport)))}
                $HASH_FIELD
            }}
            [hash.finish(), session, context]
        }

        fn eq_part(&self, other: &Self, part: $crate::conn::config::KeyPart) -> bool {
            use $crate::conn::config::KeyPart;

            true
                ${for fields { ${when fmeta(config_key(context))} && $SAME_FIELD }}
                && (part == KeyPart::Context || (true
                    ${for fields { ${when fmeta(config_key(connection))} && $SAME_FIELD }}
                ))
                && (part != KeyPart::Whole || (true
                    ${for fields { ${when any(fmeta(config_key(negotiation)), fmeta(config_key(transport)))}
                        && $SAME_FIELD
                    }}
                ))
        }
    }

    ${if tmeta(config_key(transport)) {
        impl $ttype {
            /// Returns whether both configure the same transport.
            pub(crate) fn same_transport(&self, other: &Self) -> bool {
                true ${for fields { ${when fmeta(config_key(transport))} && $SAME_FIELD }}
            }
        }
    }}
}

#[allow(clippy::single_component_path_imports)]
pub(crate) use derive_deftly_template_ConfigKey;

/// Shares one process-wide seed across configuration, pool and session identity hashes.
pub(crate) static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);

/// Identifies which transports or protocols use a configuration value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigScope(u16);

/// Selects the fields compared by a reuse key; TLS and QUIC options use distinct parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPart {
    /// Pool keys compare the whole value.
    Whole,
    /// Session keys exclude ALPN, ALPS and QUIC transport parameters.
    Session,
    /// Context keys compare only settings compiled into the TLS context.
    Context,
}

/// Configuration stored in [`ConfigSet`] and compared by reuse keys.
///
/// Hashes are cached on insertion, so values must not change while stored, and
/// `hash_parts` must agree with `eq_part` for every [`KeyPart`].
pub trait ConnectConfig: Clone + Eq + Hash + Send + Sync + 'static {
    /// Transports or protocols that use this configuration.
    const SCOPE: ConfigScope;

    /// Hashes indexed by [`KeyPart`].
    fn hash_parts(&self) -> [u64; 3] {
        [HASHER.hash_one(self); 3]
    }

    /// Compares the fields selected by `part`.
    fn eq_part(&self, other: &Self, part: KeyPart) -> bool {
        let _ = part;
        self == other
    }
}

/// Connection configuration of a client, an emulation or a request.
///
/// Entries are sorted by type and shared: clones bump one reference count, and edits
/// copy the slice of handles, never the values.
#[derive(Clone, Default)]
pub(crate) struct ConfigSet(Option<Arc<[Entry]>>);

/// Selects request configuration for a pool, session or TLS context key.
///
/// Entries outside the scope or equal to the client's are skipped. Entries past the first
/// 64 are counted whenever in scope. Keys are comparable only within the same client.
/// Selection uses cached hashes and retains all request values for other key selections.
#[derive(Clone)]
pub(crate) struct Overrides {
    config_set: ConfigSet,
    /// Bit `i` marks entry `i` as counted; entries past bit 63 count whenever in scope.
    counted: u64,
    scope: ConfigScope,
    part: KeyPart,
    /// Fold of the counted hashes in type order.
    hash: u64,
}

#[derive(Clone)]
struct Entry {
    id: TypeId,
    value: Arc<dyn Value>,
    identity: Identity,
}

#[derive(Clone, Copy)]
struct Identity {
    scope: ConfigScope,
    /// Per [`KeyPart`] hashes mixed with the configuration's type identity.
    hashes: [u64; 3],
    eq: fn(&dyn Any, &dyn Any, KeyPart) -> bool,
}

trait Value: Any + Send + Sync {
    fn type_name(&self) -> &'static str;
}

// ===== impl ConfigScope =====

impl ConfigScope {
    pub const TLS: Self = Self(1);
    pub const QUIC: Self = Self(1 << 1);
    pub const HTTP1: Self = Self(1 << 2);
    pub const HTTP2: Self = Self(1 << 3);
    pub const HTTP3: Self = Self(1 << 4);
    pub const ROUTE: Self = Self(1 << 6);
    pub const GROUP: Self = Self(1 << 7);

    const ALL: Self = Self(u16::MAX);
    const HTTP: Self = Self::HTTP1.or(Self::HTTP2).or(Self::HTTP3);
    #[cfg(feature = "http3")]
    const TCP_ONLY: Self = Self::TLS.or(Self::HTTP1).or(Self::HTTP2);
    const QUIC_ONLY: Self = Self::QUIC.or(Self::HTTP3);

    /// Selects configuration relevant to pooled connections using `protocol`.
    /// Excludes unused protocols so newly added scope bits stay in the key.
    const fn pool(protocol: Protocol) -> Self {
        Self::ALL.without(match protocol {
            Protocol::Http1 => Self::HTTP2.or(Self::QUIC_ONLY),
            #[cfg(feature = "http2")]
            Protocol::Http2 => Self::HTTP1.or(Self::QUIC_ONLY),
            Protocol::Auto => Self::QUIC_ONLY,
            #[cfg(feature = "http3")]
            Protocol::Http3 => Self::TCP_ONLY,
        })
    }

    /// Selects session configuration for `transport`, excluding HTTP options.
    const fn session(transport: TransportKind) -> Self {
        Self::ALL.without(Self::HTTP.or(match transport {
            TransportKind::Stream => Self::QUIC_ONLY,
            #[cfg(feature = "http3")]
            TransportKind::Quic => Self::TCP_ONLY,
        }))
    }

    /// Selects TLS context configuration, excluding routes and groups.
    const fn context(transport: TransportKind) -> Self {
        match transport {
            TransportKind::Stream => Self::TLS,
            #[cfg(feature = "http3")]
            TransportKind::Quic => Self::QUIC,
        }
    }

    const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

// ===== impl ConnectConfig =====

impl_connect_config!(netty::http1::Http1Options, HTTP1);
#[cfg(feature = "http2")]
impl_connect_config!(netty::http2::Http2Options, HTTP2);
#[cfg(feature = "http3")]
impl_connect_config!(netty::http3::Http3Options, HTTP3);

// ===== impl ConfigSet =====

impl ConfigSet {
    /// Inserts configuration and caches its hashes for each [`KeyPart`].
    pub(crate) fn insert<T: ConnectConfig>(&mut self, value: T) -> &mut Self {
        let id = TypeId::of::<T>();
        let identity = Identity {
            scope: T::SCOPE,
            hashes: value.hash_parts().map(|hash| HASHER.hash_one((id, hash))),
            eq: |left, right, part| match (left.downcast_ref::<T>(), right.downcast_ref::<T>()) {
                (Some(left), Some(right)) => left.eq_part(right, part),
                _ => false,
            },
        };
        self.insert_entry(Entry {
            id,
            value: Arc::new(value),
            identity,
        });
        self
    }

    /// Inserts `Some` configuration or removes the type for `None`.
    pub(crate) fn set<T: ConnectConfig>(&mut self, value: Option<T>) -> &mut Self {
        match value {
            Some(value) => self.insert(value),
            None => {
                self.remove::<T>();
                self
            }
        }
    }

    /// Returns the configuration stored for this exact type.
    pub(crate) fn get<T: ConnectConfig>(&self) -> Option<&T> {
        self.entry(TypeId::of::<T>())
            .and_then(|entry| (entry.value.as_ref() as &dyn Any).downcast_ref())
    }

    /// Returns a shared handle to the value stored for this exact type.
    pub(crate) fn get_arc<T: ConnectConfig>(&self) -> Option<Arc<T>> {
        let value: Arc<dyn Any + Send + Sync> = self.entry(TypeId::of::<T>())?.value.clone();
        value.downcast().ok()
    }

    /// Removes a value and returns a shared handle without cloning the value.
    /// Missing types leave shared storage unchanged.
    pub(crate) fn remove<T: ConnectConfig>(&mut self) -> Option<Arc<T>> {
        let entries = self.0.as_deref()?;
        let index = search(entries, TypeId::of::<T>()).ok()?;
        let value: Arc<dyn Any + Send + Sync> = entries[index].value.clone();
        self.0 = collect(
            entries[..index]
                .iter()
                .chain(&entries[index + 1..])
                .cloned(),
        );
        value.downcast().ok()
    }

    /// Merges `other` into `self`; its entries replace those of the same type.
    /// An empty destination takes the incoming storage without copying it.
    pub(crate) fn extend(&mut self, other: Self) {
        let (Some(left), Some(right)) = (self.0.as_deref(), other.0.as_deref()) else {
            if self.0.is_none() {
                self.0 = other.0;
            }
            return;
        };
        let mut merged = Vec::with_capacity(left.len() + right.len());
        let (mut left, mut right) = (left.iter().peekable(), right.iter().peekable());
        while let (Some(l), Some(r)) = (left.peek().map(|e| e.id), right.peek().map(|e| e.id)) {
            if l == r {
                left.next();
            }
            let next = if l < r { left.next() } else { right.next() };
            merged.extend(next.cloned());
        }
        merged.extend(left.chain(right).cloned());
        self.0 = Some(merged.into());
    }

    fn entries(&self) -> &[Entry] {
        self.0.as_deref().unwrap_or_default()
    }

    fn entry(&self, id: TypeId) -> Option<&Entry> {
        let entries = self.entries();
        search(entries, id).ok().map(|index| &entries[index])
    }

    fn insert_entry(&mut self, entry: Entry) {
        let entries = self.entries();
        let (index, replaced) = match search(entries, entry.id) {
            Ok(index) => (index, 1),
            Err(index) => (index, 0),
        };
        self.0 = collect(
            entries[..index]
                .iter()
                .cloned()
                .chain(iter::once(entry))
                .chain(entries[index + replaced..].iter().cloned()),
        );
    }

    fn ptr_eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            (None, None) => true,
            _ => false,
        }
    }
}

impl PartialEq for ConfigSet {
    fn eq(&self, other: &Self) -> bool {
        self.ptr_eq(other)
            || same_entries(
                self.entries().iter(),
                other.entries().iter(),
                KeyPart::Whole,
            )
    }
}

impl Eq for ConfigSet {}

impl fmt::Debug for ConfigSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(
                self.entries()
                    .iter()
                    .map(|entry| entry.value.as_ref().type_name()),
            )
            .finish()
    }
}

// ===== impl Overrides =====

impl Overrides {
    /// Selects request configuration that changes pooled connection identity.
    pub(crate) fn for_pool(
        config_set: ConfigSet,
        client_config_set: &ConfigSet,
        protocol: Protocol,
    ) -> Self {
        Self::select(
            config_set,
            client_config_set,
            ConfigScope::pool(protocol),
            KeyPart::Whole,
        )
    }

    /// Selects request configuration that changes resumable TLS session identity.
    pub(crate) fn for_session(
        config_set: ConfigSet,
        client_config_set: &ConfigSet,
        transport: TransportKind,
    ) -> Self {
        Self::select(
            config_set,
            client_config_set,
            ConfigScope::session(transport),
            KeyPart::Session,
        )
    }

    /// Selects request configuration that changes the compiled TLS context.
    pub(crate) fn for_context(
        config_set: ConfigSet,
        client_config_set: &ConfigSet,
        transport: TransportKind,
    ) -> Self {
        Self::select(
            config_set,
            client_config_set,
            ConfigScope::context(transport),
            KeyPart::Context,
        )
    }

    /// Selects entries in `scope` that differ from `client_config_set` under `part`.
    /// Uses cached hashes without allocating or hashing configuration values.
    fn select(
        config_set: ConfigSet,
        client_config_set: &ConfigSet,
        scope: ConfigScope,
        part: KeyPart,
    ) -> Self {
        let mut counted = 0;
        let mut hasher = HASHER.build_hasher();
        // Up to 64 entries, shared client storage needs no overrides; later entries count by scope.
        if !(config_set.ptr_eq(client_config_set) && config_set.entries().len() <= 64) {
            let mut client_entries = client_config_set.entries().iter().peekable();
            for (index, entry) in config_set.entries().iter().enumerate() {
                let identity = &entry.identity;
                if !identity.scope.intersects(scope) {
                    continue;
                }
                while client_entries
                    .next_if(|other| other.id < entry.id)
                    .is_some()
                {}
                let inherited = client_entries
                    .next_if(|other| other.id == entry.id)
                    .is_some_and(|other| other.same(entry, part));
                if index < 64 {
                    if inherited {
                        continue;
                    }
                    counted |= 1 << index;
                }
                hasher.write_u64(identity.hashes[part as usize]);
            }
        }

        Self {
            config_set,
            counted,
            scope,
            part,
            hash: hasher.finish(),
        }
    }

    /// Returns the counted value of this type.
    pub(crate) fn get<T: ConnectConfig>(&self) -> Option<&T> {
        let entries = self.config_set.entries();
        let index = search(entries, TypeId::of::<T>()).ok()?;
        self.counts(index, &entries[index])
            .then(|| (entries[index].value.as_ref() as &dyn Any).downcast_ref())
            .flatten()
    }

    /// Returns a shared handle to the counted value of this type.
    #[cfg(feature = "http3")]
    pub(crate) fn get_arc<T: ConnectConfig>(&self) -> Option<Arc<T>> {
        let entries = self.config_set.entries();
        let index = search(entries, TypeId::of::<T>()).ok()?;
        let entry = &entries[index];
        let value: Arc<dyn Any + Send + Sync> =
            self.counts(index, entry).then(|| entry.value.clone())?;
        value.downcast().ok()
    }

    /// Every configuration value of the request, including uncounted entries.
    pub(crate) fn config_set(&self) -> &ConfigSet {
        &self.config_set
    }

    /// Returns whether no entry is counted.
    pub(crate) fn is_empty(&self) -> bool {
        self.counted().next().is_none()
    }

    /// Returns the cached hash of the counted entries.
    pub(crate) fn hash(&self) -> u64 {
        self.hash
    }

    fn counts(&self, index: usize, entry: &Entry) -> bool {
        match index {
            0..64 => self.counted & (1 << index) != 0,
            _ => entry.identity.scope.intersects(self.scope),
        }
    }

    fn counted(&self) -> impl Iterator<Item = &Entry> {
        let entries = self.config_set.entries().iter().enumerate();
        entries.filter_map(|(index, entry)| self.counts(index, entry).then_some(entry))
    }
}

impl PartialEq for Overrides {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.scope == other.scope
            && self.part == other.part
            && ((self.config_set.ptr_eq(&other.config_set) && self.counted == other.counted)
                || same_entries(self.counted(), other.counted(), self.part))
    }
}

impl Eq for Overrides {}

impl Hash for Overrides {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl fmt::Debug for Overrides {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(self.counted().map(|entry| entry.value.as_ref().type_name()))
            .finish()
    }
}

// ===== impl Entry =====

impl Entry {
    /// Compares two entries of one type under `part`, by pointer, then hash, then value.
    fn same(&self, other: &Self, part: KeyPart) -> bool {
        let (left, right) = (&self.identity, &other.identity);
        Arc::ptr_eq(&self.value, &other.value)
            || (left.hashes[part as usize] == right.hashes[part as usize]
                && (left.eq)(
                    self.value.as_ref() as &dyn Any,
                    other.value.as_ref() as &dyn Any,
                    part,
                ))
    }
}

// ===== impl Value =====

impl<T: ConnectConfig> Value for T {
    fn type_name(&self) -> &'static str {
        type_name::<T>()
    }
}

/// Compares two type-ordered entry sequences under `part`.
fn same_entries<'a>(
    mut left: impl Iterator<Item = &'a Entry>,
    mut right: impl Iterator<Item = &'a Entry>,
    part: KeyPart,
) -> bool {
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(l), Some(r)) if l.id == r.id && l.same(r, part) => {}
            _ => return false,
        }
    }
}

fn search(entries: &[Entry], id: TypeId) -> Result<usize, usize> {
    entries.binary_search_by(|entry| entry.id.cmp(&id))
}

/// Collects entries into one allocation; the iterators used here report exact lengths.
fn collect(entries: impl Iterator<Item = Entry>) -> Option<Arc<[Entry]>> {
    let entries: Arc<[Entry]> = entries.collect();
    (!entries.is_empty()).then_some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "http2")]
    use crate::http2::Http2Options;
    use crate::{
        group::Group,
        http1::Http1Options,
        tls::{AlpnProtocol, Tls13Cipher, TlsOptions},
    };

    fn group(name: &str) -> ConfigSet {
        let mut config_set = ConfigSet::default();
        config_set.insert(Group::new(name));
        config_set
    }

    #[test]
    fn edits_share_values_and_keep_frozen_copies() {
        let mut config_set = group("a");
        config_set.insert(Http1Options::builder().max_headers(8).build());
        let frozen = config_set.clone();
        let value = frozen.get_arc::<Http1Options>().unwrap();

        config_set
            .insert(TlsOptions::default())
            .set(Some(Group::new("b")))
            .set::<Http1Options>(None);
        assert_eq!(frozen.get::<Group>(), Some(&Group::new("a")));
        assert!(frozen.get::<Http1Options>().is_some());
        assert_eq!(config_set.get::<Group>(), Some(&Group::new("b")));
        assert!(config_set.get::<Http1Options>().is_none());
        assert_eq!(config_set.get::<TlsOptions>(), Some(&TlsOptions::default()));

        // Insertion order does not change identity.
        let mut reordered = ConfigSet::default();
        reordered
            .insert(TlsOptions::default())
            .insert(Group::new("b"));
        assert_eq!(config_set, reordered);

        // An empty destination takes the storage; otherwise incoming types win.
        let mut merged = ConfigSet::default();
        merged.extend(frozen.clone());
        assert!(merged.ptr_eq(&frozen));
        merged.extend(config_set.clone());
        assert_eq!(merged.get::<Group>(), Some(&Group::new("b")));
        assert!(merged.get::<Http1Options>().is_some());
        assert!(merged.get::<TlsOptions>().is_some());

        assert!(Arc::ptr_eq(
            &merged.get_arc::<Http1Options>().unwrap(),
            &value
        ));
        assert!(Arc::ptr_eq(
            &merged.remove::<Http1Options>().unwrap(),
            &value
        ));
        assert!(merged.remove::<Http1Options>().is_none());
        assert!(frozen.get::<Http1Options>().is_some());
    }

    #[test]
    fn overrides_count_differences_in_scope() {
        let client_config_set = group("a");
        #[cfg(feature = "http2")]
        let mut client_config_set = client_config_set;
        #[cfg(feature = "http2")]
        client_config_set.insert(Http2Options::builder().header_table_size(1024).build());
        let overrides = |config_set: &ConfigSet| {
            Overrides::for_pool(config_set.clone(), &client_config_set, Protocol::Http1)
        };

        // The client's own storage and equal values are inherited.
        let empty = overrides(&ConfigSet::default());
        assert!(empty.is_empty());
        assert!(overrides(&client_config_set).is_empty());
        assert!(overrides(&group("a")) == empty);

        // Other values count; out-of-scope options never do.
        let config_set = group("b");
        #[cfg(feature = "http2")]
        let mut config_set = config_set;
        #[cfg(feature = "http2")]
        config_set.insert(Http2Options::builder().header_table_size(4096).build());
        let counted = overrides(&config_set);
        assert!(!counted.is_empty());
        assert_eq!(counted.get::<Group>(), Some(&Group::new("b")));
        #[cfg(feature = "http2")]
        assert!(counted.get::<Http2Options>().is_none());
        #[cfg(feature = "http2")]
        assert!(counted.config_set().get::<Http2Options>().is_some());
        assert!(counted == overrides(&group("b")));
        assert!(counted != overrides(&group("c")));

        // A forged hash collision still compares the values.
        let mut collision = overrides(&group("c"));
        collision.hash = counted.hash;
        assert!(counted != collision);

        // Pool, session and context identities select different parts of TLS options.
        let mut client_config_set = ConfigSet::default();
        client_config_set.insert(TlsOptions::default());
        for (options, expected) in [
            (
                TlsOptions::builder()
                    .alpn_protocols([AlpnProtocol::HTTP1])
                    .build(),
                [true, false, false],
            ),
            (
                TlsOptions::builder().server_padding(0).build(),
                [true, true, false],
            ),
            (
                TlsOptions::builder()
                    .tls13_cipher_list(&[Tls13Cipher::AES_256_GCM_SHA384])
                    .build(),
                [true, true, true],
            ),
        ] {
            let mut config_set = ConfigSet::default();
            config_set.insert(options);
            let projections = [
                Overrides::for_pool(config_set.clone(), &client_config_set, Protocol::Auto),
                Overrides::for_session(
                    config_set.clone(),
                    &client_config_set,
                    TransportKind::Stream,
                ),
                Overrides::for_context(config_set, &client_config_set, TransportKind::Stream),
            ];
            for (projection, counted) in projections.into_iter().zip(expected) {
                assert_eq!(!projection.is_empty(), counted);
            }
        }
    }
}
