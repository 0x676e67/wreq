//! Connection extensions and the value comparisons used by reuse keys.

use std::{
    any::type_name,
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, LazyLock},
};

use lru::DefaultHasher;

#[cfg(feature = "http2")]
use crate::http2::Http2Options;
use crate::{
    conn::dialer::Interface, group::Group, http1::Http1Options, proxy::Matcher, tls::TlsOptions,
};
#[cfg(feature = "http3")]
use crate::{http3::Http3Options, quic::QuicOptions};

/// Implements whole-value identity for one connection configuration type.
macro_rules! impl_connect_config {
    ($type:ty, $scope:ident) => {
        impl $crate::config::connect::ConnectConfig for $type {
            const SCOPE: $crate::config::connect::ConfigScope =
                $crate::config::connect::ConfigScope::$scope;
        }
    };
}

pub(crate) use impl_connect_config;

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

    impl $crate::config::connect::ConnectConfig for $ttype {
        const SCOPE: $crate::config::connect::ConfigScope = ${tmeta(config_key(scope)) as expr};

        fn hash_parts(&self) -> [u64; 3] {
            use std::hash::{BuildHasher, Hash, Hasher};
            use $crate::config::connect::HASHER;

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

        fn eq_part(&self, other: &Self, part: $crate::config::connect::KeyPart) -> bool {
            use $crate::config::connect::KeyPart;

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

/// Configuration values compared by connection reuse keys.
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

/// Shared connection extensions. Builders edit their own slots before a request is frozen.
#[derive(Clone, Default)]
pub(crate) struct Extensions(Option<Arc<Values>>);

/// A borrowed request overlay, with client defaults for missing types.
pub(crate) struct WithBase<'a> {
    extensions: &'a Extensions,
    base: &'a Extensions,
}

/// Selects differing values for one reuse key. Bits identify fields, not storage positions.
#[derive(Clone, Copy)]
pub(crate) struct Selection {
    fields: u16,
    part: KeyPart,
    hash: u64,
}

/// A reuse key's selection and the shared values it compares.
#[derive(Clone)]
pub(crate) struct Projection {
    values: Extensions,
    selection: Selection,
}

/// A cached protocol value can be retained by a key independently of the request.
#[derive(Clone)]
pub(crate) struct ContextKey<T> {
    value: Arc<T>,
    hash: u64,
}

/// Maps a supported extension type to its field in the connection configuration.
pub trait Extension: ConnectConfig {
    #[doc(hidden)]
    type Stored: Stored<Self>;

    #[doc(hidden)]
    const INDEX: u32;

    #[doc(hidden)]
    fn slot(values: &Values) -> &Option<Self::Stored>;

    #[doc(hidden)]
    fn slot_mut(values: &mut Values) -> &mut Option<Self::Stored>;
}

#[doc(hidden)]
pub trait Stored<T: ConnectConfig>: Clone {
    fn store(value: T) -> Self;
    fn value(&self) -> &T;
    fn hash(&self, part: KeyPart) -> u64;
    fn same(&self, other: &Self, part: KeyPart) -> bool;
}

#[doc(hidden)]
#[derive(Clone)]
pub struct Cached<T> {
    value: Arc<T>,
    hashes: [u64; 3],
}

macro_rules! extension_fields {
    ($($(#[$attr:meta])* $index:literal => $field:ident: $ty:ty as $stored:ty),+ $(,)?) => {
        #[doc(hidden)]
        #[derive(Clone, Default)]
        pub struct Values {
            fields: u16,
            $($(#[$attr])* $field: Option<$stored>,)+
        }

        impl Values {
            fn extend(&mut self, other: &Self) {
                self.fields |= other.fields;
                $($(#[$attr])* if let Some(value) = &other.$field {
                    self.$field = Some(value.clone());
                })+
            }

            fn same(&self, other: &Self, selection: Selection) -> bool {
                $($(#[$attr])* if selection.fields & (1 << $index) != 0
                    && !self.$field.as_ref().zip(other.$field.as_ref())
                        .is_some_and(|(left, right)| Stored::<$ty>::same(left, right, selection.part))
                {
                    return false;
                })+
                true
            }

            fn debug(&self, f: &mut fmt::Formatter<'_>, fields: u16) -> fmt::Result {
                let mut set = f.debug_set();
                $($(#[$attr])* if fields & (1 << $index) != 0 {
                    set.entry(&type_name::<$ty>());
                })+
                set.finish()
            }
        }

        $($(#[$attr])*
        impl Extension for $ty {
            type Stored = $stored;
            const INDEX: u32 = $index;

            fn slot(values: &Values) -> &Option<Self::Stored> {
                &values.$field
            }

            fn slot_mut(values: &mut Values) -> &mut Option<Self::Stored> {
                &mut values.$field
            }
        })+
    };
}

extension_fields! {
    0 => ipv4: Ipv4Addr as Ipv4Addr,
    1 => ipv6: Ipv6Addr as Ipv6Addr,
    2 => interface: Interface as Interface,
    3 => group: Group as Group,
    4 => matcher: Matcher as Cached<Matcher>,
    5 => tls: TlsOptions as Cached<TlsOptions>,
    6 => http1: Http1Options as Cached<Http1Options>,
    #[cfg(feature = "http2")]
    7 => http2: Http2Options as Cached<Http2Options>,
    #[cfg(feature = "http3")]
    8 => quic: QuicOptions as Cached<QuicOptions>,
    #[cfg(feature = "http3")]
    9 => http3: Http3Options as Cached<Http3Options>,
}

// ===== impl ConfigScope =====

// Retained as part of the inherited ProtocolConfig contract. Reuse keys select their own fields.
impl ConfigScope {
    pub const TLS: Self = Self(1);
    pub const QUIC: Self = Self(1 << 1);
    pub const HTTP1: Self = Self(1 << 2);
    pub const HTTP2: Self = Self(1 << 3);
    pub const HTTP3: Self = Self(1 << 4);
    pub const SOCKET: Self = Self(1 << 5);
    pub const ROUTE: Self = Self(1 << 6);
    pub const GROUP: Self = Self(1 << 7);
}

// ===== impl ConnectConfig =====

impl_connect_config!(Http1Options, HTTP1);
#[cfg(feature = "http2")]
impl_connect_config!(Http2Options, HTTP2);
#[cfg(feature = "http3")]
impl_connect_config!(Http3Options, HTTP3);

// ===== impl Stored =====

impl<T: ConnectConfig> Stored<T> for T {
    fn store(value: T) -> Self {
        value
    }

    fn value(&self) -> &T {
        self
    }

    fn hash(&self, _part: KeyPart) -> u64 {
        HASHER.hash_one(self)
    }

    fn same(&self, other: &Self, part: KeyPart) -> bool {
        self.eq_part(other, part)
    }
}

impl<T: ConnectConfig> Stored<T> for Cached<T> {
    fn store(value: T) -> Self {
        let hashes = value.hash_parts();
        Self {
            value: Arc::new(value),
            hashes,
        }
    }

    fn value(&self) -> &T {
        &self.value
    }

    fn hash(&self, part: KeyPart) -> u64 {
        self.hashes[part as usize]
    }

    fn same(&self, other: &Self, part: KeyPart) -> bool {
        Arc::ptr_eq(&self.value, &other.value)
            || (self.hash(part) == other.hash(part) && self.value.eq_part(&other.value, part))
    }
}

// ===== impl Extensions =====

impl Extensions {
    pub(crate) fn insert<T: Extension>(&mut self, value: T) -> &mut Self {
        let values = Arc::make_mut(self.0.get_or_insert_with(Arc::default));
        *T::slot_mut(values) = Some(T::Stored::store(value));
        values.fields |= 1 << T::INDEX;
        self
    }

    /// An absent value clears only this type's local setting.
    pub(crate) fn set<T: Extension>(&mut self, value: Option<T>) -> &mut Self {
        if let Some(value) = value {
            return self.insert(value);
        }
        let Some(values) = &mut self.0 else {
            return self;
        };
        let field = 1 << T::INDEX;
        if values.fields == field {
            self.0 = None;
        } else if values.fields & field != 0 {
            let values = Arc::make_mut(values);
            *T::slot_mut(values) = None;
            values.fields &= !field;
        }
        self
    }

    /// Replaces only the types supplied by the incoming configuration.
    pub(crate) fn extend(&mut self, other: Self) {
        if let Some(other) = other.0 {
            match &mut self.0 {
                Some(values) => Arc::make_mut(values).extend(&other),
                None => self.0 = Some(other),
            }
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub(crate) fn get_ref<T: Extension>(&self) -> Option<&T> {
        self.get::<T>().map(Stored::value)
    }

    pub(crate) fn get_arc<T: Extension<Stored = Cached<T>>>(&self) -> Option<Arc<T>> {
        self.get::<T>().map(|entry| entry.value.clone())
    }

    /// Borrows the overlay and its defaults without merging or copying either set.
    pub(crate) fn with_base<'a>(&'a self, base: &'a Self) -> WithBase<'a> {
        WithBase {
            extensions: self,
            base,
        }
    }

    pub(crate) fn different<T: Extension>(&self, base: &Self, part: KeyPart) -> Option<&T> {
        self.different_entry::<T>(base, part).map(Stored::value)
    }

    #[cfg(feature = "http3")]
    pub(crate) fn different_arc<T: Extension<Stored = Cached<T>>>(
        &self,
        base: &Self,
        part: KeyPart,
    ) -> Option<Arc<T>> {
        self.different_entry::<T>(base, part)
            .map(|entry| entry.value.clone())
    }

    /// Retains only the selected protocol value for a context cache.
    pub(crate) fn context_key<T: Extension<Stored = Cached<T>>>(
        &self,
        base: &Self,
    ) -> Option<ContextKey<T>> {
        let entry = self.different_entry::<T>(base, KeyPart::Context)?;
        Some(ContextKey {
            value: entry.value.clone(),
            hash: entry.hash(KeyPart::Context),
        })
    }

    fn get<T: Extension>(&self) -> Option<&T::Stored> {
        T::slot(self.0.as_deref()?).as_ref()
    }

    fn different_entry<T: Extension>(&self, base: &Self, part: KeyPart) -> Option<&T::Stored> {
        let entry = self.get::<T>()?;
        (!base.get::<T>().is_some_and(|other| entry.same(other, part))).then_some(entry)
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(values) => values.debug(f, values.fields),
            None => f.debug_set().finish(),
        }
    }
}

impl<'a> WithBase<'a> {
    pub(crate) fn get_ref<T: Extension>(&self) -> Option<&'a T> {
        self.extensions
            .get_ref::<T>()
            .or_else(|| self.base.get_ref())
    }
}

// ===== impl Selection =====

impl Selection {
    pub(crate) const fn new(part: KeyPart) -> Self {
        Self {
            fields: 0,
            part,
            hash: 0,
        }
    }

    pub(crate) fn include<T: Extension>(&mut self, request: &Extensions, client: &Extensions) {
        if let Some(entry) = request.different_entry::<T>(client, self.part) {
            self.fields |= 1 << T::INDEX;
            self.hash ^= entry.hash(self.part).rotate_left(T::INDEX);
        }
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.fields == 0
    }

    pub(crate) const fn hash(self) -> u64 {
        self.hash
    }

    pub(crate) fn get_ref<'a, T: Extension>(&self, extensions: &'a Extensions) -> Option<&'a T> {
        if self.fields & (1 << T::INDEX) != 0 {
            extensions.get_ref::<T>()
        } else {
            None
        }
    }

    pub(crate) fn key(self, extensions: &Extensions) -> Projection {
        Projection {
            values: if self.is_empty() {
                Extensions::default()
            } else {
                extensions.clone()
            },
            selection: self,
        }
    }
}

// ===== impl Projection =====

impl PartialEq for Projection {
    fn eq(&self, other: &Self) -> bool {
        let selection = self.selection;
        if selection.hash != other.selection.hash
            || selection.fields != other.selection.fields
            || selection.part != other.selection.part
        {
            return false;
        }
        match (&self.values.0, &other.values.0) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right) || left.same(right, selection),
            (None, None) => true,
            _ => false,
        }
    }
}

impl Eq for Projection {}

impl Hash for Projection {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.selection.hash);
    }
}

impl fmt::Debug for Projection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.values.0 {
            Some(values) => values.debug(f, self.selection.fields),
            None => f.debug_set().finish(),
        }
    }
}

// ===== impl ContextKey =====

impl<T> ContextKey<T> {
    pub(crate) fn get(&self) -> &T {
        &self.value
    }
}

impl<T: ConnectConfig> PartialEq for ContextKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && (Arc::ptr_eq(&self.value, &other.value)
                || self.value.eq_part(&other.value, KeyPart::Context))
    }
}

impl<T: ConnectConfig> Eq for ContextKey<T> {}

impl<T> Hash for ContextKey<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl<T> fmt::Debug for ContextKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(type_name::<T>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuse_projection_compares_values_when_hashes_match() {
        let mut left = Extensions::default();
        left.insert(Group::new("left"));
        let mut right = Extensions::default();
        right.insert(Group::new("right"));
        let client = Extensions::default();
        let mut a = Selection::new(KeyPart::Whole);
        a.include::<Group>(&left, &client);
        let mut b = Selection::new(KeyPart::Whole);
        b.include::<Group>(&right, &client);
        b.hash = a.hash;
        assert_ne!(a.key(&left), b.key(&right));
    }
}
