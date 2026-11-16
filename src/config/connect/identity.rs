//! Value comparisons used by connection, TLS context and session keys.

use std::{
    hash::{BuildHasher, Hash, Hasher},
    sync::{Arc, LazyLock},
};

use lru::DefaultHasher;

use super::{Extension, Extensions, Stored};

/// Implements whole-value identity for one connection configuration type.
macro_rules! impl_connect_config_value {
    ($type:ty, $scope:ident) => {
        impl $crate::config::connect::ConnectConfigValue for $type {
            const SCOPE: $crate::config::connect::ConfigScope =
                $crate::config::connect::ConfigScope::$scope;
        }
    };
}

pub(crate) use impl_connect_config_value;

derive_deftly::define_derive_deftly! {
    /// Derives full and scoped equality and hashing, requiring one group per field.
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

    ${define CONTEXT_KEY ${tmeta(config_key(context_key)) as ident}}
    ${define SESSION_KEY ${tmeta(config_key(session_key)) as ident}}

    ${define IDENTITY_FIELD {
        $fname: ${if fmeta(config_key(map)) {
            ::std::vec::Vec<${fmeta(config_key(map_type)) as ty}>
        } else {
            $ftype
        }},
    }}
    ${define IDENTITY_VALUE {
        $fname: ${if fmeta(config_key(map)) {
            self.$fname.as_deref().unwrap_or_default().iter()
                .map(${fmeta(config_key(map)) as expr})
                .collect()
        } else {
            ::core::clone::Clone::clone(&self.$fname)
        }},
    }}

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub(crate) struct $CONTEXT_KEY {
        ${for fields { ${when fmeta(config_key(context))} $IDENTITY_FIELD }}
    }

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub(crate) struct $SESSION_KEY {
        context: $CONTEXT_KEY,
        ${for fields { ${when fmeta(config_key(connection))} $IDENTITY_FIELD }}
    }

    impl $crate::config::connect::ScopedConfig for $ttype {
        type Context = $CONTEXT_KEY;
        type Session = $SESSION_KEY;

        fn context_identity(&self) -> Self::Context {
            $CONTEXT_KEY {
                ${for fields { ${when fmeta(config_key(context))} $IDENTITY_VALUE }}
            }
        }

        fn session_identity(&self) -> Self::Session {
            $SESSION_KEY {
                context: self.context_identity(),
                ${for fields { ${when fmeta(config_key(connection))} $IDENTITY_VALUE }}
            }
        }
    }

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

    impl $crate::config::connect::ConnectConfigValue for $ttype {
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
pub trait ConnectConfigValue: Clone + Eq + Hash + Send + Sync + 'static {
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

pub(crate) trait ScopedConfig: ConnectConfigValue {
    type Context: Clone + Eq + Hash;
    type Session: Clone + Eq + Hash;

    fn context_identity(&self) -> Self::Context;
    fn session_identity(&self) -> Self::Session;
}

/// A shared option and the hashes computed when it is stored.
#[doc(hidden)]
#[derive(Clone)]
pub struct Cached<T> {
    value: Arc<T>,
    hashes: [u64; 3],
}

/// A key that compares the whole option value.
#[derive(Clone)]
pub(crate) struct Whole<T> {
    value: Arc<T>,
    hash: u64,
}

/// Selects a local option when it differs from the explicit client default.
pub(crate) fn changed<'a, T>(
    request: &'a Extensions,
    base: &Extensions,
    part: KeyPart,
) -> Option<&'a Cached<T>>
where
    T: Extension<Stored = Cached<T>> + ConnectConfigValue,
{
    let value = request.get::<T>()?;
    (!base.get::<T>().is_some_and(|other| value.same(other, part))).then_some(value)
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

impl_connect_config_value!(crate::http1::Http1Options, HTTP1);
#[cfg(feature = "http2")]
impl_connect_config_value!(crate::http2::Http2Options, HTTP2);
#[cfg(feature = "http3")]
impl_connect_config_value!(crate::http3::Http3Options, HTTP3);

// ===== impl Cached =====

impl<T> Cached<T> {
    pub(crate) fn get(&self) -> &T {
        &self.value
    }

    pub(crate) fn arc(&self) -> Arc<T> {
        self.value.clone()
    }

    pub(crate) fn hash(&self, part: KeyPart) -> u64 {
        self.hashes[part as usize]
    }
}

impl<T: ConnectConfigValue> Cached<T> {
    fn same(&self, other: &Self, part: KeyPart) -> bool {
        Arc::ptr_eq(&self.value, &other.value)
            || (self.hash(part) == other.hash(part) && self.value.eq_part(&other.value, part))
    }
}

impl<T: ConnectConfigValue> Stored<T> for Cached<T> {
    fn store(value: T) -> Self {
        let hashes = value.hash_parts();
        Self {
            value: Arc::new(value),
            hashes,
        }
    }

    fn value(&self) -> &T {
        self.get()
    }
}

// ===== impl Whole =====

impl<T> Whole<T> {
    pub(crate) fn new(value: &Cached<T>) -> Self {
        Self {
            value: value.arc(),
            hash: value.hash(KeyPart::Whole),
        }
    }
}

impl<T: ConnectConfigValue> PartialEq for Whole<T> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && (Arc::ptr_eq(&self.value, &other.value)
                || self.value.eq_part(&other.value, KeyPart::Whole))
    }
}

impl<T: ConnectConfigValue> Eq for Whole<T> {}

impl<T> Hash for Whole<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}
