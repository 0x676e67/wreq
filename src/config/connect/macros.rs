/// Implements [`ConnectConfigValue`](crate::config::connect::ConnectConfigValue) for a type
/// with uniform equality across all scopes.
macro_rules! impl_connect_config_value {
    ($type:ty, $target:ident) => {
        impl $crate::config::connect::ConnectConfigValue for $type {
            const TARGET: $crate::config::connect::KeyTarget =
                $crate::config::connect::KeyTarget::$target;
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
        const TARGET: $crate::config::connect::KeyTarget = ${tmeta(config_key(target)) as expr};

        fn hash_scopes(&self) -> [u64; 3] {
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

        fn eq_scope(&self, other: &Self, scope: $crate::config::connect::KeyScope) -> bool {
            use $crate::config::connect::KeyScope;

            true
                ${for fields { ${when fmeta(config_key(context))} && $SAME_FIELD }}
                && (scope == KeyScope::Context || (true
                    ${for fields { ${when fmeta(config_key(connection))} && $SAME_FIELD }}
                ))
                && (scope != KeyScope::Full || (true
                    ${for fields { ${when any(fmeta(config_key(negotiation)), fmeta(config_key(transport)))}
                        && $SAME_FIELD
                    }}
                ))
        }
    }

    ${if tmeta(config_key(transport)) {
        impl $ttype {
            /// Returns whether both configure the same transport.
            #[must_use]
            pub(crate) fn same_transport(&self, other: &Self) -> bool {
                true ${for fields { ${when fmeta(config_key(transport))} && $SAME_FIELD }}
            }
        }
    }}
}

#[allow(clippy::single_component_path_imports)]
pub(crate) use derive_deftly_template_ConfigKey;
