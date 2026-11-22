use std::hash::Hasher;

pub(super) trait ContextOptions: Send + Sync + 'static {
    fn same_context(&self, other: &Self) -> bool;
    fn hash_context<H: Hasher>(&self, state: &mut H);
}

derive_deftly::define_derive_deftly! {
    /// Derives TLS option identity for pools, sessions, and compiled contexts.
    /// Unmarked fields belong to all three scopes.
    TlsKey for struct:

    ${defcond SESSION_FIELD not(any(fmeta(tls_key(pool)), fmeta(tls_key(transport))))}
    ${defcond CONTEXT_FIELD all(SESSION_FIELD, not(fmeta(tls_key(session))))}

    impl ::std::cmp::PartialEq for $ttype {
        fn eq(&self, other: &Self) -> bool {
            true ${for fields { && self.$fname == other.$fname }}
        }
    }

    impl ::std::cmp::Eq for $ttype {}

    impl ::std::hash::Hash for $ttype {
        fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
            ${for fields { ::std::hash::Hash::hash(&self.$fname, state); }}
        }
    }

    impl $ttype {
        #[must_use]
        pub(crate) fn same_session(&self, other: &Self) -> bool {
            ::std::ptr::eq(self, other)
                || (true ${for fields { ${when SESSION_FIELD} && self.$fname == other.$fname }})
        }

        pub(crate) fn hash_session<H: ::std::hash::Hasher>(&self, state: &mut H) {
            ${for fields { ${when SESSION_FIELD} ::std::hash::Hash::hash(&self.$fname, state); }}
        }

        ${if tmeta(tls_key(quic)) {
            #[must_use]
            pub(crate) fn same_transport(&self, other: &Self) -> bool {
                true ${for fields { ${when fmeta(tls_key(transport))} && self.$fname == other.$fname }}
            }
        }}
    }

    impl $crate::tls_key::ContextOptions for $ttype {
        fn same_context(&self, other: &Self) -> bool {
            ::std::ptr::eq(self, other)
                || (true ${for fields { ${when CONTEXT_FIELD} && self.$fname == other.$fname }})
        }

        fn hash_context<H: ::std::hash::Hasher>(&self, state: &mut H) {
            ${for fields { ${when CONTEXT_FIELD} ::std::hash::Hash::hash(&self.$fname, state); }}
        }
    }
}
