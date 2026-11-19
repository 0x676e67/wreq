macro_rules! set_bool {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        if $cfg.$field {
            $conn.$setter();
        }
    };
}

macro_rules! set_option {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        if let Some(val) = $cfg.$field {
            $conn.$setter(val);
        }
    };
    // Optional feature switches invert the backend's NO_* disable flags.
    ($cfg:expr, !$field:ident, $conn:expr, $flag:expr) => {
        match $cfg.$field {
            Some(false) => {
                $conn.set_options($flag);
            }
            Some(true) => {
                $conn.clear_options($flag);
            }
            None => {}
        }
    };
}

macro_rules! set_option_ref_try {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        $crate::tls::macros::set_option_ref_try!($cfg, $field, $conn, $setter, $crate::Error::tls);
    };
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident, $map_err:expr) => {
        if let Some(val) = $cfg.$field.as_ref() {
            $conn.$setter(val).map_err($map_err)?;
        }
    };
}

/// Applies ClientHello options shared by TCP/Unix and QUIC contexts.
///
/// Call order affects the ClientHello fingerprint: `all` includes stream-only options in place,
/// while `common` omits them.
#[allow(unused_macro_rules, reason = "A build may use only one setter mode")]
macro_rules! set_hello_options {
    (@all $($setter:tt)*) => {
        $($setter)*
    };
    (@common $($setter:tt)*) => {};
    ($mode:ident, $cfg:expr, $conn:expr) => {{
        use $crate::tls::macros::{set_bool, set_option, set_option_ref_try};
        use ::btls::ssl::SslOptions;

        $crate::tls::set_ech_grease_policy($conn, $cfg.ech_grease);
        set_bool!($cfg, enable_ocsp_stapling, $conn, enable_ocsp_stapling);
        set_bool!(
            $cfg,
            enable_signed_cert_timestamps,
            $conn,
            enable_signed_cert_timestamps
        );
        $crate::tls::macros::set_hello_options!(@$mode
            set_option!($cfg, !session_ticket, $conn, SslOptions::NO_TICKET)
        );
        set_option!($cfg, !psk_dhe_ke, $conn, SslOptions::NO_PSK_DHE_KE);
        $crate::tls::macros::set_hello_options!(@$mode
            set_option!($cfg, !renegotiation, $conn, SslOptions::NO_RENEGOTIATION)
        );
        set_option!($cfg, grease_enabled, $conn, set_grease_enabled);
        set_option!(
            $cfg,
            grease_sigalgs_enabled,
            $conn,
            set_grease_sigalgs_enabled
        );
        set_option!($cfg, permute_extensions, $conn, set_permute_extensions);
        set_option_ref_try!($cfg, curves_list, $conn, set_curves_list);
        set_option_ref_try!($cfg, sigalgs_list, $conn, set_sigalgs_list);
        $crate::tls::macros::set_hello_options!(@$mode
            set_option_ref_try!($cfg, cipher_list, $conn, set_cipher_list)
        );
        set_option_ref_try!($cfg, tls13_cipher_list, $conn, set_tls13_ciphers);
        $cfg.certificate_compressors.register($conn).map_err($crate::Error::tls)?;
        set_option_ref_try!(
            $cfg,
            delegated_credentials,
            $conn,
            set_delegated_credentials
        );
        set_option!($cfg, record_size_limit, $conn, set_record_size_limit);
        // An empty requested list differs from omitting the extension.
        set_option_ref_try!($cfg, trust_anchors, $conn, set_requested_trust_anchors);
        set_option_ref_try!(
            $cfg,
            extension_permutation,
            $conn,
            set_extension_permutation
        );
    }};
}

derive_deftly::define_derive_deftly! {
    /// Derives `PartialEq`, `Eq`, `Hash`, and both `KeyIdentity` impls (context and session)
    /// for TLS option structs.
    ///
    /// Unmarked fields participate in all three scopes (pool, session, and compiled context).
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

    impl<'h> $crate::tls::KeyIdentity<dyn ::std::any::Any, dyn ::std::hash::Hasher + 'h> for $ttype {
        fn same(&self, other: &dyn ::std::any::Any) -> bool {
            other.downcast_ref::<Self>().is_some_and(|other| {
                ::std::ptr::eq(self, other)
                    || (true ${for fields { ${when SESSION_FIELD} && self.$fname == other.$fname }})
            })
        }

        fn hash_key(&self, mut state: &mut (dyn ::std::hash::Hasher + 'h)) {
            ${for fields { ${when SESSION_FIELD} ::std::hash::Hash::hash(&self.$fname, &mut state); }}
        }
    }

    ${if tmeta(tls_key(quic)) {
        impl $ttype {
            #[must_use]
            pub(crate) fn same_transport(&self, other: &Self) -> bool {
                true ${for fields { ${when fmeta(tls_key(transport))} && self.$fname == other.$fname }}
            }
        }
    }}

    impl $crate::tls::KeyIdentity for $ttype {
        fn same(&self, other: &Self) -> bool {
            ::std::ptr::eq(self, other)
                || (true ${for fields { ${when CONTEXT_FIELD} && self.$fname == other.$fname }})
        }

        fn hash_key(
            &self,
            state: &mut <::lru::DefaultHasher as ::std::hash::BuildHasher>::Hasher,
        ) {
            ${for fields { ${when CONTEXT_FIELD} ::std::hash::Hash::hash(&self.$fname, state); }}
        }
    }
}

pub(crate) use derive_deftly_template_TlsKey;
pub(crate) use set_bool;
pub(crate) use set_hello_options;
pub(crate) use set_option;
pub(crate) use set_option_ref_try;
