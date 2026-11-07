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
        set_option_ref_try!($cfg, $field, $conn, $setter, Error::tls);
    };
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident, $map_err:expr) => {
        if let Some(val) = $cfg.$field.as_ref() {
            $conn.$setter(val).map_err($map_err)?;
        }
    };
}

/// Applies the ClientHello setters shared by TCP and QUIC contexts. The call order is part of
/// the fingerprint: `tcp` also runs the TCP-only setters in place, and `quic` skips them.
#[cfg_attr(
    not(feature = "http3"),
    allow(unused_macro_rules, reason = "Only QUIC skips the TCP-only setters")
)]
macro_rules! set_hello_options {
    (@tcp $($setter:tt)*) => {
        $($setter)*
    };
    (@quic $($setter:tt)*) => {};
    ($transport:ident, $cfg:expr, $conn:expr) => {
        set_ech_grease_policy($conn, $cfg.ech_grease);
        set_bool!($cfg, enable_ocsp_stapling, $conn, enable_ocsp_stapling);
        set_bool!(
            $cfg,
            enable_signed_cert_timestamps,
            $conn,
            enable_signed_cert_timestamps
        );
        set_hello_options!(@$transport
            set_option!($cfg, !session_ticket, $conn, SslOptions::NO_TICKET)
        );
        set_option!($cfg, !psk_dhe_ke, $conn, SslOptions::NO_PSK_DHE_KE);
        set_hello_options!(@$transport
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
        set_hello_options!(@$transport
            set_option_ref_try!($cfg, cipher_list, $conn, set_cipher_list)
        );
        set_option_ref_try!($cfg, tls13_cipher_list, $conn, set_tls13_ciphers);
        set_option_ref_try!($cfg, certificate_compressors, $conn, set_cert_compressors);
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
    };
}
