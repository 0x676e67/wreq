use super::impersonate_imports::*;
use http2::*;
use tls::*;

macro_rules! firefox_mod_generator {
    ($mod_name:ident, $tls_template:expr, $http2_template:expr, $header_initializer:ident, $ua:tt) => {
        pub(crate) mod $mod_name {
            use crate::tls::firefox::*;

            #[inline]
            pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
                ImpersonateSettings::builder()
                    .tls($tls_template)
                    .http2($http2_template)
                    .headers(conditional_headers!(with_headers, || {
                        $header_initializer($ua)
                    }))
                    .build()
            }
        }
    };
}

macro_rules! firefox_tls_template {
    (1) => {{
        super::FirefoxTlsSettings::builder()
            .cert_compression_algorithm(Some(super::CERT_COMPRESSION_ALGORITHM))
            .enable_ech_grease(true)
            .pre_shared_key(true)
            .psk_skip_session_tickets(true)
            .key_shares_length_limit(3)
            .build()
            .into()
    }};
    (2) => {{
        super::FirefoxTlsSettings::builder()
            .curves(super::OLD_CURVES)
            .key_shares_length_limit(2)
            .build()
            .into()
    }};
}

macro_rules! firefox_http2_template {
    (1) => {{
        super::Http2Settings::builder()
            .initial_stream_id(3)
            .header_table_size(65536)
            .enable_push(false)
            .initial_stream_window_size(131072)
            .max_frame_size(16384)
            .initial_connection_window_size(12517377 + 65535)
            .headers_priority(super::HEADER_PRIORITY)
            .headers_pseudo_order(super::HEADERS_PSEUDO_ORDER)
            .settings_order(super::SETTINGS_ORDER)
            .build()
    }};
    (2) => {{
        super::Http2Settings::builder()
            .header_table_size(65536)
            .initial_stream_window_size(131072)
            .max_frame_size(16384)
            .initial_connection_window_size(12517377 + 65535)
            .headers_priority((13, 41, false))
            .headers_pseudo_order(super::HEADERS_PSEUDO_ORDER)
            .settings_order(super::SETTINGS_ORDER)
            .build()
    }};
}

// ============== Header initializer ==============
#[inline]
fn header_initializer(ua: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    header_firefox_ua_with_accept!(headers, ua);
    header_firefox_accpet_with_upgrade!(1, headers);
    header_firefox_sec_fetch!(headers);
    header_firefox_priority!(headers);
    headers
}

#[inline]
fn header_initializer_with_zstd(ua: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    header_firefox_ua_with_accept!(headers, ua);
    header_firefox_accpet_with_upgrade!(2, headers);
    header_firefox_sec_fetch!(headers);
    header_firefox_priority!(headers);
    headers
}

// ============== tls settings ==============
mod tls {
    use std::sync::LazyLock;

    use crate::tls::mimic::tls_imports::*;

    pub const OLD_CURVES: &[SslCurve] = &[
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
        SslCurve::SECP521R1,
        SslCurve::FFDHE2048,
        SslCurve::FFDHE3072,
    ];

    pub const CURVES: &[SslCurve] = &[
        SslCurve::X25519_MLKEM768,
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
        SslCurve::SECP521R1,
        SslCurve::FFDHE2048,
        SslCurve::FFDHE3072,
    ];

    pub const CIPHER_LIST: &str = static_join!(
        ":",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA"
    );

    pub const SIGALGS_LIST: &str = static_join!(
        ":",
        "ecdsa_secp256r1_sha256",
        "ecdsa_secp384r1_sha384",
        "ecdsa_secp521r1_sha512",
        "rsa_pss_rsae_sha256",
        "rsa_pss_rsae_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha256",
        "rsa_pkcs1_sha384",
        "rsa_pkcs1_sha512",
        "ecdsa_sha1",
        "rsa_pkcs1_sha1"
    );

    pub const CERT_COMPRESSION_ALGORITHM: &[CertCompressionAlgorithm] = &[
        CertCompressionAlgorithm::Zlib,
        CertCompressionAlgorithm::Brotli,
        CertCompressionAlgorithm::Zstd,
    ];

    pub const DELEGATED_CREDENTIALS: &str = static_join!(
        ":",
        "ecdsa_secp256r1_sha256",
        "ecdsa_secp384r1_sha384",
        "ecdsa_secp521r1_sha512",
        "ecdsa_sha1"
    );

    pub const RECORD_SIZE_LIMIT: u16 = 0x4001;

    pub const EXTENSIONS: &[ExtensionType] = &[
        ExtensionType::SERVER_NAME,
        ExtensionType::EXTENDED_MASTER_SECRET,
        ExtensionType::RENEGOTIATE,
        ExtensionType::SUPPORTED_GROUPS,
        ExtensionType::EC_POINT_FORMATS,
        ExtensionType::SESSION_TICKET,
        ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        ExtensionType::STATUS_REQUEST,
        ExtensionType::DELEGATED_CREDENTIAL,
        ExtensionType::KEY_SHARE,
        ExtensionType::SUPPORTED_VERSIONS,
        ExtensionType::SIGNATURE_ALGORITHMS,
        ExtensionType::PSK_KEY_EXCHANGE_MODES,
        ExtensionType::RECORD_SIZE_LIMIT,
        ExtensionType::CERT_COMPRESSION,
        ExtensionType::ENCRYPTED_CLIENT_HELLO,
    ];

    pub static EXTENSION_PERMUTATION_INDICES: LazyLock<[u8; EXTENSIONS.len()]> =
        LazyLock::new(|| {
            let mut indices = [0u8; EXTENSIONS.len()];
            for (i, &ext) in EXTENSIONS.iter().enumerate() {
                if let Some(idx) = ExtensionType::BORING_SSLEXTENSION_PERMUTATION
                    .iter()
                    .position(|&e| e == ext)
                {
                    indices[i] = idx as u8;
                }
            }
            indices
        });

    #[derive(TypedBuilder)]
    pub struct FirefoxTlsSettings {
        // TLS curves
        #[builder(default = CURVES)]
        curves: &'static [SslCurve],

        // TLS sigalgs list
        #[builder(default = SIGALGS_LIST)]
        sigalgs_list: &'static str,

        // TLS cipher list
        #[builder(default = CIPHER_LIST)]
        cipher_list: &'static str,

        // TLS enable ech grease, https://chromestatus.com/feature/6196703843581952
        #[builder(default = false, setter(into))]
        enable_ech_grease: bool,

        // TLS pre_shared_key extension
        #[builder(default = false, setter(into))]
        pre_shared_key: bool,

        // Pre shared key skip session tickets
        #[builder(default = false, setter(into))]
        psk_skip_session_tickets: bool,

        // TLS delegated credentials extension
        #[builder(default = DELEGATED_CREDENTIALS, setter(into))]
        delegated_credentials: &'static str,

        // TLS record size limit
        #[builder(default = RECORD_SIZE_LIMIT, setter(into))]
        record_size_limit: u16,

        // TLS enable three key shares
        #[builder(default, setter(into))]
        key_shares_length_limit: Option<u8>,

        // TLS cert compression algorithm
        #[builder(default, setter(into))]
        cert_compression_algorithm: Option<&'static [CertCompressionAlgorithm]>,

        // TLS extension permutation
        #[builder(default = &*EXTENSION_PERMUTATION_INDICES, setter(into))]
        extension_permutation_indices: &'static [u8],
    }

    impl From<FirefoxTlsSettings> for TlsSettings {
        fn from(val: FirefoxTlsSettings) -> Self {
            TlsSettings::builder()
                .curves(Cow::Borrowed(val.curves))
                .sigalgs_list(Cow::Borrowed(val.sigalgs_list))
                .cipher_list(Cow::Borrowed(val.cipher_list))
                .delegated_credentials(Cow::Borrowed(val.delegated_credentials))
                .record_size_limit(val.record_size_limit)
                .enable_ocsp_stapling(true)
                .enable_ech_grease(val.enable_ech_grease)
                .alpn_protos(HttpVersionPref::All)
                .cert_compression_algorithm(val.cert_compression_algorithm.map(Cow::Borrowed))
                .min_tls_version(TlsVersion::TLS_1_2)
                .max_tls_version(TlsVersion::TLS_1_3)
                .key_shares_length_limit(val.key_shares_length_limit)
                .pre_shared_key(val.pre_shared_key)
                .psk_skip_session_ticket(val.psk_skip_session_tickets)
                .extension_permutation_indices(Cow::Borrowed(val.extension_permutation_indices))
                .build()
        }
    }
}

// ============== http2 settings ==============
mod http2 {
    use crate::tls::mimic::http2_imports::*;

    // ============== http2 headers priority ==============
    pub const HEADER_PRIORITY: (u32, u8, bool) = (0, 41, false);

    /// ============== http2 headers pseudo order ==============
    pub const HEADERS_PSEUDO_ORDER: [PseudoOrder; 4] = [Method, Path, Authority, Scheme];

    /// ============== http2 settings frame order ==============
    pub const SETTINGS_ORDER: [SettingsOrder; 8] = [
        HeaderTableSize,
        EnablePush,
        MaxConcurrentStreams,
        InitialWindowSize,
        MaxFrameSize,
        MaxHeaderListSize,
        UnknownSetting8,
        UnknownSetting9,
    ];
}

firefox_mod_generator!(
    ff133,
    firefox_tls_template!(1),
    firefox_http2_template!(1),
    header_initializer_with_zstd,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0"
);

firefox_mod_generator!(
    ff109,
    firefox_tls_template!(2),
    firefox_http2_template!(2),
    header_initializer,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
);
