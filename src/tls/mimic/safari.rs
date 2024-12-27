use super::impersonate_imports::*;
use http2::*;
use tls::*;

macro_rules! safari_mod_generator {
    ($mod_name:ident, $tls_template:expr, $http2_template:expr, $header_initializer:ident, $ua:expr) => {
        pub(crate) mod $mod_name {
            use crate::tls::{mimic::impersonate_imports::*, safari::*};

            #[inline]
            pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
                ImpersonateSettings::builder()
                    .tls($tls_template)
                    .http2($http2_template)
                    .headers(conditional_headers!(with_headers, $header_initializer, $ua))
                    .build()
            }
        }
    };
}

macro_rules! safari_tls_template {
    (1, $cipher_list:expr) => {{
        super::SafariTlsSettings::builder()
            .cipher_list($cipher_list)
            .build()
            .into()
    }};
    (2, $cipher_list:expr, $sigalgs_list:expr) => {{
        super::SafariTlsSettings::builder()
            .cipher_list($cipher_list)
            .sigalgs_list($sigalgs_list)
            .build()
            .into()
    }};
}

macro_rules! safari_http2_template {
    (1) => {{
        super::Http2Settings::builder()
            .initial_stream_window_size(2097152)
            .initial_connection_window_size(10551295)
            .max_concurrent_streams(100)
            .headers_priority(super::HEADER_PRIORITY)
            .headers_pseudo_order(super::HEADERS_PSEUDO_ORDER)
            .settings_order(super::SETTINGS_ORDER)
            .build()
    }};
    (2) => {{
        super::Http2Settings::builder()
            .initial_stream_window_size(2097152)
            .initial_connection_window_size(10551295)
            .max_concurrent_streams(100)
            .enable_push(false)
            .headers_priority(super::HEADER_PRIORITY)
            .headers_pseudo_order(super::HEADERS_PSEUDO_ORDER)
            .settings_order(super::SETTINGS_ORDER)
            .build()
    }};
    (3) => {{
        super::Http2Settings::builder()
            .initial_stream_window_size(2097152)
            .initial_connection_window_size(10485760)
            .max_concurrent_streams(100)
            .enable_push(false)
            .unknown_setting8(true)
            .unknown_setting9(true)
            .headers_priority(super::NEW_HEADER_PRIORITY)
            .headers_pseudo_order(super::NEW_HEADERS_PSEUDO_ORDER)
            .settings_order(super::NEW_SETTINGS_ORDER)
            .build()
    }};
    (4) => {{
        super::Http2Settings::builder()
            .initial_stream_window_size(4194304)
            .initial_connection_window_size(10551295)
            .max_concurrent_streams(100)
            .headers_priority(super::HEADER_PRIORITY)
            .headers_pseudo_order(super::HEADERS_PSEUDO_ORDER)
            .settings_order(super::SETTINGS_ORDER)
            .build()
    }};
    (5) => {{
        super::Http2Settings::builder()
            .initial_stream_window_size(4194304)
            .initial_connection_window_size(10551295)
            .max_concurrent_streams(100)
            .enable_push(false)
            .headers_priority(super::HEADER_PRIORITY)
            .headers_pseudo_order(super::HEADERS_PSEUDO_ORDER)
            .settings_order(super::SETTINGS_ORDER)
            .build()
    }};
}

// ============== Headers ==============
#[inline]
fn header_initializer_for_16_17(ua: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    #[cfg(all(feature = "gzip", feature = "deflate", feature = "brotli"))]
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert(USER_AGENT, HeaderValue::from_static(ua));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    headers
}

#[inline]
fn header_initializer_for_15(ua: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(ua));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    #[cfg(all(feature = "gzip", feature = "deflate", feature = "brotli"))]
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
    headers
}

#[inline]
fn header_initializer_for_18(ua: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    headers.insert(USER_AGENT, HeaderValue::from_static(ua));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert("priority", HeaderValue::from_static("u=0, i"));
    #[cfg(all(feature = "gzip", feature = "deflate", feature = "brotli"))]
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
    headers
}

// ============== TLS settings ==============
mod tls {
    use crate::tls::mimic::tls_imports::*;

    pub const CURVES: &[SslCurve] = &[
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
        SslCurve::SECP521R1,
    ];

    pub const CIPHER_LIST: &str = join!(
        ":",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    );

    pub const NEW_CIPHER_LIST: &str = join!(
        ":",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    );

    pub const SIGALGS_LIST: &str = join!(
        ":",
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "ecdsa_sha1",
        "rsa_pss_rsae_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1"
    );

    pub const NEW_SIGALGS_LIST: &str = join!(
        ":",
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1"
    );

    pub const CERT_COMPRESSION_ALGORITHM: &[CertCompressionAlgorithm] =
        &[CertCompressionAlgorithm::Zlib];

    #[derive(TypedBuilder)]
    pub struct SafariTlsSettings {
        // TLS curves
        #[builder(default = CURVES)]
        curves: &'static [SslCurve],

        // TLS sigalgs list
        #[builder(default = SIGALGS_LIST)]
        sigalgs_list: &'static str,

        // TLS cipher list
        cipher_list: &'static str,
    }

    impl From<SafariTlsSettings> for TlsSettings {
        fn from(val: SafariTlsSettings) -> Self {
            TlsSettings::builder()
                .session_ticket(false)
                .grease_enabled(true)
                .enable_ocsp_stapling(true)
                .enable_signed_cert_timestamps(true)
                .curves(Cow::Borrowed(val.curves))
                .sigalgs_list(Cow::Borrowed(val.sigalgs_list))
                .cipher_list(Cow::Borrowed(val.cipher_list))
                .min_tls_version(TlsVersion::TLS_1_0)
                .cert_compression_algorithm(Cow::Borrowed(CERT_COMPRESSION_ALGORITHM))
                .build()
        }
    }
}

// ============== Http2 settings ==============
mod http2 {
    use crate::tls::mimic::http2_imports::*;

    // ============== http2 headers priority ==============
    pub const HEADER_PRIORITY: (u32, u8, bool) = (0, 255, true);
    pub const NEW_HEADER_PRIORITY: (u32, u8, bool) = (0, 255, false);

    /// ============== http2 headers pseudo order ==============
    pub const HEADERS_PSEUDO_ORDER: [PseudoOrder; 4] = [Method, Scheme, Path, Authority];
    pub const NEW_HEADERS_PSEUDO_ORDER: [PseudoOrder; 4] = [Method, Scheme, Authority, Path];

    /// ============== http2 settings frame order ==============
    pub const SETTINGS_ORDER: [SettingsOrder; 8] = [
        HeaderTableSize,
        EnablePush,
        InitialWindowSize,
        MaxConcurrentStreams,
        MaxFrameSize,
        MaxHeaderListSize,
        UnknownSetting8,
        UnknownSetting9,
    ];
    pub const NEW_SETTINGS_ORDER: [SettingsOrder; 8] = [
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

safari_mod_generator!(
    safari15_3,
    safari_tls_template!(1, CIPHER_LIST),
    safari_http2_template!(4),
    header_initializer_for_15,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15"
);

safari_mod_generator!(
    safari15_5,
    safari_tls_template!(1, CIPHER_LIST),
    safari_http2_template!(4),
    header_initializer_for_15,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15"
);

safari_mod_generator!(
    safari15_6_1,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(4),
    header_initializer_for_15,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15"
);

safari_mod_generator!(
    safari16,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(4),
    header_initializer_for_16_17,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
);

safari_mod_generator!(
    safari16_5,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(4),
    header_initializer_for_16_17,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15"
);

safari_mod_generator!(
    safari_ios_16_5,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(1),
    header_initializer_for_16_17,
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1"
);

safari_mod_generator!(
    safari17_0,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(5),
    header_initializer_for_16_17,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
);

safari_mod_generator!(
    safari17_2_1,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(5),
    header_initializer_for_16_17,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
);

safari_mod_generator!(
    safari17_4_1,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(4),
    header_initializer_for_16_17,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"
);

safari_mod_generator!(
    safari17_5,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(5),
    header_initializer_for_16_17,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
);

safari_mod_generator!(
    safari_ios_17_2,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(2),
    header_initializer_for_16_17,
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
);

safari_mod_generator!(
    safari_ios_17_4_1,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(2),
    header_initializer_for_16_17,
    "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1"
);

safari_mod_generator!(
    safari_ipad_18,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(3),
    header_initializer_for_18,
    "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
);

safari_mod_generator!(
    safari18,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(3),
    header_initializer_for_18,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
);

safari_mod_generator!(
    safari_ios_18_1_1,
    safari_tls_template!(1, NEW_CIPHER_LIST),
    safari_http2_template!(3),
    header_initializer_for_18,
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/15E148 Safari/604.1"
);

safari_mod_generator!(
    safari18_2,
    safari_tls_template!(2, NEW_CIPHER_LIST, NEW_SIGALGS_LIST),
    safari_http2_template!(3),
    header_initializer_for_18,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15"
);
