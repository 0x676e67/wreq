use crate::tls::Http2Settings;
use http::{
    header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT},
    HeaderMap, HeaderValue,
};
use http2::{
    HEADERS_PSEUDO_ORDER, HEADER_PRIORITY, NEW_HEADERS_PSEUDO_ORDER, NEW_HEADER_PRIORITY,
    NEW_SETTINGS_ORDER, SETTINGS_ORDER,
};
use tls::SafariTlsSettings;
// ============== Headers ==============
#[inline]
fn header_initializer_for_16_17(ua: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
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
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
    headers
}

// ============== TLS settings ==============
mod tls {
    use crate::tls::impersonate::tls_imports::*;

    pub const CURVES: &[SslCurve] = &[
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
        SslCurve::SECP521R1,
    ];

    pub const CIPHER_LIST: &str = static_join!(
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

    pub const NEW_CIPHER_LIST: &str = static_join!(
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

    pub const SIGALGS_LIST: &str = static_join!(
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

    pub const NEW_SIGALGS_LIST: &str = static_join!(
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

    impl Into<TlsSettings> for SafariTlsSettings {
        fn into(self) -> TlsSettings {
            TlsSettings::builder()
                .session_ticket(false)
                .grease_enabled(true)
                .enable_ocsp_stapling(true)
                .enable_signed_cert_timestamps(true)
                .curves(Cow::Borrowed(self.curves))
                .sigalgs_list(Cow::Borrowed(self.sigalgs_list))
                .cipher_list(Cow::Borrowed(self.cipher_list))
                .min_tls_version(TlsVersion::TLS_1_0)
                .cert_compression_algorithm(CertCompressionAlgorithm::Zlib)
                .build()
        }
    }

    #[macro_export]
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
}

// ============== Http2 settings ==============
mod http2 {
    use crate::tls::impersonate::http2_imports::*;

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

    #[macro_export]
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
}

pub(crate) mod safari15_3 {
    use super::tls::CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_15};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, CIPHER_LIST))
            .http2(safari_http2_template!(4))
            .headers(conditional_headers!(with_headers, header_initializer_for_15, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15"))
            .build()
    }
}

pub(crate) mod safari15_5 {
    use super::tls::CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_15};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, CIPHER_LIST))
            .http2(safari_http2_template!(4))
            .headers(conditional_headers!(with_headers, header_initializer_for_15, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15"))
            .build()
    }
}

pub(crate) mod safari15_6_1 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_15};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(4))
            .headers(conditional_headers!(with_headers, header_initializer_for_15, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15"))
            .build()
    }
}

pub(crate) mod safari16 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_16_17};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(4))
            .headers(conditional_headers!(with_headers, header_initializer_for_16_17, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"))
            .build()
    }
}

pub(crate) mod safari16_5 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_16_17};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(4))
            .headers(conditional_headers!(with_headers, header_initializer_for_16_17, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15"))
            .build()
    }
}

pub(crate) mod safari17_0 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_16_17};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(5))
            .headers(conditional_headers!(with_headers, header_initializer_for_16_17, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"))
            .build()
    }
}

pub(crate) mod safari17_2_1 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_16_17};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(5))
            .headers(conditional_headers!(with_headers, header_initializer_for_16_17, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"))
            .build()
    }
}

pub(crate) mod safari17_4_1 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_16_17};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(4))
            .headers(conditional_headers!(with_headers, header_initializer_for_16_17, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"))
            .build()
    }
}

pub(crate) mod safari17_5 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_16_17};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(5))
            .headers(conditional_headers!(with_headers, header_initializer_for_16_17, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"))
            .build()
    }
}

pub(crate) mod safari18 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_18};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(3))
            .headers(conditional_headers!(with_headers, header_initializer_for_18, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"))
            .build()
    }
}

pub(crate) mod safari18_2 {
    use super::tls::{NEW_CIPHER_LIST, NEW_SIGALGS_LIST};
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_18};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(2, NEW_CIPHER_LIST, NEW_SIGALGS_LIST))
            .http2(safari_http2_template!(3))
            .headers(conditional_headers!(with_headers, header_initializer_for_18, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15"))
            .build()
    }
}

pub(crate) mod safari_ios_16_5 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_16_17};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(1))
            .headers(conditional_headers!(with_headers, header_initializer_for_16_17, "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1"))
            .build()
    }
}

pub(crate) mod safari_ios_17_2 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_16_17};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(2))
            .headers(conditional_headers!(with_headers, header_initializer_for_16_17, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"))
            .build()
    }
}

pub(crate) mod safari_ios_17_4_1 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_16_17};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(2))
            .headers(conditional_headers!(with_headers, header_initializer_for_16_17, "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1"))
            .build()
    }
}

pub(crate) mod safari_ipad_18 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_18};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(3))
            .headers(conditional_headers!(with_headers, header_initializer_for_18, "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"))
            .build()
    }
}

pub(crate) mod safari_ios_18_1_1 {
    use super::tls::NEW_CIPHER_LIST;
    use crate::tls::{impersonate::impersonate_imports::*, safari::header_initializer_for_18};

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(safari_tls_template!(1, NEW_CIPHER_LIST))
            .http2(safari_http2_template!(3))
            .headers(conditional_headers!(with_headers, header_initializer_for_18, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/15E148 Safari/604.1"))
            .build()
    }
}
