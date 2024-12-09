use crate::tls::{Http2Settings, TlsSettings};
use http2::{
    HEADERS_PSEUDO_ORDER, HEADER_PRORIORITY, NEW_HEADERS_PSEUDO_ORDER, NEW_HEADER_PRORIORITY,
    NEW_SETTINGS_ORDER, SETTINGS_ORDER,
};
use tls::{SafariTlsSettings, CIPHER_LIST, NEW_CIPHER_LIST};

// ============== TLS template ==============
pub fn tls_template_1() -> TlsSettings {
    SafariTlsSettings::builder()
        .cipher_list(NEW_CIPHER_LIST)
        .build()
        .into()
}

pub fn tls_template_2() -> TlsSettings {
    SafariTlsSettings::builder()
        .cipher_list(CIPHER_LIST)
        .build()
        .into()
}

// ============== HTTP template ==============
pub fn http2_template_1() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(2097152)
        .initial_connection_window_size(10551295)
        .max_concurrent_streams(100)
        .headers_priority(HEADER_PRORIORITY)
        .headers_pseudo_order(HEADERS_PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER)
        .build()
}

pub fn http2_template_2() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(2097152)
        .initial_connection_window_size(10551295)
        .max_concurrent_streams(100)
        .enable_push(false)
        .headers_priority(HEADER_PRORIORITY)
        .headers_pseudo_order(HEADERS_PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER)
        .build()
}

pub fn http2_template_3() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(2097152)
        .initial_connection_window_size(10485760)
        .max_concurrent_streams(100)
        .enable_push(false)
        .unknown_setting8(true)
        .unknown_setting9(true)
        .headers_priority(NEW_HEADER_PRORIORITY)
        .headers_pseudo_order(NEW_HEADERS_PSEUDO_ORDER)
        .settings_order(NEW_SETTINGS_ORDER)
        .build()
}

pub fn http2_template_4() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(4194304)
        .initial_connection_window_size(10551295)
        .max_concurrent_streams(100)
        .headers_priority(HEADER_PRORIORITY)
        .headers_pseudo_order(HEADERS_PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER)
        .build()
}

pub fn http2_template_5() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(4194304)
        .initial_connection_window_size(10551295)
        .max_concurrent_streams(100)
        .enable_push(false)
        .headers_priority(HEADER_PRORIORITY)
        .headers_pseudo_order(HEADERS_PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER)
        .build()
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
                .min_tls_version(Some(Version::TLS_1_0))
                .cert_compression_algorithm(CertCompressionAlgorithm::Zlib)
                .build()
        }
    }
}

// ============== Http2 settings ==============
mod http2 {
    use crate::tls::impersonate::http2_imports::*;

    // ============== http2 headers priority ==============
    pub const HEADER_PRORIORITY: (u32, u8, bool) = (0, 255, true);
    pub const NEW_HEADER_PRORIORITY: (u32, u8, bool) = (0, 255, false);

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

pub(crate) mod safari15_3 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_2())
            .http2(super::http2_template_4())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers
    }
}

pub(crate) mod safari15_5 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_2())
            .http2(super::http2_template_4())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers
    }
}

pub(crate) mod safari15_6_1 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_4())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers
    }
}

pub(crate) mod safari16 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_4())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers
    }
}

pub(crate) mod safari16_5 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_4())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers
    }
}

pub(crate) mod safari17_0 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_5())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers
    }
}

pub(crate) mod safari17_2_1 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_5())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers
    }
}

pub(crate) mod safari17_4_1 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_4())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers
    }
}

pub(crate) mod safari17_5 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_5())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers
    }
}

pub(crate) mod safari18 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_3())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
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
}

pub(crate) mod safari_ios_16_5 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_1())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers
    }
}

pub(crate) mod safari_ios_17_2 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_2())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers
    }
}

pub(crate) mod safari_ios_17_4_1 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_2())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers
    }
}

pub(crate) mod safari_ipad_18 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_3())
            .headers(if with_headers {
                static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(header_initializer);
                Some(Cow::Borrowed(&*HEADER_INITIALIZER))
            } else {
                None
            })
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("some-origin"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("priority", HeaderValue::from_static("u=0, i"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers
    }
}
