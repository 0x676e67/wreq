use crate::tls::{Http2Settings, TlsSettings};
use http2::{HEADERS_PSEUDO_ORDER, HEADER_PRORIORITY, SETTINGS_ORDER};
use tls::{ChromeTlsSettings, NEW_CURVES_1, NEW_CURVES_2};

// ============== TLS template ==============
pub fn tls_template_1() -> TlsSettings {
    ChromeTlsSettings::builder().build().into()
}

pub fn tls_template_2() -> TlsSettings {
    ChromeTlsSettings::builder()
        .enable_ech_grease(true)
        .build()
        .into()
}

pub fn tls_template_3() -> TlsSettings {
    ChromeTlsSettings::builder()
        .permute_extensions(true)
        .build()
        .into()
}

pub fn tls_template_4() -> TlsSettings {
    ChromeTlsSettings::builder()
        .permute_extensions(true)
        .enable_ech_grease(true)
        .build()
        .into()
}

pub fn tls_template_5() -> TlsSettings {
    ChromeTlsSettings::builder()
        .permute_extensions(true)
        .enable_ech_grease(true)
        .pre_shared_key(true)
        .build()
        .into()
}

pub fn tls_template_6() -> TlsSettings {
    ChromeTlsSettings::builder()
        .curves(NEW_CURVES_1)
        .permute_extensions(true)
        .pre_shared_key(true)
        .enable_ech_grease(true)
        .build()
        .into()
}

pub fn tls_template_7() -> TlsSettings {
    ChromeTlsSettings::builder()
        .curves(NEW_CURVES_2)
        .permute_extensions(true)
        .pre_shared_key(true)
        .enable_ech_grease(true)
        .build()
        .into()
}

// ============== HTTP template ==============
pub fn http2_template_1() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(6291456)
        .initial_connection_window_size(15728640)
        .max_concurrent_streams(1000)
        .max_header_list_size(262144)
        .header_table_size(65536)
        .headers_priority(HEADER_PRORIORITY)
        .headers_pseudo_order(HEADERS_PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER)
        .build()
}

pub fn http2_template_2() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(6291456)
        .initial_connection_window_size(15728640)
        .max_concurrent_streams(1000)
        .max_header_list_size(262144)
        .header_table_size(65536)
        .enable_push(false)
        .headers_priority(HEADER_PRORIORITY)
        .headers_pseudo_order(HEADERS_PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER)
        .build()
}

pub fn http2_template_3() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(6291456)
        .initial_connection_window_size(15728640)
        .max_header_list_size(262144)
        .header_table_size(65536)
        .enable_push(false)
        .headers_priority(HEADER_PRORIORITY)
        .headers_pseudo_order(HEADERS_PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER)
        .build()
}

// ============== TLS settings ==============
mod tls {
    use crate::tls::impersonate::tls_imports::*;

    pub const CURVES: &[SslCurve] = &[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1];

    pub const NEW_CURVES_1: &[SslCurve] = &[
        SslCurve::X25519_KYBER768_DRAFT00,
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
    ];

    pub const NEW_CURVES_2: &[SslCurve] = &[
        SslCurve::X25519_MLKEM768,
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
    ];

    pub const CIPHER_LIST: &str = static_join!(
        ":",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
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
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512"
    );

    #[derive(TypedBuilder)]
    pub struct ChromeTlsSettings {
        // TLS curves
        #[builder(default = CURVES)]
        curves: &'static [SslCurve],

        // TLS sigalgs list
        #[builder(default = SIGALGS_LIST)]
        sigalgs_list: &'static str,

        // TLS cipher list
        #[builder(default = CIPHER_LIST)]
        cipher_list: &'static str,

        // TLS application_settings extension
        #[builder(default = true, setter(into))]
        application_settings: bool,

        // TLS enable ech grease, https://chromestatus.com/feature/6196703843581952
        #[builder(default = false, setter(into))]
        enable_ech_grease: bool,

        // TLS permute extensions
        #[builder(default = false, setter(into))]
        permute_extensions: bool,

        // TLS pre_shared_key extension
        #[builder(default = false, setter(into))]
        pre_shared_key: bool,
    }

    impl Into<TlsSettings> for ChromeTlsSettings {
        fn into(self) -> TlsSettings {
            TlsSettings::builder()
                .grease_enabled(true)
                .enable_ocsp_stapling(true)
                .enable_signed_cert_timestamps(true)
                .curves(Cow::Borrowed(self.curves))
                .sigalgs_list(Cow::Borrowed(self.sigalgs_list))
                .cipher_list(Cow::Borrowed(self.cipher_list))
                .min_tls_version(Some(Version::TLS_1_2))
                .max_tls_version(Some(Version::TLS_1_3))
                .permute_extensions(self.permute_extensions)
                .pre_shared_key(self.pre_shared_key)
                .enable_ech_grease(self.enable_ech_grease)
                .application_settings(self.application_settings)
                .cert_compression_algorithm(CertCompressionAlgorithm::Brotli)
                .build()
        }
    }
}

// ============== Http2 settings ==============
mod http2 {
    use crate::tls::impersonate::http2_imports::*;

    // ============== http2 headers priority ==============
    pub const HEADER_PRORIORITY: (u32, u8, bool) = (0, 255, true);

    /// ============== http2 headers pseudo order ==============
    pub const HEADERS_PSEUDO_ORDER: [PseudoOrder; 4] = [Method, Authority, Scheme, Path];

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

pub(crate) mod v100 {
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
            "sec-ch-ua",
            HeaderValue::from_static(
                r#"" Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100""#,
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v101 {
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
            "sec-ch-ua",
            HeaderValue::from_static(
                r#"" Not A;Brand";v="99", "Chromium";v="101", "Google Chrome";v="101""#,
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v104 {
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
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Chromium\";v=\"104\", \" Not A;Brand\";v=\"99\", \"Google Chrome\";v=\"104\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v105 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_2())
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
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Google Chrome\";v=\"105\", \"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"105\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v106 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_3())
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
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Chromium\";v=\"106\", \"Google Chrome\";v=\"106\", \"Not;A=Brand\";v=\"99\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v107 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_3())
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
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Chromium\";v=\"107\", \"Google Chrome\";v=\"107\", \"Not;A=Brand\";v=\"99\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v108 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_3())
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
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"108\", \"Google Chrome\";v=\"108\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v109 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_3())
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
            "sec-ch-ua",
            HeaderValue::from_static(
                r#""Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110""#,
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v114 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_3())
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
            "sec-ch-ua",
            HeaderValue::from_static(
                r#""Chromium";v="114", "Not A(Brand";v="30", "Google Chrome";v="114""#,
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Mac OS\""));
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v116 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_4())
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
            "sec-ch-ua",
            HeaderValue::from_static(
                r#""Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116""#,
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v117 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_5())
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
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                r#""Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117""#,
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v118 {
    use crate::tls::impersonate::impersonte_imports::*;
    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_4())
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
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                r#""Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99""#,
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v119 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_4())
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
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=0"));
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                r#""Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24""#,
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_static("en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
        );
        headers
    }
}

pub(crate) mod v120 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_5())
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
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=0"));
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                r#""Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120""#,
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_static("en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
        );
        headers
    }
}

pub(crate) mod v123 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_5())
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
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Google Chrome\";v=\"123\", \"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"123\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("?1"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("same-site"));
        headers.insert("Sec-Fetch-User", HeaderValue::from_static("document"));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("navigate"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US;q=1.0"));
        headers
    }
}

pub(crate) mod v124 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_6())
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
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("?1"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("same-site"));
        headers.insert("Sec-Fetch-User", HeaderValue::from_static("document"));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("navigate"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US;q=1.0"));
        headers
    }
}

pub(crate) mod v126 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_6())
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
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v127 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_6())
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
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\", \"Chromium\";v=\"127\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v128 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_6())
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
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\", \"Google Chrome\";v=\"128\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers
    }
}

pub(crate) mod v129 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_6())
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
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Google Chrome\";v=\"129\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"129\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("priority", HeaderValue::from_static("u=0, i"));
        headers
    }
}

pub(crate) mod v130 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_6())
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
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"));
        headers.insert(
            "sec-purpose",
            HeaderValue::from_static("prefetch;prerender"),
        );
        headers.insert("purpose", HeaderValue::from_static("prefetch"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("priority", HeaderValue::from_static("u=0, i"));
        headers
    }
}

pub(crate) mod v131 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_7())
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
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(DNT, HeaderValue::from_static("1"));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        headers.insert("priority", HeaderValue::from_static("u=0, i"));
        headers
    }
}
