use crate::tls::{Http2Settings, TlsSettings};
use http2::{HEADERS_PSEUDO_ORDER, HEADER_PRORIORITY, SETTINGS_ORDER};
use tls::{EdgeTlsSettings, NEW_CURVES};

// ============== TLS template ==============
pub fn tls_template_1() -> TlsSettings {
    EdgeTlsSettings::builder().build().into()
}

pub fn tls_template_2() -> TlsSettings {
    EdgeTlsSettings::builder()
        .permute_extensions(true)
        .pre_shared_key(true)
        .enable_ech_grease(true)
        .build()
        .into()
}

pub fn tls_template_3() -> TlsSettings {
    EdgeTlsSettings::builder()
        .curves(NEW_CURVES)
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

    pub const NEW_CURVES: &[SslCurve] = &[
        SslCurve::X25519_KYBER768_DRAFT00,
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
    pub struct EdgeTlsSettings {
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

    impl Into<TlsSettings> for EdgeTlsSettings {
        fn into(self) -> TlsSettings {
            TlsSettings::builder()
                .grease_enabled(true)
                .enable_ocsp_stapling(true)
                .enable_signed_cert_timestamps(true)
                .curves(Cow::Borrowed(self.curves))
                .sigalgs_list(Cow::Borrowed(self.sigalgs_list))
                .cipher_list(Cow::Borrowed(self.cipher_list))
                .min_tls_version(Version::TLS_1_2)
                .max_tls_version(Version::TLS_1_3)
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
    pub static SETTINGS_ORDER: [SettingsOrder; 8] = [
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

pub(crate) mod edge101 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_1())
            .http2(super::http2_template_1())
            .headers(conditional_headers!(with_headers, header_initializer))
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                r#"" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101""#,
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "sec-ch-ua-platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
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

pub(crate) mod edge122 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_2())
            .http2(super::http2_template_2())
            .headers(conditional_headers!(with_headers, header_initializer))
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"Microsoft Edge\";v=\"122\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"));
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

pub(crate) mod edge127 {
    use crate::tls::impersonate::impersonte_imports::*;

    #[inline]
    pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
        ImpersonateSettings::builder()
            .tls(super::tls_template_3())
            .http2(super::http2_template_2())
            .headers(conditional_headers!(with_headers, header_initializer))
            .build()
    }

    #[inline]
    fn header_initializer() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                "\"Not)A;Brand\";v=\"99\", \"Microsoft Edge\";v=\"127\", \"Chromium\";v=\"127\"",
            ),
        );
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0"));
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
