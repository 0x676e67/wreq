use crate::mimic::impersonate_imports::*;
use http2::*;
use tls::*;

macro_rules! mod_generator {
    ($mod_name:ident, $tls_template:expr, $http2_template:expr, $header_initializer:ident, $sec_ch_ua:tt, $ua:tt) => {
        pub(crate) mod $mod_name {
            use super::*;

            #[inline]
            pub fn get_settings(with_headers: bool) -> ImpersonateSettings {
                ImpersonateSettings::builder()
                    .tls($tls_template)
                    .http2($http2_template)
                    .headers(conditional_headers!(with_headers, || {
                        $header_initializer($sec_ch_ua, $ua)
                    }))
                    .build()
            }
        }
    };
}

macro_rules! tls_settings {
    (1) => {{
        super::ChromeTlsSettings::builder().build().into()
    }};
    (2) => {{
        super::ChromeTlsSettings::builder()
            .enable_ech_grease(true)
            .build()
            .into()
    }};
    (3) => {{
        super::ChromeTlsSettings::builder()
            .permute_extensions(true)
            .build()
            .into()
    }};
    (4) => {{
        super::ChromeTlsSettings::builder()
            .permute_extensions(true)
            .enable_ech_grease(true)
            .build()
            .into()
    }};
    (5) => {{
        super::ChromeTlsSettings::builder()
            .permute_extensions(true)
            .enable_ech_grease(true)
            .pre_shared_key(true)
            .build()
            .into()
    }};
    (6, $curves:expr) => {{
        super::ChromeTlsSettings::builder()
            .curves($curves)
            .permute_extensions(true)
            .pre_shared_key(true)
            .enable_ech_grease(true)
            .build()
            .into()
    }};
}

macro_rules! http2_settings {
    (1) => {{
        super::Http2Settings::builder()
            .initial_stream_window_size(6291456)
            .initial_connection_window_size(15728640)
            .max_concurrent_streams(1000)
            .max_header_list_size(262144)
            .header_table_size(65536)
            .headers_priority(super::HEADER_PRIORITY)
            .headers_pseudo_order(super::HEADERS_PSEUDO_ORDER)
            .settings_order(super::SETTINGS_ORDER)
            .build()
    }};
    (2) => {{
        super::Http2Settings::builder()
            .initial_stream_window_size(6291456)
            .initial_connection_window_size(15728640)
            .max_concurrent_streams(1000)
            .max_header_list_size(262144)
            .header_table_size(65536)
            .enable_push(false)
            .headers_priority(super::HEADER_PRIORITY)
            .headers_pseudo_order(super::HEADERS_PSEUDO_ORDER)
            .settings_order(super::SETTINGS_ORDER)
            .build()
    }};
    (3) => {{
        super::Http2Settings::builder()
            .initial_stream_window_size(6291456)
            .initial_connection_window_size(15728640)
            .max_header_list_size(262144)
            .header_table_size(65536)
            .enable_push(false)
            .headers_priority(super::HEADER_PRIORITY)
            .headers_pseudo_order(super::HEADERS_PSEUDO_ORDER)
            .settings_order(super::SETTINGS_ORDER)
            .build()
    }};
}

#[inline]
fn header_initializer(sec_ch_ua: &'static str, ua: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    header_chrome_accpet!(headers);
    header_chrome_sec_ch_ua!(headers, sec_ch_ua);
    header_chrome_sec_fetch!(headers);
    header_chrome_ua!(headers, ua);
    headers
}

#[inline]
fn header_initializer_with_zstd(sec_ch_ua: &'static str, ua: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    header_chrome_accpet!(zstd, headers);
    header_chrome_sec_ch_ua!(headers, sec_ch_ua);
    header_chrome_sec_fetch!(headers);
    header_chrome_ua!(headers, ua);
    headers
}

#[inline]
fn header_initializer_with_zstd_priority(sec_ch_ua: &'static str, ua: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    header_chrome_accpet!(zstd, headers);
    headers.insert("priority", HeaderValue::from_static("u=0, i"));
    header_chrome_sec_ch_ua!(headers, sec_ch_ua);
    header_chrome_sec_fetch!(headers);
    header_chrome_ua!(headers, ua);
    headers
}

mod tls {
    use crate::{mimic::tls_imports::*, tls::AlpsProto};

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

    pub const CIPHER_LIST: &str = join!(
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

    pub const SIGALGS_LIST: &str = join!(
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

    pub const CERT_COMPRESSION_ALGORITHM: &[CertCompressionAlgorithm] =
        &[CertCompressionAlgorithm::Brotli];

    #[derive(TypedBuilder)]
    pub struct ChromeTlsSettings {
        #[builder(default = CURVES)]
        curves: &'static [SslCurve],

        #[builder(default = SIGALGS_LIST)]
        sigalgs_list: &'static str,

        #[builder(default = CIPHER_LIST)]
        cipher_list: &'static str,

        #[builder(default = AlpsProto::Http2, setter(into))]
        alps_proto: AlpsProto,

        #[builder(default = false, setter(into))]
        enable_ech_grease: bool,

        #[builder(default = false, setter(into))]
        permute_extensions: bool,

        #[builder(default = false, setter(into))]
        pre_shared_key: bool,
    }

    impl From<ChromeTlsSettings> for TlsSettings {
        fn from(val: ChromeTlsSettings) -> Self {
            TlsSettings::builder()
                .grease_enabled(true)
                .enable_ocsp_stapling(true)
                .enable_signed_cert_timestamps(true)
                .curves(Cow::Borrowed(val.curves))
                .sigalgs_list(Cow::Borrowed(val.sigalgs_list))
                .cipher_list(Cow::Borrowed(val.cipher_list))
                .min_tls_version(TlsVersion::TLS_1_2)
                .max_tls_version(TlsVersion::TLS_1_3)
                .permute_extensions(val.permute_extensions)
                .pre_shared_key(val.pre_shared_key)
                .enable_ech_grease(val.enable_ech_grease)
                .alps_proto(val.alps_proto)
                .cert_compression_algorithm(Cow::Borrowed(CERT_COMPRESSION_ALGORITHM))
                .build()
        }
    }
}

mod http2 {
    use crate::mimic::http2_imports::*;

    pub const HEADER_PRIORITY: (u32, u8, bool) = (0, 255, true);

    pub const HEADERS_PSEUDO_ORDER: [PseudoOrder; 4] = [Method, Authority, Scheme, Path];

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

mod_generator!(
    v100,
    tls_settings!(1),
    http2_settings!(1),
    header_initializer,
    r#""Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36"
);

mod_generator!(
    v101,
    tls_settings!(1),
    http2_settings!(1),
    header_initializer,
    r#""Not A;Brand";v="99", "Chromium";v="101", "Google Chrome";v="101""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"
);

mod_generator!(
    v104,
    tls_settings!(1),
    http2_settings!(1),
    header_initializer,
    r#""Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"
);

mod_generator!(
    v105,
    tls_settings!(2),
    http2_settings!(1),
    header_initializer,
    r#""Google Chrome";v="105", "Not)A;Brand";v="8", "Chromium";v="105""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"
);

mod_generator!(
    v106,
    tls_settings!(3),
    http2_settings!(2),
    header_initializer,
    r#""Chromium";v="106", "Google Chrome";v="106", "Not;A=Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36"
);

mod_generator!(
    v107,
    tls_settings!(3),
    http2_settings!(2),
    header_initializer,
    r#""Chromium";v="107", "Google Chrome";v="107", "Not;A=Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
);

mod_generator!(
    v108,
    tls_settings!(3),
    http2_settings!(2),
    header_initializer,
    r#""Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
);

mod_generator!(
    v109,
    tls_settings!(3),
    http2_settings!(2),
    header_initializer,
    r#""Chromium";v="109", "Google Chrome";v="109", "Not;A=Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
);

mod_generator!(
    v114,
    tls_settings!(3),
    http2_settings!(2),
    header_initializer,
    r#""Chromium";v="114", "Google Chrome";v="114", "Not;A=Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
);

mod_generator!(
    v116,
    tls_settings!(4),
    http2_settings!(2),
    header_initializer,
    r#""Chromium";v="116", "Google Chrome";v="116", "Not;A=Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
);

mod_generator!(
    v117,
    tls_settings!(5),
    http2_settings!(3),
    header_initializer,
    r#""Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
);

mod_generator!(
    v118,
    tls_settings!(4),
    http2_settings!(3),
    header_initializer,
    r#""Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
);

mod_generator!(
    v119,
    tls_settings!(4),
    http2_settings!(3),
    header_initializer,
    r#""Chromium";v="119", "Google Chrome";v="119", "Not=A?Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
);

mod_generator!(
    v120,
    tls_settings!(5),
    http2_settings!(3),
    header_initializer,
    r#""Chromium";v="120", "Google Chrome";v="120", "Not?A_Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
);

mod_generator!(
    v123,
    tls_settings!(5),
    http2_settings!(3),
    header_initializer_with_zstd,
    r#""Google Chrome";v="123", "Not;A=Brand";v="8", "Chromium";v="123""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
);

mod_generator!(
    v124,
    tls_settings!(6, NEW_CURVES_1),
    http2_settings!(3),
    header_initializer_with_zstd,
    r#""Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
);

mod_generator!(
    v126,
    tls_settings!(6, NEW_CURVES_1),
    http2_settings!(3),
    header_initializer_with_zstd,
    r#""Chromium";v="126", "Google Chrome";v="126", "Not-A.Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
);

mod_generator!(
    v127,
    tls_settings!(6, NEW_CURVES_1),
    http2_settings!(3),
    header_initializer_with_zstd,
    r#""Not/A)Brand";v="8", "Chromium";v="127", "Google Chrome";v="127""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
);

mod_generator!(
    v128,
    tls_settings!(6, NEW_CURVES_1),
    http2_settings!(3),
    header_initializer,
    r#""Chromium";v="128", "Google Chrome";v="128", "Not?A_Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
);

mod_generator!(
    v129,
    tls_settings!(6, NEW_CURVES_1),
    http2_settings!(3),
    header_initializer_with_zstd_priority,
    r#""Google Chrome";v="129", "Chromium";v="129", "Not_A Brand\";v="24""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
);

mod_generator!(
    v130,
    tls_settings!(6, NEW_CURVES_1),
    http2_settings!(3),
    header_initializer_with_zstd_priority,
    r#""Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
);

mod_generator!(
    v131,
    tls_settings!(6, NEW_CURVES_2),
    http2_settings!(3),
    header_initializer_with_zstd_priority,
    r#""Google Chrome";v="131", "Chromium";v="131", "Not_A Brand\";v="24""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
);

mod_generator!(
    edge101,
    tls_settings!(1),
    http2_settings!(1),
    header_initializer,
    r#""Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47"
);

mod_generator!(
    edge122,
    tls_settings!(5),
    http2_settings!(3),
    header_initializer,
    r#""Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
);

mod_generator!(
    edge127,
    tls_settings!(6, NEW_CURVES_1),
    http2_settings!(3),
    header_initializer_with_zstd_priority,
    r#""Not)A;Brand";v="99", "Microsoft Edge";v="127", "Chromium";v="127""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0"
);

mod_generator!(
    edge131,
    tls_settings!(6, NEW_CURVES_2),
    http2_settings!(3),
    header_initializer_with_zstd_priority,
    r#""Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24""#,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
);
