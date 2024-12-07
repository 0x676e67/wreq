pub mod edge101;
pub mod edge122;
pub mod edge127;

use crate::tls::Http2Settings;
use http2::{HEADERS_PSEUDO_ORDER, HEADER_PRORIORITY, SETTINGS_ORDER};

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

mod tls {
    use crate::tls::{cert_compression::CertCompressionAlgorithm, TlsSettings, Version};
    use boring::ssl::SslCurve;
    use typed_builder::TypedBuilder;

    pub const CURVES: &[SslCurve] = &[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1];

    pub const NEW_CURVES: &[SslCurve] = &[
        SslCurve::X25519_KYBER768_DRAFT00,
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
    ];

    pub const CIPHER_LIST: [&str; 15] = [
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
        "TLS_RSA_WITH_AES_256_CBC_SHA",
    ];

    pub const SIGALGS_LIST: [&str; 8] = [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
    ];

    #[derive(TypedBuilder)]
    pub struct EdgeTlsSettings<'a> {
        // TLS curves
        #[builder(default = &CURVES)]
        curves: &'a [SslCurve],

        // TLS sigalgs list
        #[builder(default = &SIGALGS_LIST)]
        sigalgs_list: &'a [&'a str],

        // TLS cipher list
        #[builder(default = &CIPHER_LIST)]
        cipher_list: &'a [&'a str],

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

    impl Into<TlsSettings> for EdgeTlsSettings<'_> {
        fn into(self) -> TlsSettings {
            TlsSettings::builder()
                .grease_enabled(true)
                .enable_ocsp_stapling(true)
                .enable_signed_cert_timestamps(true)
                .curves(self.curves.to_vec())
                .sigalgs_list(self.sigalgs_list.join(":"))
                .cipher_list(self.cipher_list.join(":"))
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

mod http2 {
    use hyper::PseudoOrder::{self, *};
    use hyper::SettingsOrder::{self, *};

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
