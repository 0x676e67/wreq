pub mod okhttp3_11;
pub mod okhttp3_13;
pub mod okhttp3_14;
pub mod okhttp3_9;
pub mod okhttp4_10;
pub mod okhttp4_9;
pub mod okhttp5;

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

mod tls {
    use crate::tls::{TlsSettings, Version};
    use boring::ssl::SslCurve;
    use typed_builder::TypedBuilder;

    pub const CURVES: &[SslCurve] = &[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1];

    pub const SIGALGS_LIST: [&str; 9] = [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1",
    ];

    #[derive(TypedBuilder)]
    pub struct OkHttpTlsSettings<'a> {
        // TLS curves
        #[builder(default = &CURVES)]
        curves: &'a [SslCurve],

        // TLS sigalgs list
        #[builder(default = &SIGALGS_LIST)]
        sigalgs_list: &'a [&'a str],

        // TLS cipher list
        cipher_list: &'a [&'a str],
    }

    impl Into<TlsSettings> for OkHttpTlsSettings<'_> {
        fn into(self) -> TlsSettings {
            TlsSettings::builder()
                .enable_ocsp_stapling(true)
                .curves(self.curves.to_vec())
                .sigalgs_list(self.sigalgs_list.join(":"))
                .cipher_list(self.cipher_list.join(":"))
                .min_tls_version(Some(Version::TLS_1_2))
                .max_tls_version(Some(Version::TLS_1_3))
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
