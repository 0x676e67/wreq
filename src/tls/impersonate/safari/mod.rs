pub mod safari15_3;
pub mod safari15_5;
pub mod safari15_6_1;
pub mod safari16;
pub mod safari16_5;
pub mod safari17_0;
pub mod safari17_2_1;
pub mod safari17_4_1;
pub mod safari17_5;
pub mod safari18;
pub mod safari_ios_16_5;
pub mod safari_ios_17_2;
pub mod safari_ios_17_4_1;
pub mod safari_ipad_18;

use crate::tls::{Http2Settings, TlsResult, TlsSettings};
use http2::{
    HEADERS_PSEUDO_ORDER, HEADER_PRORIORITY, NEW_HEADERS_PSEUDO_ORDER, NEW_HEADER_PRORIORITY,
    NEW_SETTINGS_ORDER, SETTINGS_ORDER,
};
use tls::{SafariTlsSettings, CIPHER_LIST, NEW_CIPHER_LIST};

// ============== TLS template ==============
pub fn tls_template_1() -> TlsResult<TlsSettings> {
    SafariTlsSettings::builder()
        .cipher_list(&NEW_CIPHER_LIST)
        .build()
        .try_into()
}

pub fn tls_template_2() -> TlsResult<TlsSettings> {
    SafariTlsSettings::builder()
        .cipher_list(&CIPHER_LIST)
        .build()
        .try_into()
}

// ============== HTTP template ==============
pub fn http2_template_1() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(2097152)
        .initial_connection_window_size(10551295)
        .max_concurrent_streams(100)
        .headers_priority(HEADER_PRORIORITY)
        .headers_pseudo_order(HEADERS_PSEUDO_ORDER)
        .settings_order(&SETTINGS_ORDER)
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
        .settings_order(&SETTINGS_ORDER)
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
        .settings_order(&NEW_SETTINGS_ORDER)
        .build()
}

pub fn http2_template_4() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(4194304)
        .initial_connection_window_size(10551295)
        .max_concurrent_streams(100)
        .headers_priority(HEADER_PRORIORITY)
        .headers_pseudo_order(HEADERS_PSEUDO_ORDER)
        .settings_order(&SETTINGS_ORDER)
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
        .settings_order(&SETTINGS_ORDER)
        .build()
}

mod tls {
    use crate::tls::{
        cert_compression::CertCompressionAlgorithm, extension::TlsExtension, TlsSettings,
    };
    use boring::{
        error::ErrorStack,
        ssl::{SslConnector, SslCurve, SslMethod, SslOptions, SslVersion},
    };
    use typed_builder::TypedBuilder;

    pub const CURVES: &[SslCurve] = &[
        SslCurve::X25519,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
        SslCurve::SECP521R1,
    ];

    pub const CIPHER_LIST: [&str; 26] = [
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
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    ];

    pub const NEW_CIPHER_LIST: [&str; 20] = [
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
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    ];

    pub const SIGALGS_LIST: [&str; 11] = [
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
        "rsa_pkcs1_sha1",
    ];

    #[derive(TypedBuilder)]
    pub struct SafariTlsSettings<'a> {
        // TLS curves
        #[builder(default = CURVES)]
        curves: &'static [SslCurve],

        // TLS sigalgs list
        #[builder(default = &SIGALGS_LIST)]
        sigalgs_list: &'a [&'a str],

        // TLS cipher list
        cipher_list: &'a [&'a str],
    }

    impl TryInto<TlsSettings> for SafariTlsSettings<'_> {
        type Error = ErrorStack;

        fn try_into(self) -> Result<TlsSettings, Self::Error> {
            let sigalgs_list = self.sigalgs_list.join(":");
            let cipher_list = self.cipher_list.join(":");
            let curves = self.curves;

            let connector = Box::new(move || {
                let mut builder = SslConnector::builder(SslMethod::tls_client())?;
                builder.set_options(SslOptions::NO_TICKET);
                builder.set_grease_enabled(true);
                builder.enable_ocsp_stapling();
                builder.set_curves(curves)?;
                builder.set_sigalgs_list(&sigalgs_list)?;
                builder.set_cipher_list(&cipher_list)?;
                builder.enable_signed_cert_timestamps();
                builder.set_min_proto_version(Some(SslVersion::TLS1))?;
                builder.configure_add_cert_compression_alg(CertCompressionAlgorithm::Zlib)
            });

            Ok(TlsSettings::builder()
                .connector(connector)
                .http_version_pref(crate::HttpVersionPref::All)
                .build())
        }
    }
}

mod http2 {
    use hyper::PseudoOrder::{self, *};
    use hyper::SettingsOrder::{self, *};

    // ============== http2 headers priority ==============
    pub const HEADER_PRORIORITY: (u32, u8, bool) = (0, 255, true);
    pub const NEW_HEADER_PRORIORITY: (u32, u8, bool) = (0, 255, false);

    /// ============== http2 headers pseudo order ==============
    pub const HEADERS_PSEUDO_ORDER: [PseudoOrder; 4] = [Method, Scheme, Path, Authority];
    pub const NEW_HEADERS_PSEUDO_ORDER: [PseudoOrder; 4] = [Method, Scheme, Authority, Path];

    /// ============== http2 settings frame order ==============
    pub const SETTINGS_ORDER: [SettingsOrder; 7] = [
        HeaderTableSize,
        EnablePush,
        InitialWindowSize,
        MaxConcurrentStreams,
        MaxFrameSize,
        MaxHeaderListSize,
        EnableConnectProtocol,
    ];
    pub const NEW_SETTINGS_ORDER: [SettingsOrder; 9] = [
        HeaderTableSize,
        EnablePush,
        MaxConcurrentStreams,
        InitialWindowSize,
        MaxFrameSize,
        MaxHeaderListSize,
        EnableConnectProtocol,
        UnknownSetting8,
        UnknownSetting9,
    ];
}
