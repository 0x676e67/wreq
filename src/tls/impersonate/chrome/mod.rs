pub mod v100;
pub mod v101;
pub mod v104;
pub mod v105;
pub mod v106;
pub mod v107;
pub mod v108;
pub mod v109;
pub mod v114;
pub mod v116;
pub mod v117;
pub mod v118;
pub mod v119;
pub mod v120;
pub mod v123;
pub mod v124;
pub mod v126;
pub mod v127;
pub mod v128;
pub mod v129;
pub mod v130;
pub mod v131;

use crate::tls::{Http2Settings, TlsResult, TlsSettings};
use http2::{HEADERS_PSEUDO_ORDER, HEADER_PRORIORITY, SETTINGS_ORDER};
use tls::{ChromeTlsSettings, NEW_CURVES_1, NEW_CURVES_2};

// ============== TLS template ==============
pub fn tls_template_1() -> TlsResult<TlsSettings> {
    ChromeTlsSettings::builder().build().try_into()
}

pub fn tls_template_2() -> TlsResult<TlsSettings> {
    ChromeTlsSettings::builder()
        .enable_ech_grease(true)
        .build()
        .try_into()
}

pub fn tls_template_3() -> TlsResult<TlsSettings> {
    ChromeTlsSettings::builder()
        .permute_extensions(true)
        .build()
        .try_into()
}

pub fn tls_template_4() -> TlsResult<TlsSettings> {
    ChromeTlsSettings::builder()
        .permute_extensions(true)
        .enable_ech_grease(true)
        .build()
        .try_into()
}

pub fn tls_template_5() -> TlsResult<TlsSettings> {
    ChromeTlsSettings::builder()
        .permute_extensions(true)
        .enable_ech_grease(true)
        .pre_shared_key(true)
        .build()
        .try_into()
}

pub fn tls_template_6() -> TlsResult<TlsSettings> {
    ChromeTlsSettings::builder()
        .curves(NEW_CURVES_1)
        .permute_extensions(true)
        .pre_shared_key(true)
        .enable_ech_grease(true)
        .build()
        .try_into()
}

pub fn tls_template_7() -> TlsResult<TlsSettings> {
    ChromeTlsSettings::builder()
        .curves(NEW_CURVES_2)
        .permute_extensions(true)
        .pre_shared_key(true)
        .enable_ech_grease(true)
        .build()
        .try_into()
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

mod tls {
    use crate::{
        tls::{cert_compression::CertCompressionAlgorithm, extension::TlsExtension, TlsSettings},
        HttpVersionPref,
    };
    use boring::{
        error::ErrorStack,
        ssl::{SslConnector, SslCurve, SslMethod, SslVersion},
    };
    use typed_builder::TypedBuilder;

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
    pub struct ChromeTlsSettings<'a> {
        // TLS curves
        #[builder(default = CURVES)]
        curves: &'static [SslCurve],

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

    impl TryInto<TlsSettings> for ChromeTlsSettings<'_> {
        type Error = ErrorStack;

        fn try_into(self) -> Result<TlsSettings, Self::Error> {
            let sigalgs_list = self.sigalgs_list.join(":");
            let cipher_list = self.cipher_list.join(":");
            let curves = self.curves;

            let connector = Box::new(move || {
                let mut builder = SslConnector::builder(SslMethod::tls_client())?;
                builder.set_grease_enabled(true);
                builder.enable_ocsp_stapling();
                builder.set_curves(curves)?;
                builder.set_sigalgs_list(&sigalgs_list)?;
                builder.set_cipher_list(&cipher_list)?;
                builder.enable_signed_cert_timestamps();
                builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
                builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
                builder.set_permute_extensions(self.permute_extensions);
                builder.configure_add_cert_compression_alg(CertCompressionAlgorithm::Brotli)
            });

            Ok(TlsSettings::builder()
                .connector(connector)
                .http_version_pref(HttpVersionPref::All)
                .permute_extensions(self.permute_extensions)
                .pre_shared_key(self.pre_shared_key)
                .enable_ech_grease(self.enable_ech_grease)
                .application_settings(self.application_settings)
                .build())
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
