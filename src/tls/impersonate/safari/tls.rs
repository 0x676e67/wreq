use std::sync::Arc;

use crate::tls::{
    cert_compression::CertCompressionAlgorithm, extension::TlsExtension, TlsSettings,
};
use boring::{
    error::ErrorStack,
    ssl::{SslConnector, SslCurve, SslMethod, SslOptions, SslVersion},
};
use typed_builder::TypedBuilder;

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

const SIGALGS_LIST: [&str; 11] = [
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
    #[builder(default, setter(into))]
    curves: Option<&'a [SslCurve]>,

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
        let curves = self.curves.map(|c| c.to_owned()).unwrap_or_else(|| {
            vec![
                SslCurve::X25519,
                SslCurve::SECP256R1,
                SslCurve::SECP384R1,
                SslCurve::SECP521R1,
            ]
        });

        let connector = Arc::new(move || {
            let mut builder = SslConnector::builder(SslMethod::tls_client())?;
            builder.set_options(SslOptions::NO_TICKET);
            builder.set_grease_enabled(true);
            builder.enable_ocsp_stapling();
            builder.set_sigalgs_list(&sigalgs_list)?;
            builder.set_cipher_list(&cipher_list)?;
            builder.set_curves(&curves)?;
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
