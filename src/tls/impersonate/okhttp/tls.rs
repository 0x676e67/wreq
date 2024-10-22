use std::sync::Arc;

use crate::tls::TlsSettings;
use boring::{
    error::ErrorStack,
    ssl::{SslConnector, SslCurve, SslMethod, SslVersion},
};
use typed_builder::TypedBuilder;

const SIGALGS_LIST: [&str; 9] = [
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
    #[builder(default, setter(into))]
    curves: Option<&'a [SslCurve]>,

    // TLS sigalgs list
    #[builder(default = &SIGALGS_LIST)]
    sigalgs_list: &'a [&'a str],

    // TLS cipher list
    cipher_list: &'a [&'a str],
}

impl TryInto<TlsSettings> for OkHttpTlsSettings<'_> {
    type Error = ErrorStack;

    fn try_into(self) -> Result<TlsSettings, Self::Error> {
        let sigalgs_list = self.sigalgs_list.join(":");
        let cipher_list = self.cipher_list.join(":");
        let curves = self
            .curves
            .map(|c| c.to_owned())
            .unwrap_or_else(|| vec![SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1]);

        let connector = Arc::new(move || {
            let mut builder = SslConnector::builder(SslMethod::tls_client())?;
            builder.enable_ocsp_stapling();
            builder.set_curves(&curves)?;
            builder.set_sigalgs_list(&sigalgs_list)?;
            builder.set_cipher_list(&cipher_list)?;
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
            Ok(builder)
        });

        Ok(TlsSettings::builder()
            .connector(connector)
            .http_version_pref(crate::HttpVersionPref::All)
            .build())
    }
}
