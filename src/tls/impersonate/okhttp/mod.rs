pub mod okhttp3_11;
pub mod okhttp3_13;
pub mod okhttp3_14;
pub mod okhttp3_9;
pub mod okhttp4_10;
pub mod okhttp4_9;
pub mod okhttp5;

use crate::tls::TlsExtensionSettings;
use boring::{
    error::ErrorStack,
    ssl::{SslConnector, SslConnectorBuilder, SslCurve, SslMethod, SslVersion},
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
struct OkHttpTlsSettings<'a> {
    // TLS curves
    #[builder(default, setter(into))]
    curves: Option<&'a [SslCurve]>,

    // TLS sigalgs list
    #[builder(default = &SIGALGS_LIST)]
    sigalgs_list: &'a [&'a str],

    // TLS cipher list
    cipher_list: &'a [&'a str],

    // TLS extension
    extension: TlsExtensionSettings,
}

impl TryInto<(SslConnectorBuilder, TlsExtensionSettings)> for OkHttpTlsSettings<'_> {
    type Error = ErrorStack;

    fn try_into(self) -> Result<(SslConnectorBuilder, TlsExtensionSettings), Self::Error> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.enable_ocsp_stapling();
        builder.set_curves(self.curves.unwrap_or(&[
            SslCurve::X25519,
            SslCurve::SECP256R1,
            SslCurve::SECP384R1,
        ]))?;
        builder.set_sigalgs_list(&self.sigalgs_list.join(":"))?;
        builder.set_cipher_list(&self.cipher_list.join(":"))?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        Ok((builder, self.extension))
    }
}
