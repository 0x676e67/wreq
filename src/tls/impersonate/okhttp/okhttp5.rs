use super::tls::OkHttpTlsSettings;
use crate::tls::impersonate::ImpersonateSettings;
use crate::tls::TlsResult;
use http::{
    header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT},
    HeaderMap, HeaderValue,
};

pub(crate) fn get_settings() -> TlsResult<ImpersonateSettings> {
    Ok(ImpersonateSettings::builder()
        .tls(
            OkHttpTlsSettings::builder()
                .cipher_list(&[
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
                    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                ])
                .build()
                .try_into()?,
        )
        .http2(super::http2_template_1())
        .headers(header_initializer)
        .build())
}

fn header_initializer(headers: &mut HeaderMap) {
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(USER_AGENT, HeaderValue::from_static("NRC Audio/2.0.6 (nl.nrc.audio; build:36; Android 14; Sdk:34; Manufacturer:OnePlus; Model: CPH2609) OkHttp/5.0.0-alpha2"));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
}
