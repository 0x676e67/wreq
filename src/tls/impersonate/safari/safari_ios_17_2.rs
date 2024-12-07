use crate::tls::impersonate::ImpersonateSettings;
use crate::tls::TlsResult;
use http::{
    header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT},
    HeaderMap, HeaderValue,
};

pub(crate) fn get_settings() -> TlsResult<ImpersonateSettings> {
    Ok(ImpersonateSettings::builder()
        .tls(super::tls_template_1()?)
        .http2(super::http2_template_2())
        .headers(header_initializer)
        .build())
}

fn header_initializer(headers: &mut HeaderMap) {
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
}
