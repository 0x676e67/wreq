use crate::tls::impersonate::ImpersonateSettings;
use crate::tls::TlsResult;
use http::{
    header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT},
    HeaderMap, HeaderValue,
};

pub(crate) fn get_settings() -> TlsResult<ImpersonateSettings> {
    Ok(ImpersonateSettings::builder()
        .tls(super::safari_tls_template_2()?)
        .http2(super::safari_http2_template_4())
        .headers(Box::new(header_initializer))
        .build())
}

fn header_initializer(headers: &mut HeaderMap) {
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
}
