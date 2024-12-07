use crate::tls::impersonate::ImpersonateSettings;
use http::{
    header::{
        ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, CACHE_CONTROL, DNT, UPGRADE_INSECURE_REQUESTS,
        USER_AGENT,
    },
    HeaderMap, HeaderValue,
};

pub(crate) fn get_settings() -> ImpersonateSettings {
    ImpersonateSettings::builder()
        .tls(super::tls_template_4())
        .http2(super::http2_template_3())
        .headers(header_initializer)
        .build()
}

fn header_initializer(headers: &mut HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=0"));
    headers.insert(
        "sec-ch-ua",
        HeaderValue::from_static(
            r#""Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24""#,
        ),
    );
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
    headers.insert(DNT, HeaderValue::from_static("1"));
    headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"));
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
    headers.insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static("en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
    );
}
