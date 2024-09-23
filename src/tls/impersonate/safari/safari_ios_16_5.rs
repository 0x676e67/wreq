use super::{SafariTlsSettings, CIPHER_LIST};
use crate::tls::{Http2Settings, ImpersonateSettings};
use crate::tls::{ImpersonateConfig, TlsResult};
use http::{
    header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT},
    HeaderMap, HeaderValue,
};

pub(crate) fn get_settings(settings: ImpersonateConfig) -> TlsResult<ImpersonateSettings> {
    Ok(ImpersonateSettings::builder()
        .tls(
            SafariTlsSettings::builder()
                .cipher_list(&CIPHER_LIST)
                .extension(settings.tls_extension)
                .build()
                .try_into()?,
        )
        .http2(
            Http2Settings::builder()
                .initial_stream_window_size(2097152)
                .initial_connection_window_size(10551295)
                .max_concurrent_streams(100)
                .headers_priority(settings.http2_headers_priority)
                .headers_pseudo_order(settings.http2_headers_pseudo_order)
                .settings_order(settings.http2_settings_order)
                .build(),
        )
        .headers(Box::new(header_initializer))
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
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
}
