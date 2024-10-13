mod http2;
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
mod tls;

use crate::tls::{Http2Settings, TlsExtensionSettings, TlsResult};
use boring::ssl::SslConnectorBuilder;
use http2::{
    HEADERS_PSEUDO_ORDER, HEADER_PRORIORITY, NEW_HEADERS_PSEUDO_ORDER, NEW_HEADER_PRORIORITY,
    NEW_SETTINGS_ORDER, SETTINGS_ORDER,
};
use tls::{SafariTlsSettings, CIPHER_LIST, NEW_CIPHER_LIST};

// ============== TLS template ==============
pub fn safari_tls_template_1() -> TlsResult<(SslConnectorBuilder, TlsExtensionSettings)> {
    SafariTlsSettings::builder()
        .cipher_list(&NEW_CIPHER_LIST)
        .build()
        .try_into()
        .map_err(Into::into)
}

pub fn safari_tls_template_2() -> TlsResult<(SslConnectorBuilder, TlsExtensionSettings)> {
    SafariTlsSettings::builder()
        .cipher_list(&CIPHER_LIST)
        .build()
        .try_into()
        .map_err(Into::into)
}

// ============== HTTP template ==============
pub fn safari_http2_template_1() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(2097152)
        .initial_connection_window_size(10551295)
        .max_concurrent_streams(100)
        .headers_priority(*HEADER_PRORIORITY)
        .headers_pseudo_order(*HEADERS_PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER.to_vec())
        .build()
}

pub fn safari_http2_template_2() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(2097152)
        .initial_connection_window_size(10551295)
        .max_concurrent_streams(100)
        .enable_push(false)
        .headers_priority(*HEADER_PRORIORITY)
        .headers_pseudo_order(*HEADERS_PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER.to_vec())
        .build()
}

pub fn safari_http2_template_3() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(2097152)
        .initial_connection_window_size(10485760)
        .max_concurrent_streams(100)
        .enable_push(false)
        .unknown_setting8(true)
        .unknown_setting9(true)
        .headers_priority(*NEW_HEADER_PRORIORITY)
        .headers_pseudo_order(*NEW_HEADERS_PSEUDO_ORDER)
        .settings_order(NEW_SETTINGS_ORDER.to_vec())
        .build()
}

pub fn safari_http2_template_4() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(4194304)
        .initial_connection_window_size(10551295)
        .max_concurrent_streams(100)
        .headers_priority(*HEADER_PRORIORITY)
        .headers_pseudo_order(*HEADERS_PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER.to_vec())
        .build()
}

pub fn safari_http2_template_5() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(4194304)
        .initial_connection_window_size(10551295)
        .max_concurrent_streams(100)
        .enable_push(false)
        .headers_priority(*HEADER_PRORIORITY)
        .headers_pseudo_order(*HEADERS_PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER.to_vec())
        .build()
}
