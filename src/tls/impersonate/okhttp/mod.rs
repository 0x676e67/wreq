mod http2;
pub mod okhttp3_11;
pub mod okhttp3_13;
pub mod okhttp3_14;
pub mod okhttp3_9;
pub mod okhttp4_10;
pub mod okhttp4_9;
pub mod okhttp5;
mod tls;

use crate::tls::Http2Settings;
use http2::{HEADERS_PSEUDO_ORDER, HEADER_PRORIORITY, SETTINGS_ORDER};

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
        .settings_order(&SETTINGS_ORDER)
        .build()
}
