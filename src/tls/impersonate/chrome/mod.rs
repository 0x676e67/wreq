mod http2;
mod tls;
pub mod v100;
pub mod v101;
pub mod v104;
pub mod v105;
pub mod v106;
pub mod v107;
pub mod v108;
pub mod v109;
pub mod v114;
pub mod v116;
pub mod v117;
pub mod v118;
pub mod v119;
pub mod v120;
pub mod v123;
pub mod v124;
pub mod v126;
pub mod v127;
pub mod v128;
pub mod v129;

use crate::tls::{Http2Settings, TlsExtensionSettings, TlsResult};
use boring::ssl::SslConnectorBuilder;
use http2::{HEADERS_PSEUDO_ORDER, HEADER_PRORIORITY, SETTINGS_ORDER};
use tls::{ChromeTlsSettings, NEW_CURVES};

// ============== TLS template ==============
pub fn tls_template_1() -> TlsResult<(SslConnectorBuilder, TlsExtensionSettings)> {
    ChromeTlsSettings::builder()
        .build()
        .try_into()
        .map_err(Into::into)
}

pub fn tls_template_2() -> TlsResult<(SslConnectorBuilder, TlsExtensionSettings)> {
    ChromeTlsSettings::builder()
        .enable_ech_grease(true)
        .build()
        .try_into()
        .map_err(Into::into)
}

pub fn tls_template_3() -> TlsResult<(SslConnectorBuilder, TlsExtensionSettings)> {
    ChromeTlsSettings::builder()
        .permute_extensions(true)
        .build()
        .try_into()
        .map_err(Into::into)
}

pub fn tls_template_4() -> TlsResult<(SslConnectorBuilder, TlsExtensionSettings)> {
    ChromeTlsSettings::builder()
        .permute_extensions(true)
        .enable_ech_grease(true)
        .build()
        .try_into()
        .map_err(Into::into)
}

pub fn tls_template_5() -> TlsResult<(SslConnectorBuilder, TlsExtensionSettings)> {
    ChromeTlsSettings::builder()
        .permute_extensions(true)
        .enable_ech_grease(true)
        .pre_shared_key(true)
        .build()
        .try_into()
        .map_err(Into::into)
}

pub fn tls_template_6() -> TlsResult<(SslConnectorBuilder, TlsExtensionSettings)> {
    ChromeTlsSettings::builder()
        .curves(NEW_CURVES)
        .permute_extensions(true)
        .pre_shared_key(true)
        .enable_ech_grease(true)
        .build()
        .try_into()
        .map_err(Into::into)
}

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

pub fn http2_template_2() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(6291456)
        .initial_connection_window_size(15728640)
        .max_concurrent_streams(1000)
        .max_header_list_size(262144)
        .header_table_size(65536)
        .enable_push(false)
        .headers_priority(HEADER_PRORIORITY)
        .headers_pseudo_order(HEADERS_PSEUDO_ORDER)
        .settings_order(&SETTINGS_ORDER)
        .build()
}

pub fn http2_template_3() -> Http2Settings {
    Http2Settings::builder()
        .initial_stream_window_size(6291456)
        .initial_connection_window_size(15728640)
        .max_header_list_size(262144)
        .header_table_size(65536)
        .enable_push(false)
        .headers_priority(HEADER_PRORIORITY)
        .headers_pseudo_order(HEADERS_PSEUDO_ORDER)
        .settings_order(&SETTINGS_ORDER)
        .build()
}
