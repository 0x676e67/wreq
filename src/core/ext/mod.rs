//! HTTP extensions.

mod config;
mod h1_reason_phrase;
mod header;

pub(crate) use config::{
    RequestConfig, RequestConfigValue, RequestExtendedConnectProtocol, RequestLevelOptions,
    RequestOriginalHeaders,
};
pub(crate) use h1_reason_phrase::ReasonPhrase;
pub use header::OriginalHeaders;
