//! HTTP extensions.

mod config;
mod h1_reason_phrase;

pub(crate) use self::{
    config::{RequestConfig, RequestConfigValue, RequestLayerOptions, RequestOrigHeaderMap},
    h1_reason_phrase::ReasonPhrase,
};
