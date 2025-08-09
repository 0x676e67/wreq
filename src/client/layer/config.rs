use crate::{core::ext::RequestConfigValue, redirect::Policy};

// ================================
//
// The following sections are all configuration types
// provided by reqwets.
//
// To add a new config:
//
// 1. create a new struct for the config key like `RequestTimeoutOptions`.
// 2. implement `RequestConfigValue` for the struct, the `Value` is the config value's type.
//
// ================================

#[derive(Clone, Copy)]
pub(crate) struct RequestTimeoutOptions;

impl RequestConfigValue for RequestTimeoutOptions {
    type Value = super::timeout::TimeoutOptions;
}

#[derive(Clone, Copy)]
pub(crate) struct RequestRedirectPolicy;
impl RequestConfigValue for RequestRedirectPolicy {
    type Value = Policy;
}

#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
))]
#[derive(Clone, Copy)]
pub(crate) struct RequestAcceptEncoding;

#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
))]
impl RequestConfigValue for RequestAcceptEncoding {
    type Value = crate::client::layer::decoder::AcceptEncoding;
}

#[derive(Clone, Copy)]
pub(crate) struct RequestDefaultHeaders;
impl RequestConfigValue for RequestDefaultHeaders {
    type Value = bool;
}
