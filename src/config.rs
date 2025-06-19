use std::time::Duration;

use crate::{core::ext::RequestConfigValue, redirect::Policy};

// ================================
//
// The following sections are all configuration types
// provided by reqwets.
//
// To add a new config:
//
// 1. create a new struct for the config key like `RequestTimeout`.
// 2. implement `RequestConfigValue` for the struct, the `Value` is the config value's type.
//
// ================================

#[derive(Clone, Copy)]
pub(crate) struct RequestTimeout;

impl RequestConfigValue for RequestTimeout {
    type Value = Duration;
}

pub(crate) type RequestTotalTimeout = RequestTimeout;

pub(crate) type RequestReadTimeout = RequestTimeout;

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
    type Value = crate::client::decoder::AcceptEncoding;
}

#[derive(Clone, Copy)]
pub(crate) struct RequestSkipDefaultHeaders;
impl RequestConfigValue for RequestSkipDefaultHeaders {
    type Value = bool;
}
