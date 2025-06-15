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
pub(crate) struct RequestTotalTimeout;

impl RequestConfigValue for RequestTotalTimeout {
    type Value = Duration;
}

#[derive(Clone, Copy)]
pub(crate) struct RequestReadTimeout;

impl RequestConfigValue for RequestReadTimeout {
    type Value = Duration;
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
pub(crate) struct RequestAcceptsEncoding;

#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
))]
impl RequestConfigValue for RequestAcceptsEncoding {
    type Value = crate::client::decoder::Accepts;
}
