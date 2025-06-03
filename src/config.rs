use crate::core::ext::RequestConfigValue;
use std::time::Duration;

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
