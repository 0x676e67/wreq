//! The `config` module provides a generic mechanism for loading and managing
//! request-scoped configuration.
//!
//! # Design Overview
//!
//! This module is centered around two abstractions:
//!
//! - The [`RequestConfigValue`] trait, used to associate a config key type with its value type.
//! - The [`RequestConfig`] struct, which wraps an optional value of the type linked via
//!   [`RequestConfigValue`].
//!
//! Under the hood, the [`RequestConfig`] struct holds a single value for the associated config
//! type. This value can be conveniently accessed, inserted, or mutated using [`http::Extensions`],
//! enabling type-safe configuration storage and retrieval on a per-request basis.
//!
//! # Motivation
//!
//! The key design benefit is the ability to store multiple config types—potentially even with the
//! same value type (e.g., [`std::time::Duration`])—without code duplication or ambiguity. By
//! leveraging trait association, each config key is distinct at the type level, while code for
//! storage and access remains totally generic.
//!
//! # Usage
//!
//! Implement [`RequestConfigValue`] for any marker type you wish to use as a config key,
//! specifying the associated value type. Then use [`RequestConfig<T>`] in [`Extensions`]
//! to set or retrieve config values for each key type in a uniform way.

use std::fmt::Debug;

use http::Extensions;

/// This trait is empty and is only used to associate a configuration key type with its
/// corresponding value type.
pub(crate) trait RequestConfigValue: Copy + Clone + 'static {
    type Value: Clone + Debug + Send + Sync + 'static;
}

/// RequestConfig carries a request-scoped configuration value.
#[derive(Clone, Copy)]
pub(crate) struct RequestConfig<T: RequestConfigValue>(Option<T::Value>);

impl<T: RequestConfigValue> Default for RequestConfig<T> {
    fn default() -> Self {
        RequestConfig(None)
    }
}

impl<T> RequestConfig<T>
where
    T: RequestConfigValue,
{
    #[inline]
    pub(crate) const fn new(v: Option<T::Value>) -> Self {
        RequestConfig(v)
    }

    #[inline]
    pub(crate) const fn as_ref(&self) -> Option<&T::Value> {
        self.0.as_ref()
    }

    /// Retrieve the value from the request-scoped configuration.
    ///
    /// If the request specifies a value, use that value; otherwise, attempt to retrieve it from the
    /// current instance (typically a client instance).
    #[inline]
    pub(crate) fn fetch<'a>(&'a self, ext: &'a Extensions) -> Option<&'a T::Value> {
        ext.get::<RequestConfig<T>>()
            .and_then(|v| v.0.as_ref())
            .or(self.0.as_ref())
    }

    /// Replaces the internal value with a clone of the corresponding value found in the given
    /// `Extensions`, if present.
    ///
    /// This method attempts to retrieve a value of type `RequestConfig<T>` from the provided
    /// `Extensions`. If such a value exists, the current internal value is replaced with a
    /// clone of that value. If not, the internal value remains unchanged.
    #[inline]
    pub(crate) fn replace_from(&mut self, ext: &Extensions) {
        if let Some(value) = RequestConfig::<T>::get(ext) {
            self.0 = Some(value.clone());
        }
    }

    /// Inserts this value into the given `Extensions` if it does not already contain one of the
    /// same type.
    ///
    /// This method checks whether the provided `Extensions` contains a `RequestConfig<T>`.
    /// If not, it clones the current value and inserts it into the extensions. If a value already
    /// exists, the method does nothing.
    #[inline]
    pub(crate) fn replace_to(&self, ext: &mut Extensions) {
        let option_value = ext.get_mut::<RequestConfig<T>>();
        if option_value.is_none() {
            ext.insert(self.clone());
        }
    }

    /// Retrieve the value from the request's Extensions.
    #[inline]
    pub(crate) fn get(ext: &Extensions) -> Option<&T::Value> {
        ext.get::<RequestConfig<T>>().and_then(|v| v.0.as_ref())
    }

    /// Retrieve the mutable value from the request's Extensions.
    #[inline]
    pub(crate) fn get_mut(ext: &mut Extensions) -> &mut Option<T::Value> {
        let cfg = ext.get_or_insert_default::<RequestConfig<T>>();
        &mut cfg.0
    }

    /// Retrieve the value from the request's Extensions, consuming it.
    #[inline]
    pub(crate) fn remove(ext: &mut Extensions) -> Option<T::Value> {
        ext.remove::<RequestConfig<T>>().and_then(|v| v.0)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RequestHttpVersionPref;

impl RequestConfigValue for RequestHttpVersionPref {
    type Value = http::Version;
}

/// Request ipv4 address configuration.
#[derive(Clone, Copy)]
pub(crate) struct RequestIpv4Addr;

impl RequestConfigValue for RequestIpv4Addr {
    type Value = std::net::Ipv4Addr;
}

/// Request ipv6 address configuration.
#[derive(Clone, Copy)]
pub(crate) struct RequestIpv6Addr;

impl RequestConfigValue for RequestIpv6Addr {
    type Value = std::net::Ipv6Addr;
}

/// Request interface configuration.
#[derive(Clone, Copy)]
pub(crate) struct RequestInterface;

impl RequestConfigValue for RequestInterface {
    type Value = std::borrow::Cow<'static, str>;
}

#[derive(Clone, Copy)]
pub(crate) struct RequestProxyMatcher;

impl RequestConfigValue for RequestProxyMatcher {
    type Value = crate::proxy::Matcher;
}

#[derive(Clone, Copy)]
pub(crate) struct RequestOriginalHeaders;

impl RequestConfigValue for RequestOriginalHeaders {
    type Value = super::OriginalHeaders;
}
