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
    /// Creates a new `RequestConfig` with the provided value.
    #[inline]
    pub(crate) const fn new(v: Option<T::Value>) -> Self {
        RequestConfig(v)
    }

    /// Returns a reference to the inner value of this request-scoped configuration.
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

    /// Loads the internal value from the provided `Extensions`, if present.
    ///
    /// This method attempts to retrieve a value of type `RequestConfig<T>` from the provided
    /// `Extensions`. If such a value exists, the current internal value is replaced with a
    /// clone of that value. If not, the internal value remains unchanged.
    #[inline]
    pub(crate) fn load(&mut self, ext: &Extensions) {
        if let Some(value) = RequestConfig::<T>::get(ext) {
            self.0 = Some(value.clone());
        }
    }

    /// Stores this value into the given `Extensions`, if a value of the same type is not already
    /// present.
    ///
    /// This method checks whether the provided `Extensions` contains a `RequestConfig<T>`.
    /// If not, it clones the current value and inserts it into the extensions. If a value already
    /// exists, the method does nothing.
    #[inline]
    pub(crate) fn store(&self, ext: &mut Extensions) {
        let option_value = ext.get_mut::<RequestConfig<T>>();
        if option_value.is_none() {
            ext.insert(self.clone());
        }
    }

    /// Returns an immutable reference to the stored value from the given `Extensions`, if present.
    ///
    /// Internally fetches `RequestConfig<T>` and returns a reference to its inner value, if set.
    #[inline]
    pub(crate) fn get(ext: &Extensions) -> Option<&T::Value> {
        ext.get::<RequestConfig<T>>().and_then(|v| v.0.as_ref())
    }

    /// Returns a mutable reference to the inner value in `Extensions`, inserting a default if
    /// missing.
    ///
    /// This ensures a `RequestConfig<T>` exists and returns a mutable reference to its inner
    /// `Option<T::Value>`.
    #[inline]
    pub(crate) fn get_mut(ext: &mut Extensions) -> &mut Option<T::Value> {
        let cfg = ext.get_or_insert_default::<RequestConfig<T>>();
        &mut cfg.0
    }

    /// Removes and returns the stored value from the given `Extensions`, if present.
    ///
    /// This consumes the `RequestConfig<T>` entry and extracts its inner value.
    #[inline]
    pub(crate) fn remove(ext: &mut Extensions) -> Option<T::Value> {
        ext.remove::<RequestConfig<T>>().and_then(|v| v.0)
    }
}

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Copy)]
pub(crate) struct RequestExtendedConnectProtocol;

impl RequestConfigValue for RequestExtendedConnectProtocol {
    type Value = http2::ext::Protocol;
}

/// Request TCP connect options for the request.
#[derive(Clone, Copy)]
pub(crate) struct RequestTcpConnectOptions;

impl RequestConfigValue for RequestTcpConnectOptions {
    type Value = crate::core::client::connect::TcpConnectOptions;
}

/// Request transport options for the request.
#[derive(Clone, Copy)]
pub(crate) struct RequestTransportOptions;

impl RequestConfigValue for RequestTransportOptions {
    type Value = crate::core::client::options::TransportOptions;
}

/// Request enforced HTTP version for the request.
#[derive(Clone, Copy)]
pub(crate) struct RequestEnforcedHttpVersion;

impl RequestConfigValue for RequestEnforcedHttpVersion {
    type Value = http::Version;
}

/// Request proxy matcher for the request.
#[derive(Clone, Copy)]
pub(crate) struct RequestProxyMatcher;

impl RequestConfigValue for RequestProxyMatcher {
    type Value = crate::proxy::Matcher;
}

/// Request original headers for the request.
#[derive(Clone, Copy)]
pub(crate) struct RequestOriginalHeaders;

impl RequestConfigValue for RequestOriginalHeaders {
    type Value = super::header::OriginalHeaders;
}
