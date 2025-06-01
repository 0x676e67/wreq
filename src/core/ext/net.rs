use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "solaris",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
#[derive(Clone, Eq, PartialEq)]
pub struct Interface {
    inner: Option<std::borrow::Cow<'static, str>>,
}

// ==== impl Interface ====
#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "solaris",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
impl Interface {
    pub(crate) fn into_inner(self) -> Option<std::borrow::Cow<'static, str>> {
        self.inner
    }
}

#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "solaris",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
impl<T> From<T> for Interface
where
    T: Into<Option<std::borrow::Cow<'static, str>>>,
{
    fn from(value: T) -> Self {
        Self {
            inner: value.into(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Addresses {
    inner: (Option<Ipv4Addr>, Option<Ipv6Addr>),
}

// ==== impl Addresses ====

impl Addresses {
    pub(crate) fn into_inner(self) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        self.inner
    }
}

impl<T, U> From<(T, U)> for Addresses
where
    T: Into<Option<Ipv4Addr>>,
    U: Into<Option<Ipv6Addr>>,
{
    fn from(value: (T, U)) -> Self {
        Self {
            inner: (value.0.into(), value.1.into()),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProxyScheme {
    inner: Option<crate::proxy::ProxyScheme>,
}

// ==== impl ProxyScheme ====

impl ProxyScheme {
    pub(crate) fn into_inner(self) -> Option<crate::proxy::ProxyScheme> {
        self.inner
    }
}

impl<T> From<T> for ProxyScheme
where
    T: Into<Option<crate::proxy::ProxyScheme>>,
{
    fn from(value: T) -> Self {
        Self {
            inner: value.into(),
        }
    }
}
