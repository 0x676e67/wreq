//! HTTP extensions.

mod config;
mod h1_reason_phrase;
mod header;

use std::fmt;

pub(crate) use config::{
    RequestConfig, RequestConfigValue, RequestHttpVersionPref, RequestInterface, RequestIpv4Addr,
    RequestIpv6Addr, RequestOriginalHeaders, RequestProxyMatcher,
};
pub(crate) use h1_reason_phrase::ReasonPhrase;

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    inner: http2::ext::Protocol,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    #[allow(unused)]
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            inner: http2::ext::Protocol::from_static(value),
        }
    }

    pub(crate) fn into_inner(self) -> http2::ext::Protocol {
        self.inner
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            inner: http2::ext::Protocol::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}
