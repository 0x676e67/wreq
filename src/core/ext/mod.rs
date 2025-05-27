//! HTTP extensions.

use bytes::Bytes;
use http::header::HeaderName;
use http::header::{HeaderMap, IntoHeaderName, ValueIter};
use std::fmt;

mod h1_reason_phrase;
pub use h1_reason_phrase::ReasonPhrase;

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

/// A map from header names to their original casing as received in an HTTP message.
///
/// If an HTTP/1 response `res` is parsed on a connection whose option
/// [`preserve_header_case`] was set to true and the response included
/// the following headers:
///
/// ```ignore
/// x-Bread: Baguette
/// X-BREAD: Pain
/// x-bread: Ficelle
/// ```
///
/// Then `res.extensions().get::<HeaderCaseMap>()` will return a map with:
///
/// ```ignore
/// HeaderCaseMap({
///     "x-bread": ["x-Bread", "X-BREAD", "x-bread"],
/// })
/// ```
///
/// [`preserve_header_case`]: /client/struct.Client.html#method.preserve_header_case
#[derive(Clone, Debug)]
pub(crate) struct HeaderCaseMap(HeaderMap<Bytes>);

impl HeaderCaseMap {
    /// Returns a view of all spellings associated with that header name,
    /// in the order they were found.
    pub(crate) fn get_all<'a>(
        &'a self,
        name: &HeaderName,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
        self.get_all_internal(name)
    }

    /// Returns a view of all spellings associated with that header name,
    /// in the order they were found.
    pub(crate) fn get_all_internal(&self, name: &HeaderName) -> ValueIter<'_, Bytes> {
        self.0.get_all(name).into_iter()
    }

    pub(crate) fn default() -> Self {
        Self(Default::default())
    }

    pub(crate) fn append<N>(&mut self, name: N, orig: Bytes)
    where
        N: IntoHeaderName,
    {
        self.0.append(name, orig);
    }
}
