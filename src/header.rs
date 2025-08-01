//! Header module
//! re-exports the `http::header` module for easier access

use bytes::Bytes;
pub use http::header::*;
use sealed::HeaderCaseName;

/// A map from header names to their original casing as received in an HTTP message.
///
/// [`OrigHeaderMap`] not only preserves the original case of each header name as it appeared
/// in the request or response, but also maintains the insertion order of headers. This makes
/// it suitable for use cases where the order of headers matters, such as HTTP/1.x message
/// serialization, proxying, or reproducing requests/responses exactly as received.
///
/// If an HTTP/1 response `res` is parsed on a connection whose option
/// `preserve_header_case` was set to true and the response included
/// the following headers:
///
/// ```ignore
/// x-Bread: Baguette
/// X-BREAD: Pain
/// x-bread: Ficelle
/// ```
///
/// Then `res.extensions().get::<OrigHeaderMap>()` will return a map with:
///
/// ```ignore
/// OrigHeaderMap({
///     "x-bread": ["x-Bread", "X-BREAD", "x-bread"],
/// })
/// ```
///
/// # Note
/// [`OrigHeaderMap`] can also be used as a header ordering map, preserving the order in which
/// headers were added. This is useful for scenarios where header order must be retained.
#[derive(Debug, Clone, Default)]
pub struct OrigHeaderMap(HeaderMap<Bytes>);

impl OrigHeaderMap {
    /// Creates a new, empty [`OrigHeaderMap`].
    #[inline]
    pub fn new() -> Self {
        Self(HeaderMap::default())
    }

    /// Creates an empty [`OrigHeaderMap`] with the specified capacity.
    #[inline]
    pub fn with_capacity(size: usize) -> Self {
        Self(HeaderMap::with_capacity(size))
    }

    /// Insert a new header name into the collection.
    ///
    /// If the map did not previously have this key present, then `false` is
    /// returned.
    ///
    /// If the map did have this key present, the new value is pushed to the end
    /// of the list of values currently associated with the key. The key is not
    /// updated, though; this matters for types that can be `==` without being
    /// identical.
    #[inline]
    pub fn insert<N>(&mut self, orig: N) -> bool
    where
        N: TryInto<HeaderCaseName>,
    {
        match orig.try_into() {
            Ok(orig) => self.0.append(orig.name, orig.orig),
            Err(_) => false,
        }
    }

    /// Extends a a collection with the contents of an iterator.
    #[inline]
    pub fn extend(&mut self, iter: OrigHeaderMap) {
        self.0.extend(iter.0);
    }

    /// Returns an iterator over all header names and their original spellings.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &Bytes)> {
        self.0.iter()
    }
}

impl OrigHeaderMap {
    /// Appends a header name to the end of the collection.
    #[inline]
    pub(crate) fn append<N>(&mut self, name: N, orig: Bytes)
    where
        N: IntoHeaderName,
    {
        self.0.append(name, orig);
    }

    /// Returns a view of all spellings associated with that header name,
    /// in the order they were found.
    #[inline]
    pub(crate) fn get_all<'a>(
        &'a self,
        name: &HeaderName,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
        self.0.get_all(name).into_iter()
    }

    /// Returns an iterator over all header names and their original spellings.
    #[inline]
    pub(crate) fn keys(&self) -> impl Iterator<Item = &HeaderName> {
        self.0.keys()
    }
}

impl<'a> IntoIterator for &'a OrigHeaderMap {
    type Item = (&'a HeaderName, &'a Bytes);
    type IntoIter = <&'a HeaderMap<Bytes> as IntoIterator>::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for OrigHeaderMap {
    type Item = (Option<HeaderName>, Bytes);
    type IntoIter = <HeaderMap<Bytes> as IntoIterator>::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

mod sealed {
    use std::borrow::Cow;

    use bytes::Bytes;
    use http::HeaderName;

    /// Represents an HTTP header name with its original casing preserved.
    ///
    /// `HeaderCaseName` is used to store the original case-sensitive form of an HTTP header name as
    /// it appeared in the request or response. While HTTP header names are case-insensitive
    /// according to the specification, preserving the original casing can be important for
    /// certain applications, such as proxies, logging, debugging, or when reproducing requests
    /// exactly as received.
    ///
    /// This type allows you to associate a normalized `HeaderName` with its original string
    /// representation, enabling accurate restoration or inspection of header names in their
    /// original form.
    pub struct HeaderCaseName {
        /// The original header name in its original case.
        pub orig: Bytes,
        /// The normalized header name in lowercase.
        pub name: HeaderName,
    }

    impl From<HeaderName> for HeaderCaseName {
        fn from(name: HeaderName) -> Self {
            Self {
                orig: Bytes::from_owner(name.clone()),
                name,
            }
        }
    }

    impl<'a> From<&'a HeaderName> for HeaderCaseName {
        fn from(src: &'a HeaderName) -> HeaderCaseName {
            Self::from(src.clone())
        }
    }

    impl TryFrom<String> for HeaderCaseName {
        type Error = http::Error;

        fn try_from(orig: String) -> Result<Self, Self::Error> {
            let name = HeaderName::from_bytes(orig.as_bytes())?;
            Ok(Self {
                orig: Bytes::from_owner(orig),
                name,
            })
        }
    }

    impl TryFrom<Cow<'static, str>> for HeaderCaseName {
        type Error = http::Error;

        fn try_from(orig: Cow<'static, str>) -> Result<Self, Self::Error> {
            match orig {
                Cow::Borrowed(orig) => Self::try_from(orig.as_bytes()),
                Cow::Owned(orig) => Self::try_from(orig),
            }
        }
    }

    impl TryFrom<Bytes> for HeaderCaseName {
        type Error = http::Error;

        fn try_from(orig: Bytes) -> Result<Self, Self::Error> {
            let name = HeaderName::from_bytes(&orig)?;
            Ok(Self { orig, name })
        }
    }

    impl<'a> TryFrom<&'a Bytes> for HeaderCaseName {
        type Error = http::Error;

        fn try_from(orig: &'a Bytes) -> Result<Self, Self::Error> {
            let name = HeaderName::from_bytes(orig)?;
            Ok(Self {
                orig: orig.clone(),
                name,
            })
        }
    }

    impl TryFrom<&'static [u8]> for HeaderCaseName {
        type Error = http::Error;

        fn try_from(orig: &'static [u8]) -> Result<Self, Self::Error> {
            let name = HeaderName::from_bytes(orig)?;
            Ok(Self {
                orig: Bytes::from_static(orig),
                name,
            })
        }
    }

    impl TryFrom<&'static str> for HeaderCaseName {
        type Error = http::Error;

        fn try_from(orig: &'static str) -> Result<Self, Self::Error> {
            Self::try_from(orig.as_bytes())
        }
    }
}

#[cfg(test)]
mod test {
    use bytes::Bytes;

    use super::OrigHeaderMap;

    #[test]
    fn test_header_order() {
        let mut headers = OrigHeaderMap::new();

        // Insert headers with different cases and order
        headers.append("X-Test", Bytes::from("X-Test"));
        headers.append("X-Another", Bytes::from("X-Another"));
        headers.append("x-test2", Bytes::from("x-test2"));

        // Check order and case
        let mut iter = headers.iter();
        assert_eq!(iter.next().unwrap().1, "X-Test");
        assert_eq!(iter.next().unwrap().1, "X-Another");
        assert_eq!(iter.next().unwrap().1, "x-test2");
    }

    #[test]
    fn test_header_case() {
        let mut headers = OrigHeaderMap::new();

        // Insert headers with different cases
        headers.append("X-Test", Bytes::from("X-Test"));
        headers.append("x-test", Bytes::from("x-test"));

        // Check that both headers are stored
        let all_x_test: Vec<_> = headers.get_all(&"X-Test".parse().unwrap()).collect();
        assert_eq!(all_x_test.len(), 2);
        assert!(all_x_test.iter().any(|v| v.as_ref() == b"X-Test"));
        assert!(all_x_test.iter().any(|v| v.as_ref() == b"x-test"));
    }

    #[test]
    fn test_header_multiple_cases() {
        let mut headers = OrigHeaderMap::new();

        // Insert multiple headers with the same name but different cases
        headers.append("X-test", Bytes::from("X-test"));
        headers.append("x-test", Bytes::from("x-test"));
        headers.append("X-test", Bytes::from("X-test"));

        // Check that all variations are stored
        let all_x_test: Vec<_> = headers.get_all(&"x-test".parse().unwrap()).collect();
        assert_eq!(all_x_test.len(), 3);
        assert!(all_x_test.iter().any(|v| v.as_ref() == b"X-test"));
        assert!(all_x_test.iter().any(|v| v.as_ref() == b"x-test"));
        assert!(all_x_test.iter().any(|v| v.as_ref() == b"X-test"));
    }
}
