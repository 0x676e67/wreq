use bytes::Bytes;
use http::{HeaderMap, HeaderName, header::IntoHeaderName};

use super::name::OriginalHeaderName;

/// A mapping that preserves the original case of HTTP header names.
///
/// `OriginalHeaders` is used to store and retrieve the original casing of HTTP header names as
/// they appeared in the incoming request or outgoing response. While HTTP header names are
/// case-insensitive by specification, some applications (such as proxies, logging, or debugging
/// tools) may require access to the original case for accurate reproduction or inspection.
///
/// This type allows you to associate each normalized `HeaderName` with its original string
/// representation, enabling restoration or reference to the original header casing when needed.
#[derive(Debug, Clone)]
pub struct OriginalHeaders(HeaderMap<Bytes>);

impl OriginalHeaders {
    /// Creates a new, empty `OriginalHeaders`.
    #[inline]
    pub fn new() -> Self {
        Self(HeaderMap::default())
    }

    /// Creates an empty `OriginalHeaders` with the specified capacity.
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
        N: TryInto<OriginalHeaderName>,
    {
        match orig.try_into() {
            Ok(orig) => self.0.append(orig.name, orig.orig),
            Err(_) => false,
        }
    }

    /// Extends a a collection with the contents of an iterator.
    #[inline]
    pub fn extend(&mut self, iter: OriginalHeaders) {
        self.0.extend(iter.0);
    }

    /// Returns an iterator over all header names and their original spellings.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &Bytes)> {
        self.0.iter()
    }

    /// Returns the number of header names in the collection.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the collection contains no header names.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl OriginalHeaders {
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

impl Default for OriginalHeaders {
    #[inline]
    fn default() -> Self {
        Self::with_capacity(12)
    }
}

impl<'a> IntoIterator for &'a OriginalHeaders {
    type Item = (&'a HeaderName, &'a Bytes);
    type IntoIter = <&'a HeaderMap<Bytes> as IntoIterator>::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for OriginalHeaders {
    type Item = (Option<HeaderName>, Bytes);
    type IntoIter = <HeaderMap<Bytes> as IntoIterator>::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod test {
    use bytes::Bytes;

    use crate::OriginalHeaders;

    #[test]
    fn test_header_order() {
        let mut headers = OriginalHeaders::new();

        // Insert headers with different cases and order
        headers.append("X-Test", Bytes::from("X-Test"));
        headers.append("X-Another", Bytes::from("X-Another"));
        headers.append("x-test2", Bytes::from("x-test2"));

        // Check order and case
        let mut iter = headers.0.iter();
        assert_eq!(iter.next().unwrap().1, "X-Test");
        assert_eq!(iter.next().unwrap().1, "X-Another");
        assert_eq!(iter.next().unwrap().1, "x-test2");
    }

    #[test]
    fn test_header_case() {
        let mut headers = OriginalHeaders::new();

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
        let mut headers = OriginalHeaders::new();

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
