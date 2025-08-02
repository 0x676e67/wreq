//! Header module
//! re-exports the `http::header` module for easier access

pub use http::header::*;
pub use name::OrigHeaderName;
use sealed::Sealed;

/// Trait for types that can be converted into an [`OrigHeaderName`] (case-preserved header).
///
/// This trait is sealed, so only known types can implement it.
/// Supported types:
/// - `&'static str`
/// - `String`
/// - `Bytes`
/// - `HeaderName`
/// - `&HeaderName`
/// - `OrigHeaderName`
/// - `&OrigHeaderName`
pub trait IntoOrigHeaderName: Sealed {
    /// Converts the type into an [`OrigHeaderName`].
    fn into_orig_header_name(self) -> OrigHeaderName;
}

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
pub struct OrigHeaderMap(HeaderMap<OrigHeaderName>);

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
        N: IntoOrigHeaderName,
    {
        let orig_header_name = orig.into_orig_header_name();
        match &orig_header_name {
            OrigHeaderName::Cased(bytes) => HeaderName::from_bytes(bytes)
                .map(|name| self.0.append(name, orig_header_name))
                .unwrap_or(false),
            OrigHeaderName::Standard(header_name) => {
                self.0.append(header_name.clone(), orig_header_name)
            }
        }
    }

    /// Extends the map with all entries from another [`OrigHeaderMap`], preserving order.
    #[inline]
    pub fn extend(&mut self, iter: OrigHeaderMap) {
        self.0.extend(iter.0);
    }

    /// Returns an iterator over all header names and their original spellings, in insertion order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &OrigHeaderName)> {
        self.0.iter()
    }
}

impl OrigHeaderMap {
    /// Appends a header name to the end of the collection.
    #[inline]
    pub(crate) fn append<N>(&mut self, name: N, orig: OrigHeaderName)
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
    type Item = (&'a HeaderName, &'a OrigHeaderName);
    type IntoIter = <&'a HeaderMap<OrigHeaderName> as IntoIterator>::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for OrigHeaderMap {
    type Item = (Option<HeaderName>, OrigHeaderName);
    type IntoIter = <HeaderMap<OrigHeaderName> as IntoIterator>::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

mod name {
    use bytes::Bytes;
    use http::HeaderName;

    use super::IntoOrigHeaderName;

    /// An HTTP header name with both normalized and original casing.
    ///
    /// While HTTP headers are case-insensitive, this type stores both
    /// the canonical `HeaderName` and the original casing as received,
    /// useful for preserving header order and formatting in proxies,
    /// debugging, or exact HTTP message reproduction.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum OrigHeaderName {
        /// The original casing of the header name as received.
        Cased(Bytes),
        /// The canonical (normalized, lowercased) header name.
        Standard(HeaderName),
    }

    impl AsRef<[u8]> for OrigHeaderName {
        #[inline]
        fn as_ref(&self) -> &[u8] {
            match self {
                OrigHeaderName::Standard(name) => name.as_ref(),
                OrigHeaderName::Cased(orig) => orig.as_ref(),
            }
        }
    }

    impl IntoOrigHeaderName for &'static str {
        fn into_orig_header_name(self) -> OrigHeaderName {
            Bytes::from_static(self.as_bytes()).into_orig_header_name()
        }
    }

    impl IntoOrigHeaderName for String {
        #[inline]
        fn into_orig_header_name(self) -> OrigHeaderName {
            Bytes::from(self).into_orig_header_name()
        }
    }

    impl IntoOrigHeaderName for Bytes {
        #[inline]
        fn into_orig_header_name(self) -> OrigHeaderName {
            OrigHeaderName::Cased(self)
        }
    }

    impl IntoOrigHeaderName for &HeaderName {
        #[inline]
        fn into_orig_header_name(self) -> OrigHeaderName {
            OrigHeaderName::Standard(self.clone())
        }
    }

    impl IntoOrigHeaderName for HeaderName {
        #[inline]
        fn into_orig_header_name(self) -> OrigHeaderName {
            OrigHeaderName::Standard(self)
        }
    }

    impl IntoOrigHeaderName for OrigHeaderName {
        #[inline]
        fn into_orig_header_name(self) -> OrigHeaderName {
            self
        }
    }

    impl IntoOrigHeaderName for &OrigHeaderName {
        #[inline]
        fn into_orig_header_name(self) -> OrigHeaderName {
            self.clone()
        }
    }
}

mod sealed {

    use bytes::Bytes;
    use http::HeaderName;

    use crate::header::OrigHeaderName;

    pub trait Sealed {}

    impl Sealed for &'static str {}
    impl Sealed for String {}
    impl Sealed for Bytes {}
    impl Sealed for &HeaderName {}
    impl Sealed for HeaderName {}
    impl Sealed for &OrigHeaderName {}
    impl Sealed for OrigHeaderName {}
}

#[cfg(test)]
mod test {
    use super::OrigHeaderMap;

    #[test]
    fn test_header_order() {
        let mut headers = OrigHeaderMap::new();

        // Insert headers with different cases and order
        headers.insert("X-Test");
        headers.insert("X-Another");
        headers.insert("x-test2");

        // Check order and case
        let mut iter = headers.iter();
        assert_eq!(iter.next().unwrap().1.as_ref(), b"X-Test");
        assert_eq!(iter.next().unwrap().1.as_ref(), b"X-Another");
        assert_eq!(iter.next().unwrap().1.as_ref(), b"x-test2");
    }

    #[test]
    fn test_extend_preserves_order() {
        use super::OrigHeaderMap;

        let mut map1 = OrigHeaderMap::new();
        map1.insert("A-Header");
        map1.insert("B-Header");

        let mut map2 = OrigHeaderMap::new();
        map2.insert("C-Header");
        map2.insert("D-Header");

        map1.extend(map2);

        let names: Vec<_> = map1.iter().map(|(_, orig)| orig.as_ref()).collect();
        assert_eq!(
            names,
            vec![b"A-Header", b"B-Header", b"C-Header", b"D-Header"]
        );
    }

    #[test]
    fn test_header_case() {
        let mut headers = OrigHeaderMap::new();

        // Insert headers with different cases
        headers.insert("X-Test");
        headers.insert("x-test");

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
        headers.insert("X-test");
        headers.insert("x-test");
        headers.insert("X-test");

        // Check that all variations are stored
        let all_x_test: Vec<_> = headers.get_all(&"x-test".parse().unwrap()).collect();
        assert_eq!(all_x_test.len(), 3);
        assert!(all_x_test.iter().any(|v| v.as_ref() == b"X-test"));
        assert!(all_x_test.iter().any(|v| v.as_ref() == b"x-test"));
        assert!(all_x_test.iter().any(|v| v.as_ref() == b"X-test"));
    }
}
