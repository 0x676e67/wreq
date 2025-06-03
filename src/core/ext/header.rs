use bytes::Bytes;
use http::{
    HeaderMap, HeaderName,
    header::{IntoHeaderName, ValueIter},
};

/// Maintains an ordered collection of original HTTP header names and their spellings.
///
/// `OriginalHeaders` preserves both the original spelling and the insertion order of header names
/// as they appear in the incoming HTTP request. This is important for scenarios where the exact
/// header casing and order are significant, such as signature verification, protocol compliance,
/// or proxying requests without normalization.
///
/// # Features
/// - Preserves the original spelling (case) of each header name.
/// - Maintains the insertion order of headers as received.
/// - Efficient push and iteration.
/// - Provides capacity management and default initialization.
#[derive(Debug, Clone)]
pub struct OriginalHeaders(HeaderMap<Bytes>);

impl OriginalHeaders {
    /// Creates a new, empty `OriginalHeaders`.
    pub fn new() -> Self {
        Self(HeaderMap::default())
    }

    /// Creates an empty `OriginalHeaders` with the specified capacity.
    #[inline]
    pub fn with_capacity(size: usize) -> Self {
        Self(HeaderMap::with_capacity(size))
    }

    /// Insert a new header name into the collection.
    #[inline]
    pub fn insert<O>(&mut self, orig: O)
    where
        O: TryInto<Bytes>,
    {
        if let Ok(bytes) = orig.try_into() {
            // Convert the original header name to a HeaderName
            if let Ok(name) = HeaderName::from_bytes(bytes.as_ref()) {
                // Append the original header name to the collection
                self.0.append(name, bytes);
            }
        }
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
    pub(crate) fn append<N>(&mut self, name: N, orig: Bytes)
    where
        N: IntoHeaderName,
    {
        self.0.append(name, orig);
    }

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

    /// Returns an iterator over all header names and their original spellings.
    pub(crate) fn keys(&self) -> impl Iterator<Item = &HeaderName> {
        self.0.keys()
    }
}

impl Default for OriginalHeaders {
    /// Creates an empty `OriginalHeaders` with a default capacity of 12.
    #[inline]
    fn default() -> Self {
        Self::with_capacity(12)
    }
}

#[test]
fn test_header_order_and_case() {
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
