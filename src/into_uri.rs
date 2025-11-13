//! URI conversion utilities.
//!
//! This module provides the [`IntoUri`] trait, allowing various types
//! (such as `&str`, `String`, `Vec<u8>`, etc.) to be fallibly converted into an [`http::Uri`].
//! The conversion is based on `TryFrom<T> for Uri` and ensures the resulting URI is valid and
//! contains a host.
//!
//! Internally, the trait is sealed to prevent

use http::Uri;

/// Converts a value into a [`Uri`] with error handling.
///
/// This trait is implemented for common types such as [`Uri`], [`String`], [`&str`], and byte
/// slices, as well as any type that can be fallibly converted into a [`Uri`] via [`TryFrom`].
pub trait IntoUri: sealed::IntoUriSealed {}

impl IntoUri for Uri {}
impl IntoUri for &Uri {}
impl IntoUri for &str {}
impl IntoUri for String {}
impl IntoUri for &String {}
impl IntoUri for Vec<u8> {}
impl IntoUri for &[u8] {}

mod sealed {
    use std::borrow::Cow;

    use bytes::Bytes;
    use http::{
        Uri,
        uri::{Authority, Parts, PathAndQuery, Scheme},
    };

    use crate::{
        Error, Result,
        ext::{PATH, QUERY, USERINFO},
    };

    pub trait IntoUriSealed {
        // Besides parsing as a valid `Uri`.
        fn into_uri(self) -> Result<Uri>;
    }

    impl IntoUriSealed for &[u8] {
        fn into_uri(self) -> Result<Uri> {
            // try to parse directly
            let uri = match Uri::try_from(self) {
                Ok(uri) => uri,
                Err(err) => {
                    let mut parts = Parts::default();

                    // parse scheme and rest directly with "://"
                    let pos = self
                        .windows(3)
                        .position(|window| window == b"://")
                        .ok_or_else(|| Error::builder(err))?;
                    let (scheme, rest) = self.split_at(pos);
                    let rest = &rest[3..];

                    // parse scheme
                    parts.scheme = Scheme::try_from(scheme).map(Some).map_err(Error::builder)?;

                    // split authority and path_and_query
                    let (authority, path_and_query) = match rest.iter().position(|&b| b == b'/') {
                        Some(pos) => rest.split_at(pos),
                        None => (rest, b"" as &[u8]),
                    };

                    // parse authority
                    parts.authority = {
                        let authority = percent_encoding::percent_encode(authority, USERINFO);
                        Authority::from_maybe_shared(Bytes::from(Cow::from(authority).into_owned()))
                            .map(Some)
                            .map_err(Error::builder)?
                    };

                    // parse and percent-encode path_and_query
                    if !path_and_query.is_empty() {
                        const PQ_SPLIT: char = '?';

                        parts.path_and_query =
                            match path_and_query.iter().position(|&b| b == (PQ_SPLIT as u8)) {
                                Some(pos) => {
                                    let (path, query) = path_and_query.split_at(pos);
                                    let encoded_path =
                                        Cow::from(percent_encoding::percent_encode(path, PATH));
                                    let encoded_query = Cow::from(
                                        percent_encoding::percent_encode(&query[1..], QUERY),
                                    );

                                    let path_and_query = match (encoded_path, encoded_query) {
                                        (Cow::Owned(mut path), query) => {
                                            path.push(PQ_SPLIT);
                                            path.extend(query.chars());
                                            path
                                        }
                                        (path, Cow::Owned(mut query)) => {
                                            query.reserve(path.len() + 1);
                                            query.insert(0, PQ_SPLIT);
                                            query.insert_str(0, &path);
                                            query
                                        }
                                        (Cow::Borrowed(path), Cow::Borrowed(query)) => {
                                            let mut path_and_query =
                                                String::with_capacity(path.len() + query.len() + 1);
                                            path_and_query.push_str(path);
                                            path_and_query.push(PQ_SPLIT);
                                            path_and_query.push_str(query);
                                            path_and_query
                                        }
                                    };

                                    PathAndQuery::from_maybe_shared(Bytes::from(path_and_query))
                                        .map(Some)
                                        .map_err(Error::builder)?
                                }
                                None => {
                                    let encoded_path =
                                        percent_encoding::percent_encode(path_and_query, PATH);

                                    PathAndQuery::from_maybe_shared(Bytes::from(
                                        Cow::from(encoded_path).into_owned(),
                                    ))
                                    .map(Some)
                                    .map_err(Error::builder)?
                                }
                            };
                    }

                    // Reconstruct Uri
                    Uri::from_parts(parts).map_err(Error::builder)?
                }
            };

            match (uri.scheme(), uri.authority()) {
                (Some(_), Some(_)) => Ok(uri),
                _ => Err(Error::uri_bad_scheme(uri)),
            }
        }
    }

    impl IntoUriSealed for Vec<u8> {
        #[inline]
        fn into_uri(self) -> Result<Uri> {
            IntoUriSealed::into_uri(self.as_slice())
        }
    }

    impl IntoUriSealed for &str {
        #[inline]
        fn into_uri(self) -> Result<Uri> {
            IntoUriSealed::into_uri(self.as_bytes())
        }
    }

    impl IntoUriSealed for String {
        #[inline]
        fn into_uri(self) -> Result<Uri> {
            IntoUriSealed::into_uri(self.as_str())
        }
    }

    impl IntoUriSealed for &String {
        #[inline]
        fn into_uri(self) -> Result<Uri> {
            IntoUriSealed::into_uri(self.as_str())
        }
    }

    impl IntoUriSealed for Uri {
        fn into_uri(self) -> Result<Uri> {
            match (self.scheme(), self.authority()) {
                (Some(_), Some(_)) => Ok(self),
                _ => Err(Error::uri_bad_scheme(self)),
            }
        }
    }

    impl IntoUriSealed for &Uri {
        fn into_uri(self) -> Result<Uri> {
            match (self.scheme(), self.authority()) {
                (Some(_), Some(_)) => Ok(self.clone()),
                _ => Err(Error::uri_bad_scheme(self.clone())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sealed::IntoUriSealed;

    #[test]
    fn into_uri_bad_scheme() {
        let err = "/hello/world".into_uri().unwrap_err();
        assert_eq!(
            err.to_string(),
            "builder error for uri (/hello/world): URI scheme is not allowed"
        );

        let err = "127.0.0.1".into_uri().unwrap_err();
        assert_eq!(
            err.to_string(),
            "builder error for uri (127.0.0.1): URI scheme is not allowed"
        );
    }

    #[test]
    fn into_uri_with_space_in_path() {
        let uri = "http://example.com/hello world".into_uri().unwrap();
        assert_eq!(uri, "http://example.com/hello%20world");
    }

    #[test]
    fn into_uri_with_unicode_in_path() {
        let uri = "http://example.com/文件/测试".into_uri().unwrap();
        assert_eq!(uri, "http://example.com/文件/测试");
    }

    #[test]
    fn into_uri_with_special_chars_in_path() {
        let uri = "http://example.com/path<>{}".into_uri().unwrap();
        assert_eq!(uri, "http://example.com/path%3C%3E%7B%7D");
    }

    #[test]
    fn into_uri_with_query_preserved() {
        let uri = "http://example.com/path?key=value&foo=bar"
            .into_uri()
            .unwrap();
        assert_eq!(uri, "http://example.com/path?key=value&foo=bar");
    }

    #[test]
    fn into_uri_bytes_with_encoding() {
        let bytes = b"http://example.com/hello world";
        let uri = bytes.as_slice().into_uri().unwrap();
        assert_eq!(uri, "http://example.com/hello%20world");
    }

    #[test]
    fn test_bytes_with_query() {
        let bytes = b"http://example.com/path?key=hello%20world";
        let uri = bytes.as_slice().into_uri().unwrap();
        assert_eq!(uri.to_string(), "http://example.com/path?key=hello%20world");
    }

    #[test]
    fn test_bytes_with_unicode() {
        let bytes = b"http://example.com/\xE6\xB5\x8B\xE8\xAF\x95";
        let uri = bytes.as_slice().into_uri().unwrap();
        assert_eq!(uri, "http://example.com/测试");
    }

    #[test]
    fn test_bytes_minimal() {
        let bytes = b"http://example.com";
        let uri = bytes.as_slice().into_uri().unwrap();
        assert_eq!(uri, "http://example.com");
    }

    #[test]
    fn test_bytes_invalid_utf8() {
        let bytes = b"http://example.com/\xFF\xFF";
        let uri = bytes.as_slice().into_uri().unwrap();
        assert_eq!(uri, "http://example.com/%FF%FF");
    }
}
