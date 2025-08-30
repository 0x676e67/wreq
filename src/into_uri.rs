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
impl IntoUri for String {}
impl IntoUri for &str {}
impl IntoUri for &String {}
impl IntoUri for Vec<u8> {}
impl IntoUri for &[u8] {}

mod sealed {
    use std::error::Error as StdError;

    use http::Uri;

    use crate::{Error, Result};

    pub trait IntoUriSealed {
        // Besides parsing as a valid `Uri`.
        fn into_uri(self) -> Result<Uri>;
    }

    impl<T> IntoUriSealed for T
    where
        Uri: TryFrom<T>,
        <Uri as TryFrom<T>>::Error: StdError + Send + Sync + 'static,
    {
        fn into_uri(self) -> Result<Uri> {
            Uri::try_from(self).map_err(Error::builder).and_then(|uri| {
                match (uri.scheme(), uri.authority()) {
                    (Some(_), Some(_)) => Ok(uri),
                    _ => Err(Error::uri_bad_scheme(uri)),
                }
            })
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
}
