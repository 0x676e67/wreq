use std::error::Error as StdError;

use http::Uri;

use crate::Error;

/// Converts a value into a [`Uri`] with error handling.
///
/// This trait is implemented for common types such as [`Uri`], [`String`], [`&str`], and byte
/// slices, as well as any type that can be fallibly converted into a [`Uri`] via [`TryFrom`].
pub trait IntoUri: IntoUriSealed {}

pub trait IntoUriSealed {
    // Besides parsing as a valid `Uri`.
    fn into_uri(self) -> crate::Result<Uri>;
}

// ===== impl IntoUri =====

impl IntoUri for Uri {}
impl IntoUri for &Uri {}
impl IntoUri for String {}
impl IntoUri for &str {}
impl IntoUri for &String {}
impl IntoUri for Vec<u8> {}
impl IntoUri for &[u8] {}

// ===== impl IntoUriSealed =====

impl<T> IntoUriSealed for T
where
    Uri: TryFrom<T>,
    <Uri as TryFrom<T>>::Error: StdError + Send + Sync + 'static,
{
    fn into_uri(self) -> crate::Result<Uri> {
        let uri = Uri::try_from(self).map_err(Error::builder)?;
        if uri.host().is_some() {
            Ok(uri)
        } else {
            Err(Error::url_bad_scheme().with_uri(uri))
        }
    }
}
