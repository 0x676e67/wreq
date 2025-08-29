use std::{borrow::Cow, error::Error as _};

use http::Uri;
use percent_encoding::{AsciiSet, CONTROLS, NON_ALPHANUMERIC, percent_encode};

use crate::{Error, error::BadScheme};

/// A trait to try to convert some type into a `Uri`.
///
/// This trait is "sealed", such that only types within wreq can
/// implement it.
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

// ===== impl IntoUriSealed =====

impl IntoUriSealed for Uri {
    fn into_uri(self) -> crate::Result<Uri> {
        if self.host().is_some() {
            Ok(self)
        } else {
            Err(Error::url_bad_scheme().with_uri(self))
        }
    }
}

impl IntoUriSealed for &Uri {
    fn into_uri(self) -> crate::Result<Uri> {
        self.clone().into_uri()
    }
}

impl<T> IntoUriSealed for T
where
    T: AsRef<str> + sealed::Sealed,
{
    fn into_uri(self) -> crate::Result<Uri> {
        Uri::try_from(self.as_ref())
            .map_err(Error::builder)?
            .into_uri()
    }
}

mod sealed {
    use http::Uri;

    pub trait Sealed {}

    impl Sealed for &str {}
    impl Sealed for &String {}
    impl Sealed for String {}
}
