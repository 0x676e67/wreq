use std::{convert::TryInto, fmt, time::SystemTime};

use cookie::{Cookie as RawCookie, Expiration, SameSite};

use crate::{error::Error, header::HeaderValue};

/// A parsed HTTP cookie.
#[derive(Debug, Clone)]
pub struct Cookie<'a>(RawCookie<'a>);

impl<'a> Cookie<'a> {
    pub(crate) fn parse(value: &'a HeaderValue) -> crate::Result<Cookie<'a>> {
        std::str::from_utf8(value.as_bytes())
            .map_err(cookie::ParseError::from)
            .and_then(cookie::Cookie::parse)
            .map_err(Error::decode)
            .map(Cookie)
    }

    /// Returns the name of `self`.
    #[inline]
    pub fn name(&self) -> &str {
        self.0.name()
    }

    /// Returns the value of `self`.
    ///
    /// Does not strip surrounding quotes.
    #[inline]
    pub fn value(&self) -> &str {
        self.0.value()
    }

    /// Returns whether this cookie was marked `HttpOnly` or not.
    #[inline]
    pub fn http_only(&self) -> bool {
        self.0.http_only().unwrap_or(false)
    }

    /// Returns whether this cookie was marked `Secure` or not.
    #[inline]
    pub fn secure(&self) -> bool {
        self.0.secure().unwrap_or(false)
    }

    /// Returns whether the `SameSite` attribute of this cookie is `Lax`.
    #[inline]
    pub fn same_site_lax(&self) -> bool {
        self.0.same_site() == Some(SameSite::Lax)
    }

    /// Returns whether the `SameSite` attribute of this cookie is `Strict`.
    #[inline]
    pub fn same_site_strict(&self) -> bool {
        self.0.same_site() == Some(SameSite::Strict)
    }

    /// Returns the `Path` of the cookie if one was specified.
    #[inline]
    pub fn path(&self) -> Option<&str> {
        self.0.path()
    }

    /// Returns the `Domain` of the cookie if one was specified.
    ///
    /// This does not consider whether the `Domain` is valid; validation is left to higher-level
    /// libraries, as needed. However, if the `Domain` starts with a leading `.`, the leading `.` is
    /// stripped.
    #[inline]
    pub fn domain(&self) -> Option<&str> {
        self.0.domain()
    }

    /// Returns the specified max-age of the cookie if it is non-negative and representable.
    #[inline]
    pub fn max_age(&self) -> Option<std::time::Duration> {
        self.0.max_age().and_then(|d| d.try_into().ok())
    }

    /// Returns the expiration date-time of the cookie if one was specified.
    ///
    /// Session cookies return `None`.
    #[inline]
    pub fn expires(&self) -> Option<SystemTime> {
        match self.0.expires() {
            Some(Expiration::DateTime(offset)) => Some(SystemTime::from(offset)),
            None | Some(Expiration::Session) => None,
        }
    }

    /// Converts `self` into a `Cookie` with a static lifetime with as few allocations as possible.
    #[inline]
    pub fn into_owned(self) -> Cookie<'static> {
        Cookie(self.0.into_owned())
    }
}

impl fmt::Display for Cookie<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'c> From<RawCookie<'c>> for Cookie<'c> {
    #[inline]
    fn from(cookie: RawCookie<'c>) -> Cookie<'c> {
        Cookie(cookie)
    }
}

impl<'c> From<Cookie<'c>> for RawCookie<'c> {
    #[inline]
    fn from(cookie: Cookie<'c>) -> RawCookie<'c> {
        cookie.0
    }
}
