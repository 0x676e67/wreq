//! HTTP Cookies

use std::{convert::TryInto, fmt, sync::Arc, time::SystemTime};

use bytes::{BufMut, Bytes};
use cookie_crate::{Cookie as RawCookie, Expiration, SameSite};
use http::Uri;

use crate::{error::Error, header::HeaderValue, sync::RwLock};

/// Actions for a persistent cookie store providing session support.
pub trait CookieStore: Send + Sync {
    /// Store a set of Set-Cookie header values received from `uri`
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri);

    /// Get any Cookie values in the store for `uri`
    fn cookies(&self, uri: &Uri) -> Vec<HeaderValue>;
}

/// Trait for converting types into a shared cookie store ([`Arc<dyn CookieStore>`]).
///
/// Implemented for any [`CookieStore`] type, [`Arc<T>`] where `T: CookieStore`, and [`Arc<dyn
/// CookieStore>`]. Enables ergonomic conversion to a trait object for use in APIs without manual
/// boxing.
pub trait IntoCookieStore {
    /// Converts the implementor into an [`Arc<dyn CookieStore>`].
    ///
    /// This method allows ergonomic conversion of concrete cookie stores, [`Arc<T>`], or
    /// existing [`Arc<dyn CookieStore>`] into a trait object suitable for APIs that expect
    /// a shared cookie store.
    fn into_cookie_store(self) -> Arc<dyn CookieStore>;
}

/// A single HTTP cookie.
#[derive(Debug, Clone)]
pub struct Cookie<'a>(RawCookie<'a>);

/// A good default `CookieStore` implementation.
///
/// This is the implementation used when simply calling `cookie_store(true)`.
/// This type is exposed to allow creating one and filling it with some
/// existing cookies more easily, before creating a `Client`.
#[derive(Debug)]
pub struct Jar(RwLock<cookie_store::CookieStore>);

// ===== impl IntoCookieStore =====

impl IntoCookieStore for Arc<dyn CookieStore> {
    #[inline]
    fn into_cookie_store(self) -> Arc<dyn CookieStore> {
        self
    }
}

impl<R> IntoCookieStore for Arc<R>
where
    R: CookieStore + 'static,
{
    #[inline]
    fn into_cookie_store(self) -> Arc<dyn CookieStore> {
        self
    }
}

impl<R> IntoCookieStore for R
where
    R: CookieStore + 'static,
{
    #[inline]
    fn into_cookie_store(self) -> Arc<dyn CookieStore> {
        Arc::new(self)
    }
}

// ===== impl Cookie =====

impl<'a> Cookie<'a> {
    /// The name of the cookie.
    #[inline]
    pub fn name(&self) -> &str {
        self.0.name()
    }

    /// The value of the cookie.
    #[inline]
    pub fn value(&self) -> &str {
        self.0.value()
    }

    /// Returns true if the 'HttpOnly' directive is enabled.
    #[inline]
    pub fn http_only(&self) -> bool {
        self.0.http_only().unwrap_or(false)
    }

    /// Returns true if the 'Secure' directive is enabled.
    #[inline]
    pub fn secure(&self) -> bool {
        self.0.secure().unwrap_or(false)
    }

    /// Returns true if  'SameSite' directive is 'Lax'.
    #[inline]
    pub fn same_site_lax(&self) -> bool {
        self.0.same_site() == Some(SameSite::Lax)
    }

    /// Returns true if  'SameSite' directive is 'Strict'.
    #[inline]
    pub fn same_site_strict(&self) -> bool {
        self.0.same_site() == Some(SameSite::Strict)
    }

    /// Returns the path directive of the cookie, if set.
    #[inline]
    pub fn path(&self) -> Option<&str> {
        self.0.path()
    }

    /// Returns the domain directive of the cookie, if set.
    #[inline]
    pub fn domain(&self) -> Option<&str> {
        self.0.domain()
    }

    /// Get the Max-Age information.
    #[inline]
    pub fn max_age(&self) -> Option<std::time::Duration> {
        self.0.max_age().and_then(|d| d.try_into().ok())
    }

    /// The cookie expiration time.
    #[inline]
    pub fn expires(&self) -> Option<SystemTime> {
        match self.0.expires() {
            Some(Expiration::DateTime(offset)) => Some(SystemTime::from(offset)),
            None | Some(Expiration::Session) => None,
        }
    }

    /// Converts `self` into a `Cookie` with a static lifetime with as few
    /// allocations as possible.
    #[inline]
    pub fn into_owned(self) -> Cookie<'static> {
        Cookie(self.0.into_owned())
    }
}

impl fmt::Display for Cookie<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a> TryFrom<&'a HeaderValue> for Cookie<'a> {
    type Error = crate::Error;

    fn try_from(value: &'a HeaderValue) -> Result<Self, Self::Error> {
        std::str::from_utf8(value.as_bytes())
            .map_err(cookie_crate::ParseError::from)
            .and_then(cookie_crate::Cookie::parse)
            .map_err(Error::decode)
            .map(Cookie)
    }
}

// ===== impl Jar =====

impl Jar {
    /// Add a cookie str to this jar.
    ///
    /// # Example
    ///
    /// ```
    /// use wreq::{
    ///     Url,
    ///     cookie::Jar,
    /// };
    ///
    /// let cookie = "foo=bar; Domain=yolo.local";
    /// let url = "https://yolo.local".parse::<Url>().unwrap();
    ///
    /// let jar = Jar::default();
    /// jar.add_cookie_str(cookie, &url);
    ///
    /// // and now add to a `ClientBuilder`?
    /// ```
    pub fn add_cookie_str(&self, cookie: &str, url: &url::Url) {
        let cookies = cookie_crate::Cookie::parse(cookie)
            .ok()
            .map(|c| c.into_owned())
            .into_iter();
        self.0.write().store_response_cookies(cookies, url);
    }
}

impl CookieStore for Jar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri) {
        let iter = cookie_headers
            .map(Cookie::try_from)
            .filter_map(Result::ok)
            .map(|cookie| cookie.0.into_owned());

        if let Ok(url) = url::Url::parse(&uri.to_string()) {
            self.0.write().store_response_cookies(iter, &url);
        }
    }

    fn cookies(&self, uri: &Uri) -> Vec<HeaderValue> {
        const COOKIE_SEPARATOR: &[u8] = b"=";

        if let Ok(url) = url::Url::parse(&uri.to_string()) {
            return self
                .0
                .read()
                .get_request_values(&url)
                .filter_map(|(name, value)| {
                    let name = name.as_bytes();
                    let value = value.as_bytes();
                    let mut cookie = bytes::BytesMut::with_capacity(name.len() + 1 + value.len());

                    cookie.put(name);
                    cookie.put(COOKIE_SEPARATOR);
                    cookie.put(value);

                    HeaderValue::from_maybe_shared(Bytes::from(cookie)).ok()
                })
                .collect();
        }

        Vec::new()
    }
}

impl Default for Jar {
    fn default() -> Self {
        Self(RwLock::new(cookie_store::CookieStore::default()))
    }
}
