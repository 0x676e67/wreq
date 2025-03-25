//! HTTP Cookies

use crate::header::{HeaderValue, SET_COOKIE};
#[cfg(feature = "cookies")]
use antidote::RwLock;
pub use cookie_crate::{Cookie as RawCookie, Expiration, SameSite, time::Duration};
use std::borrow::Cow;
use std::convert::TryInto;
use std::fmt;
use std::time::SystemTime;

/// Actions for a persistent cookie store providing session support.
pub trait CookieStore: Send + Sync {
    /// Store a set of Set-Cookie header values received from `url`
    fn set_cookies(&self, url: &url::Url, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>);

    /// Store a cookie into the store for `url`
    fn set_cookie(&self, _url: &url::Url, _cookie: &dyn IntoCookie) {}

    /// Get any Cookie values in the store for `url`
    fn cookies(&self, url: &url::Url) -> Option<HeaderValue>;

    /// Removes a Cookie value in the store for `url` and `name`
    fn remove(&self, _url: &url::Url, _name: &str) {}

    /// Clear all cookies from the store.
    fn clear(&self) {}
}

/// A trait for types that can be converted into a `Cookie`.
pub trait IntoCookie {
    /// Convert into a `Cookie`.
    fn into(&self) -> Result<Cow<'_, Cookie<'_>>, crate::Error>;
}

/// A single HTTP cookie.
#[derive(Debug, Clone)]
pub struct Cookie<'a>(RawCookie<'a>);

/// A builder for a `Cookie`.
#[derive(Debug, Clone)]
pub struct CookieBuilder<'a>(cookie_crate::CookieBuilder<'a>);

/// A good default `CookieStore` implementation.
///
/// This is the implementation used when simply calling `cookie_store(true)`.
/// This type is exposed to allow creating one and filling it with some
/// existing cookies more easily, before creating a `Client`.
#[cfg(feature = "cookies")]
#[derive(Debug)]
pub struct Jar(RwLock<cookie_store::CookieStore>);

// ===== impl Cookie =====
impl<'a> Cookie<'a> {
    /// Parse a `Cookie` from a `AsRef<[u8]>`.
    pub fn parse<V>(value: &'a V) -> Result<Cookie<'a>, crate::Error>
    where
        V: AsRef<[u8]> + ?Sized,
    {
        std::str::from_utf8(value.as_ref())
            .map_err(cookie_crate::ParseError::from)
            .and_then(RawCookie::parse)
            .map(Cookie)
            .map_err(Into::into)
    }

    /// Creates a new `CookieBuilder` instance from the given name and value.
    #[inline(always)]
    pub fn builder<N, V>(name: N, value: V) -> CookieBuilder<'a>
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        CookieBuilder::new(name, value)
    }

    /// Creates a new `Cookie` instance from the given name and value.
    #[inline(always)]
    pub fn new<N, V>(name: N, value: V) -> Cookie<'a>
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        Cookie(RawCookie::new(name, value))
    }

    /// The name of the cookie.
    #[inline(always)]
    pub fn name(&self) -> &str {
        self.0.name()
    }

    /// The value of the cookie.
    #[inline(always)]
    pub fn value(&self) -> &str {
        self.0.value()
    }

    /// Returns true if the 'HttpOnly' directive is enabled.
    #[inline(always)]
    pub fn http_only(&self) -> bool {
        self.0.http_only().unwrap_or(false)
    }

    /// Returns true if the 'Secure' directive is enabled.
    #[inline(always)]
    pub fn secure(&self) -> bool {
        self.0.secure().unwrap_or(false)
    }

    /// Returns true if  'SameSite' directive is 'Lax'.
    #[inline(always)]
    pub fn same_site_lax(&self) -> bool {
        self.0.same_site() == Some(cookie_crate::SameSite::Lax)
    }

    /// Returns true if  'SameSite' directive is 'Strict'.
    #[inline(always)]
    pub fn same_site_strict(&self) -> bool {
        self.0.same_site() == Some(cookie_crate::SameSite::Strict)
    }

    /// Returns the path directive of the cookie, if set.
    #[inline(always)]
    pub fn path(&self) -> Option<&str> {
        self.0.path()
    }

    /// Returns the domain directive of the cookie, if set.
    #[inline(always)]
    pub fn domain(&self) -> Option<&str> {
        self.0.domain()
    }

    /// Get the Max-Age information.
    #[inline(always)]
    pub fn max_age(&self) -> Option<std::time::Duration> {
        self.0.max_age().and_then(|d| d.try_into().ok())
    }

    /// The cookie expiration time.
    #[inline(always)]
    pub fn expires(&self) -> Option<SystemTime> {
        match self.0.expires() {
            Some(cookie_crate::Expiration::DateTime(offset)) => Some(SystemTime::from(offset)),
            None | Some(cookie_crate::Expiration::Session) => None,
        }
    }

    /// Returns the cookie as owned.
    #[inline(always)]
    pub fn into_owned(self) -> Cookie<'static> {
        Cookie(self.0.into_owned())
    }

    /// Returns the inner `cookie_crate::Cookie` instance.
    #[inline(always)]
    pub fn into_inner(self) -> RawCookie<'a> {
        self.0
    }
}

impl fmt::Display for Cookie<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

// ===== impl CookieBuilder =====
impl<'c> CookieBuilder<'c> {
    /// Creates a new `CookieBuilder` instance from the given name and value.
    pub fn new<N, V>(name: N, value: V) -> Self
    where
        N: Into<Cow<'c, str>>,
        V: Into<Cow<'c, str>>,
    {
        CookieBuilder(cookie_crate::CookieBuilder::new(name, value))
    }

    /// Set the 'HttpOnly' directive.
    #[inline(always)]
    pub fn http_only(mut self, enabled: bool) -> Self {
        self.0 = self.0.http_only(enabled);
        self
    }

    /// Set the 'Secure' directive.
    #[inline(always)]
    pub fn secure(mut self, enabled: bool) -> Self {
        self.0 = self.0.secure(enabled);
        self
    }

    /// Set the 'SameSite' directive.
    #[inline(always)]
    pub fn same_site(mut self, same_site: cookie_crate::SameSite) -> Self {
        self.0 = self.0.same_site(same_site);
        self
    }

    /// Set the path directive.
    #[inline(always)]
    pub fn path<P>(mut self, path: P) -> Self
    where
        P: Into<Cow<'c, str>>,
    {
        self.0 = self.0.path(path);
        self
    }

    /// Set the domain directive.
    #[inline(always)]
    pub fn domain<D>(mut self, domain: D) -> Self
    where
        D: Into<Cow<'c, str>>,
    {
        self.0 = self.0.domain(domain);
        self
    }

    /// Set the Max-Age directive.
    #[inline(always)]
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.0 = self.0.max_age(max_age);
        self
    }

    /// Set the expiration time.
    #[inline(always)]
    pub fn expires<E>(mut self, expires: E) -> Self
    where
        E: Into<Expiration>,
    {
        self.0 = self.0.expires(expires);
        self
    }

    /// Build the `Cookie`.
    #[inline(always)]
    pub fn build(self) -> Cookie<'c> {
        Cookie(self.0.build())
    }
}

pub(crate) fn extract_response_cookie_headers(
    headers: &hyper2::HeaderMap,
) -> impl Iterator<Item = &'_ HeaderValue> {
    headers.get_all(SET_COOKIE).iter()
}

pub(crate) fn extract_response_cookies(
    headers: &hyper2::HeaderMap,
) -> impl Iterator<Item = Result<Cookie<'_>, crate::Error>> {
    headers.get_all(SET_COOKIE).iter().map(Cookie::parse)
}

// ===== impl IntoCookie =====
impl IntoCookie for &HeaderValue {
    #[inline]
    fn into(&self) -> Result<Cow<'_, Cookie<'_>>, crate::Error> {
        Cookie::parse(self).map(Cow::Owned)
    }
}

impl IntoCookie for HeaderValue {
    #[inline]
    fn into(&self) -> Result<Cow<'_, Cookie<'_>>, crate::Error> {
        Cookie::parse(self).map(Cow::Owned)
    }
}

impl IntoCookie for &Cookie<'_> {
    #[inline]
    fn into(&self) -> Result<Cow<'_, Cookie<'_>>, crate::Error> {
        Ok(Cow::Borrowed(self))
    }
}

impl IntoCookie for Cookie<'_> {
    #[inline]
    fn into(&self) -> Result<Cow<'_, Cookie<'_>>, crate::Error> {
        Ok(Cow::Borrowed(self))
    }
}

// ===== impl Jar =====
#[cfg(feature = "cookies")]
impl Jar {
    /// Add a cookie to this jar.
    ///
    /// # Example
    ///
    /// ```
    /// use rquest::{cookie::Jar, Url};
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
        let cookies = RawCookie::parse(cookie)
            .ok()
            .map(|c| c.into_owned())
            .into_iter();
        self.0.write().store_response_cookies(cookies, url);
    }
}

#[cfg(feature = "cookies")]
impl CookieStore for Jar {
    fn set_cookies(&self, url: &url::Url, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>) {
        let iter = cookie_headers
            .filter_map(|val| Cookie::parse(val.as_bytes()).map(|c| c.0.into_owned()).ok());

        self.0.write().store_response_cookies(iter, url);
    }

    fn cookies(&self, url: &url::Url) -> Option<HeaderValue> {
        let lock = self.0.read();
        let mut iter = lock.get_request_values(url);

        let (first_name, first_value) = iter.next()?;

        let mut cookie = String::with_capacity(32);
        cookie.push_str(first_name);
        cookie.push('=');
        cookie.push_str(first_value);
        for (name, value) in iter {
            cookie.push_str("; ");
            cookie.push_str(name);
            cookie.push('=');
            cookie.push_str(value);
        }

        HeaderValue::from_maybe_shared(bytes::Bytes::from(cookie)).ok()
    }

    fn set_cookie<'c>(&self, url: &url::Url, cookie: &dyn IntoCookie) {
        if let Ok(cookie) = cookie.into() {
            let _ = self.0.write().insert_raw(&cookie.0, url);
        }
    }

    fn remove(&self, url: &url::Url, name: &str) {
        if let Some(domain) = url.host_str() {
            self.0.write().remove(domain, url.path(), name);
        }
    }

    fn clear(&self) {
        self.0.write().clear();
    }
}

#[cfg(feature = "cookies")]
impl Default for Jar {
    fn default() -> Self {
        Self(RwLock::new(cookie_store::CookieStore::default()))
    }
}
