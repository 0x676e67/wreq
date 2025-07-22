//! HTTP Cookies

use std::{borrow::Cow, convert::TryInto, fmt, time::SystemTime};

use bytes::BufMut;
pub use cookie_crate::{Cookie as RawCookie, Expiration, SameSite, time::Duration};

use crate::{
    error::Error,
    header::{HeaderValue, SET_COOKIE},
    sync::RwLock,
};

/// Actions for a persistent cookie store providing session support.
pub trait CookieStore: Send + Sync {
    /// Store a set of Set-Cookie header values received from `url`
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &url::Url);

    /// Get any Cookie values in the store for `url`
    fn cookies(&self, url: &url::Url) -> Option<Vec<HeaderValue>>;
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
#[derive(Debug)]
pub struct Jar(RwLock<cookie_store::CookieStore>);

// ===== impl Cookie =====
impl<'a> Cookie<'a> {
    fn parse(value: &'a HeaderValue) -> crate::Result<Cookie<'a>> {
        std::str::from_utf8(value.as_bytes())
            .map_err(cookie_crate::ParseError::from)
            .and_then(cookie_crate::Cookie::parse)
            .map_err(Error::decode)
            .map(Cookie)
    }

    /// Creates a new `CookieBuilder` instance from the given name and value.
    #[inline]
    pub fn builder<N, V>(name: N, value: V) -> CookieBuilder<'a>
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        CookieBuilder::new(name, value)
    }

    /// Creates a new `Cookie` instance from the given name and value.
    #[inline]
    pub fn new<N, V>(name: N, value: V) -> Cookie<'a>
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        Cookie(RawCookie::new(name, value))
    }

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

    /// Returns the raw cookie.
    #[inline]
    pub fn into_raw(self) -> RawCookie<'a> {
        self.0
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
    #[inline]
    pub fn http_only(mut self, enabled: bool) -> Self {
        self.0 = self.0.http_only(enabled);
        self
    }

    /// Set the 'Secure' directive.
    #[inline]
    pub fn secure(mut self, enabled: bool) -> Self {
        self.0 = self.0.secure(enabled);
        self
    }

    /// Set the 'SameSite' directive.
    #[inline]
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.0 = self.0.same_site(same_site);
        self
    }

    /// Set the path directive.
    #[inline]
    pub fn path<P>(mut self, path: P) -> Self
    where
        P: Into<Cow<'c, str>>,
    {
        self.0 = self.0.path(path);
        self
    }

    /// Set the domain directive.
    #[inline]
    pub fn domain<D>(mut self, domain: D) -> Self
    where
        D: Into<Cow<'c, str>>,
    {
        self.0 = self.0.domain(domain);
        self
    }

    /// Set the Max-Age directive.
    #[inline]
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.0 = self.0.max_age(max_age);
        self
    }

    /// Set the expiration time.
    #[inline]
    pub fn expires<E>(mut self, expires: E) -> Self
    where
        E: Into<Expiration>,
    {
        self.0 = self.0.expires(expires);
        self
    }

    /// Build the `Cookie`.
    #[inline]
    pub fn build(self) -> Cookie<'c> {
        Cookie(self.0.build())
    }
}

pub(crate) fn extract_response_cookies(
    headers: &http::HeaderMap,
) -> impl Iterator<Item = crate::Result<Cookie<'_>>> {
    headers.get_all(SET_COOKIE).iter().map(Cookie::parse)
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

    /// Add a cookie to this jar.
    ///
    /// # Example
    ///
    /// ```
    /// use wreq::{
    ///     Url,
    ///     cookie::{
    ///         Cookie,
    ///         Jar,
    ///     },
    /// };
    ///
    /// let cookie = Cookie::new("foo", "bar");
    /// let url = "https://yolo.local".parse::<Url>().unwrap();
    ///
    /// let jar = Jar::default();
    /// jar.add_cookie(cookie, &url);
    ///
    /// // and now add to a `ClientBuilder`?
    /// ```
    pub fn add_cookie(&self, cookie: Cookie<'_>, url: &url::Url) {
        let _ = self.0.write().insert_raw(&cookie.0, url);
    }

    /// Removes a `Cookie` from the store, returning the `Cookie` if it was in the jar.
    ///
    /// # Example
    ///
    /// ```
    /// use wreq::{
    ///     Url,
    ///     cookie::Jar,
    /// };
    ///
    /// // add a cookie
    /// let cookie = "foo=bar; Domain=yolo.local";
    /// let url = "https://yolo.local".parse::<Url>().unwrap();
    /// let jar = Jar::default();
    /// jar.add_cookie_str(cookie, &url);
    ///
    /// // remove the cookie
    /// jar.remove("foo", &url);
    /// ```
    pub fn remove(&self, name: &str, url: &url::Url) {
        if let Some(domain) = url.host_str() {
            self.0.write().remove(domain, url.path(), name);
        }
    }

    /// Clear the contents of the jar.
    ///
    /// # Example
    /// ```
    /// use wreq::{
    ///     Url,
    ///     cookie::Jar,
    /// };
    ///
    /// // add a cookie
    /// let cookie = "foo=bar; Domain=yolo.local";
    /// let url = "https://yolo.local".parse::<Url>().unwrap();
    /// let jar = Jar::default();
    /// jar.add_cookie_str(cookie, &url);
    ///
    /// // remove all cookies
    /// jar.clear();
    /// ```
    pub fn clear(&self) {
        self.0.write().clear();
    }
}

impl CookieStore for Jar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &url::Url) {
        let iter =
            cookie_headers.filter_map(|val| Cookie::parse(val).map(|c| c.0.into_owned()).ok());

        self.0.write().store_response_cookies(iter, url);
    }

    fn cookies(&self, url: &url::Url) -> Option<Vec<HeaderValue>> {
        let mut cookies = Vec::new();
        let lock = self.0.read();
        for (name, value) in lock.get_request_values(url) {
            let mut cookie = bytes::BytesMut::with_capacity(64);
            cookie.put(name.as_bytes());
            cookie.put(&b"="[..]);
            cookie.put(value.as_bytes());
            if let Ok(cookie) = HeaderValue::from_maybe_shared(cookie) {
                cookies.push(cookie);
            }
        }

        if cookies.is_empty() {
            None
        } else {
            Some(cookies)
        }
    }
}

impl Default for Jar {
    fn default() -> Self {
        Self(RwLock::new(cookie_store::CookieStore::default()))
    }
}
