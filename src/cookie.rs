//! HTTP Cookies

use std::{
    convert::TryInto,
    fmt,
    sync::Arc,
    time::{Duration, SystemTime},
};

use bytes::{BufMut, Bytes};
use cookie_crate::{Cookie as RawCookie, Expiration, SameSite};
use http::Uri;

use crate::{
    error::Error,
    hash::{HASHER, HashMap},
    header::HeaderValue,
    sync::RwLock,
};

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

type NameMap = HashMap<String, RawCookie<'static>>;
type PathMap = HashMap<String, NameMap>;
type DomainMap = HashMap<String, PathMap>;

/// A good default `CookieStore` implementation.
///
/// This is the implementation used when simply calling `cookie_store(true)`.
/// This type is exposed to allow creating one and filling it with some
/// existing cookies more easily, before creating a `Client`.
#[derive(Debug)]
pub struct Jar(RwLock<DomainMap>);

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
    pub fn add_cookie_str(&self, cookie: &str, uri: &Uri) {
        if let Ok(raw) = RawCookie::parse(cookie) {
            self.add_cookie(raw.into_owned(), uri);
        }
    }

    fn add_cookie(&self, cookie: RawCookie<'static>, uri: &Uri) {
        let domain = cookie.domain().or_else(|| uri.host()).unwrap_or_default();
        let path = cookie.path().unwrap_or_else(|| default_path(uri));
        let name = cookie.name();

        let mut inner = self.0.write();
        let name_map = inner
            .entry(domain.to_owned())
            .or_insert_with(|| HashMap::with_hasher(HASHER))
            .entry(path.to_owned())
            .or_insert_with(|| HashMap::with_hasher(HASHER));

        // RFC 6265: If Max-Age=0 or Expires in the past, remove the cookie
        let expired = match cookie.expires() {
            Some(Expiration::DateTime(dt)) => SystemTime::from(dt) <= SystemTime::now(),
            _ => false,
        } || cookie
            .max_age()
            .is_some_and(|age| age == Duration::from_secs(0));

        if expired {
            name_map.remove(name);
        } else {
            name_map.insert(name.to_owned(), cookie);
        }
    }
}

impl CookieStore for Jar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri) {
        let cookies = cookie_headers
            .map(Cookie::try_from)
            .filter_map(Result::ok)
            .map(|cookie| cookie.0.into_owned());

        for cookie in cookies {
            self.add_cookie(cookie, uri);
        }
    }

    fn cookies(&self, uri: &Uri) -> Vec<HeaderValue> {
        let mut cookies = Vec::new();

        let host = match uri.host() {
            Some(h) => h,
            None => return cookies,
        };

        let inner = self.0.read();
        let mut expires = Vec::new();

        // Iterate all possible matching domains (host and parent domains)
        for (domain, path_map) in inner.iter() {
            if domain_match(host, domain) {
                // Path matching: RFC 6265 5.1.4
                for (path, name_map) in path_map.iter() {
                    if path_match(uri.path(), path) {
                        // Collect valid cookies
                        for cookie in name_map.values() {
                            // Check expiry
                            if let Some(Expiration::DateTime(dt)) = cookie.expires() {
                                if SystemTime::from(dt) <= SystemTime::now() {
                                    expires.push(cookie.name().to_owned());
                                    continue;
                                }
                            }

                            let name = cookie.name().as_bytes();
                            let value = cookie.value().as_bytes();
                            let mut cookie_bytes =
                                bytes::BytesMut::with_capacity(name.len() + 1 + value.len());

                            cookie_bytes.put(name);
                            cookie_bytes.put(&b"="[..]);
                            cookie_bytes.put(value);

                            if let Ok(cookie) =
                                HeaderValue::from_maybe_shared(Bytes::from(cookie_bytes))
                            {
                                cookies.push(cookie);
                            }
                        }
                    }
                }
            }
        }

        if !expires.is_empty() {
            // Remove expired cookies
            let mut inner = self.0.write();
            for path_map in inner.values_mut() {
                for name_map in path_map.values_mut() {
                    for name in expires.iter() {
                        name_map.remove(name);
                    }
                }
            }
        }

        cookies
    }
}

// RFC 6265 domain-match
fn domain_match(host: &str, domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }
    if host == domain {
        return true;
    }
    host.ends_with(&format!(".{}", domain))
}

// RFC 6265 path-match
fn path_match(req_path: &str, cookie_path: &str) -> bool {
    req_path == cookie_path
        || req_path.starts_with(cookie_path)
            && (cookie_path.ends_with('/') || req_path[cookie_path.len()..].starts_with('/'))
}

// RFC 6265 default-path
fn default_path(uri: &Uri) -> &str {
    const DEFAULT_PATH: &str = "/";

    let path = uri.path();

    if !path.starts_with(DEFAULT_PATH) {
        return DEFAULT_PATH;
    }

    if let Some(pos) = path.rfind(DEFAULT_PATH) {
        if pos == 0 {
            return DEFAULT_PATH;
        }
        return &path[..pos];
    }

    DEFAULT_PATH
}

impl Default for Jar {
    fn default() -> Self {
        Self(RwLock::new(HashMap::with_hasher(HASHER)))
    }
}
