//! HTTP Cookies

use std::{
    convert::TryInto,
    fmt,
    sync::Arc,
    time::{Duration, SystemTime},
};

use bytes::{BufMut, Bytes};
use cookie::{Cookie as RawCookie, CookieJar, Expiration, SameSite};
use http::Uri;

use crate::{
    error::Error,
    ext::UriExt,
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

/// A good default `CookieStore` implementation.
///
/// This is the implementation used when simply calling `cookie_store(true)`.
/// This type is exposed to allow creating one and filling it with some
/// existing cookies more easily, before creating a `Client`.
pub struct Jar(RwLock<HashMap<String, HashMap<String, CookieJar>>>);

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
    pub(crate) fn parse(value: &'a HeaderValue) -> crate::Result<Cookie<'a>> {
        std::str::from_utf8(value.as_bytes())
            .map_err(cookie::ParseError::from)
            .and_then(cookie::Cookie::parse)
            .map_err(Error::decode)
            .map(Cookie)
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

impl<'c> From<RawCookie<'c>> for Cookie<'c> {
    fn from(cookie: RawCookie<'c>) -> Cookie<'c> {
        Cookie(cookie)
    }
}

impl<'c> From<Cookie<'c>> for RawCookie<'c> {
    fn from(cookie: Cookie<'c>) -> RawCookie<'c> {
        cookie.0
    }
}

// ===== impl Jar =====

macro_rules! into_uri {
    ($expr:expr) => {
        match Uri::try_from($expr) {
            Ok(u) => u,
            Err(_) => return,
        }
    };
}

impl Jar {
    /// Get a cookie by name for a given Uri.
    ///
    /// Returns the cookie with the specified name for the domain and path
    /// derived from the given Uri, if it exists.
    ///
    /// # Example
    /// ```
    /// use wreq::cookie::Jar;
    /// let jar = Jar::default();
    /// jar.add_cookie_str("foo=bar; Path=/foo; Domain=example.com", "http://example.com/foo");
    /// let cookie = jar.get("foo", "http://example.com/foo").unwrap();
    /// assert_eq!(cookie.value(), "bar");
    /// ```
    pub fn get<U>(&self, name: &str, uri: U) -> Option<Cookie<'static>>
    where
        Uri: TryFrom<U>,
    {
        let uri = Uri::try_from(uri).ok()?;
        let cookie = self
            .0
            .read()
            .get(uri.host()?)?
            .get(uri.path())?
            .get(name)?
            .clone()
            .into_owned();
        Some(Cookie(cookie))
    }

    /// Get all cookies in this jar.
    ///
    /// Returns an iterator over all cookies currently stored in the jar,
    /// regardless of domain or path.
    ///
    /// # Example
    /// ```
    /// use wreq::cookie::Jar;
    /// let jar = Jar::default();
    /// jar.add_cookie_str("foo=bar; Domain=example.com", "http://example.com");
    /// for cookie in jar.get_all() {
    ///     println!("{}={}", cookie.name(), cookie.value());
    /// }
    /// ```
    pub fn get_all(&self) -> impl Iterator<Item = Cookie<'static>> {
        self.0
            .read()
            .iter()
            .flat_map(|(_, path_map)| {
                path_map.iter().flat_map(|(_, name_map)| {
                    name_map
                        .iter()
                        .map(|cookie| Cookie(cookie.clone().into_owned()))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Add a cookie str to this jar.
    ///
    /// # Example
    ///
    /// ```
    /// use wreq::cookie::Jar;
    ///
    /// let cookie = "foo=bar; Domain=yolo.local";
    /// let jar = Jar::default();
    /// jar.add_cookie_str(cookie, "https://yolo.local");
    /// ```
    pub fn add_cookie_str<U>(&self, cookie: &str, uri: U)
    where
        Uri: TryFrom<U>,
    {
        if let Ok(raw) = RawCookie::parse(cookie) {
            self.add_cookie(raw.into_owned(), uri);
        }
    }

    /// Add a cookie to this jar.
    ///
    /// The cookie's domain and path attributes are used if present, otherwise
    /// the domain and path are derived from the provided Uri.
    ///
    /// # Example
    /// ```
    /// use wreq::cookie::Jar;
    /// use cookie::CookieBuilder;
    /// let jar = Jar::default();
    /// let cookie = CookieBuilder::new("foo", "bar")
    ///     .domain("example.com")
    ///     .path("/")
    ///     .build();
    /// jar.add_cookie(cookie, "http://example.com");
    /// ```
    pub fn add_cookie<C, U>(&self, cookie: C, uri: U)
    where
        C: Into<RawCookie<'static>>,
        Uri: TryFrom<U>,
    {
        let cookie: RawCookie<'static> = cookie.into();
        let uri = into_uri!(uri);
        let domain = cookie
            .domain()
            .map(normalize_domain)
            .or_else(|| uri.host())
            .unwrap_or_default();
        let path = cookie.path().unwrap_or_else(|| normalize_path(&uri));

        let mut inner = self.0.write();
        let name_map = inner
            .entry(domain.to_owned())
            .or_insert_with(|| HashMap::with_hasher(HASHER))
            .entry(path.to_owned())
            .or_default();

        // RFC 6265: If Max-Age=0 or Expires in the past, remove the cookie
        let expired = match cookie.expires() {
            Some(Expiration::DateTime(dt)) => SystemTime::from(dt) <= SystemTime::now(),
            _ => false,
        } || cookie
            .max_age()
            .is_some_and(|age| age == Duration::from_secs(0));

        if expired {
            name_map.remove(cookie);
        } else {
            name_map.add(cookie);
        }
    }

    /// Remove a cookie by name for a given Uri.
    ///
    /// Removes the cookie with the specified name for the domain and path
    /// derived from the given Uri, if it exists.
    ///
    /// # Example
    /// ```
    /// use wreq::cookie::Jar;
    /// let jar = Jar::default();
    /// jar.add_cookie_str("foo=bar; Path=/foo; Domain=example.com", "http://example.com/foo");
    /// assert!(jar.get("foo", "http://example.com/foo").is_some());
    /// jar.remove("foo", "http://example.com/foo");
    /// assert!(jar.get("foo", "http://example.com/foo").is_none());
    /// ```
    pub fn remove<C, U>(&self, cookie: C, uri: U)
    where
        C: Into<RawCookie<'static>>,
        Uri: TryFrom<U>,
    {
        let uri = into_uri!(uri);
        if let Some(host) = uri.host() {
            let mut inner = self.0.write();
            if let Some(path_map) = inner.get_mut(host) {
                if let Some(name_map) = path_map.get_mut(uri.path()) {
                    name_map.remove(cookie.into());
                }
            }
        }
    }

    /// Clear all cookies from this jar.
    ///
    /// Removes all cookies from the jar, leaving it empty.
    ///
    /// # Example
    /// ```
    /// use wreq::cookie::Jar;
    /// let jar = Jar::default();
    /// jar.add_cookie_str("foo=bar; Domain=example.com", "http://example.com");
    /// assert_eq!(jar.get_all().count(), 1);
    /// jar.clear();
    /// assert_eq!(jar.get_all().count(), 0);
    /// ```
    pub fn clear(&self) {
        self.0.write().clear();
    }
}

impl CookieStore for Jar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri) {
        let cookies = cookie_headers
            .map(Cookie::parse)
            .filter_map(Result::ok)
            .map(|cookie| cookie.0.into_owned());

        for cookie in cookies {
            self.add_cookie(cookie, uri);
        }
    }

    fn cookies(&self, uri: &Uri) -> Vec<HeaderValue> {
        let host = match uri.host() {
            Some(h) => h,
            None => return Vec::new(),
        };

        let is_https = uri.is_https();

        self.0
            .read()
            .iter()
            .filter(|(domain, _)| domain_match(host, domain))
            .flat_map(|(_, path_map)| {
                path_map
                    .iter()
                    .filter(|(path, _)| path_match(uri.path(), path))
                    .flat_map(|(_, name_map)| {
                        name_map.iter().filter_map(|cookie| {
                            // If the cookie is Secure, only send it over HTTPS
                            if cookie.secure() == Some(true) && !is_https {
                                return None;
                            }

                            // Skip expired cookie
                            if let Some(Expiration::DateTime(dt)) = cookie.expires() {
                                if SystemTime::from(dt) <= SystemTime::now() {
                                    return None;
                                }
                            }

                            // Build cookie header value
                            let name = cookie.name().as_bytes();
                            let value = cookie.value().as_bytes();
                            let mut cookie_bytes =
                                bytes::BytesMut::with_capacity(name.len() + 1 + value.len());

                            cookie_bytes.put(name);
                            cookie_bytes.put(&b"="[..]);
                            cookie_bytes.put(value);

                            HeaderValue::from_maybe_shared(Bytes::from(cookie_bytes)).ok()
                        })
                    })
            })
            .collect()
    }
}

impl Default for Jar {
    fn default() -> Self {
        Self(RwLock::new(HashMap::with_hasher(HASHER)))
    }
}

const DEFAULT_PATH: &str = "/";

/// Determines if the given `host` matches the cookie `domain` according to
/// [RFC 6265 section 5.1.3](https://datatracker.ietf.org/doc/html/rfc6265#section-5.1.3).
///
/// - Returns true if the host and domain are identical.
/// - Returns true if the host is a subdomain of the domain (host ends with ".domain").
/// - Returns false otherwise.
fn domain_match(host: &str, domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }
    if host == domain {
        return true;
    }
    host.len() > domain.len()
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
        && host.ends_with(domain)
}

/// Determines if the request path matches the cookie path according to
/// [RFC 6265 section 5.1.4](https://datatracker.ietf.org/doc/html/rfc6265#section-5.1.4).
///
/// - Returns true if the request path and cookie path are identical.
/// - Returns true if the request path starts with the cookie path, and
///   - the cookie path ends with '/', or
///   - the next character in the request path after the cookie path is '/'.
/// - Returns false otherwise.
fn path_match(req_path: &str, cookie_path: &str) -> bool {
    req_path == cookie_path
        || req_path.starts_with(cookie_path)
            && (cookie_path.ends_with(DEFAULT_PATH)
                || req_path[cookie_path.len()..].starts_with(DEFAULT_PATH))
}

/// Normalizes a domain by stripping any port information.
///
/// According to [RFC 6265 section 5.2.3](https://datatracker.ietf.org/doc/html/rfc6265#section-5.2.3),
/// the domain attribute of a cookie must not include a port. If a port is present (non-standard),
/// it will be ignored for domain matching purposes.
fn normalize_domain(domain: &str) -> &str {
    domain.split(':').next().unwrap_or(domain)
}

/// Computes the normalized default path for a cookie as specified in
/// [RFC 6265 section 5.1.4](https://datatracker.ietf.org/doc/html/rfc6265#section-5.1.4).
///
/// This function normalizes the path for a cookie, ensuring it matches
/// browser and server expectations for default cookie scope.
fn normalize_path(uri: &Uri) -> &str {
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
