//! HTTP Cookies

use std::{collections::HashMap, convert::TryInto, fmt, sync::Arc, time::SystemTime};

use bytes::Bytes;
use cookie::{
    Cookie as RawCookie, CookieJar, Expiration, SameSite,
    time::{Duration, OffsetDateTime},
};
use http::{Uri, Version};
use url::Host;

use crate::{IntoUri, error::Error, ext::UriExt, header::HeaderValue, sync::RwLock};

/// Canonical immutable host used as a cookie domain key.
type CanonicalHost = Host<Box<str>>;

/// Cookie header values in two forms.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Cookies {
    /// All cookies combined into one header (compressed).
    Compressed(HeaderValue),

    /// Each cookie sent as its own header (uncompressed).
    Uncompressed(Vec<HeaderValue>),

    /// No cookies.
    Empty,
}

/// Actions for a persistent cookie store providing session support.
pub trait CookieStore: Send + Sync {
    /// Store a set of Set-Cookie header values received from `uri`
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri);

    /// Returns cookies for the given URI and HTTP version.
    ///
    /// Following [RFC 9112 §5.6.3], HTTP/1.1 combines all cookies into a single header.
    /// For [HTTP/2] and above, cookies are sent as separate header fields
    /// as per [RFC 9113 §8.1.2.5].
    ///
    /// [RFC 9112 §5.6.3]: https://www.rfc-editor.org/rfc/rfc9112#section-5.6.3
    /// [RFC 9113 §8.1.2.5]: https://www.rfc-editor.org/rfc/rfc9113#section-8.1.2.5
    /// [HTTP/2]: https://datatracker.ietf.org/doc/html/rfc9113
    fn cookies(&self, uri: &Uri, version: Version) -> Cookies;
}

impl_into_shared!(
    /// Trait for converting types into a shared cookie store ([`Arc<dyn CookieStore>`]).
    ///
    /// Implemented for any [`CookieStore`] type, [`Arc<T>`] where `T: CookieStore`, and [`Arc<dyn
    /// CookieStore>`]. Enables ergonomic conversion to a trait object for use in APIs without manual
    /// boxing.
    pub trait IntoCookieStore => CookieStore
);

impl_request_config_value!(Arc<dyn CookieStore>);

/// Trait for converting types into an owned cookie ([`Cookie<'static>`]).
pub trait IntoCookie {
    /// Converts the implementor into a optional owned [`Cookie<'static>`].
    fn into_cookie(self) -> Option<Cookie<'static>>;
}

/// A single HTTP cookie.
#[derive(Debug, Clone)]
pub struct Cookie<'a>(RawCookie<'a>);

/// A good default `CookieStore` implementation.
///
/// This is the implementation used when simply calling `cookie_store(true)`.
/// This type is exposed to allow creating one and filling it with some
/// existing cookies more easily, before creating a [`crate::Client`].
#[derive(Debug, Default)]
pub struct Jar(RwLock<HashMap<CanonicalHost, HashMap<String, CookieJar>>>);

// ===== impl IntoCookie =====

impl IntoCookie for Cookie<'_> {
    #[inline]
    fn into_cookie(self) -> Option<Cookie<'static>> {
        Some(self.into_owned())
    }
}

impl IntoCookie for RawCookie<'_> {
    #[inline]
    fn into_cookie(self) -> Option<Cookie<'static>> {
        Some(Cookie(self.into_owned()))
    }
}

impl IntoCookie for &str {
    #[inline]
    fn into_cookie(self) -> Option<Cookie<'static>> {
        RawCookie::parse(self).map(|c| Cookie(c.into_owned())).ok()
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

// ===== impl Jar =====

macro_rules! into_uri {
    ($expr:expr) => {
        match $expr.into_uri() {
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
    /// jar.add("foo=bar; Path=/foo; Domain=example.com", "http://example.com/foo");
    /// let cookie = jar.get("foo", "http://example.com/foo").unwrap();
    /// assert_eq!(cookie.value(), "bar");
    /// ```
    pub fn get<U: IntoUri>(&self, name: &str, uri: U) -> Option<Cookie<'static>> {
        let uri = uri.into_uri().ok()?;
        let host = canonical_host(uri.host()?)?;
        let store = self.0.read();
        let cookie = store.get(&host)?.get(uri.path())?.get(name)?;

        if cookie_is_expired(cookie, OffsetDateTime::now_utc()) {
            return None;
        }

        Some(Cookie(cookie.clone().into_owned()))
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
    /// jar.add("foo=bar; Domain=example.com", "http://example.com");
    /// for cookie in jar.get_all() {
    ///     println!("{}={}", cookie.name(), cookie.value());
    /// }
    /// ```
    pub fn get_all(&self) -> impl Iterator<Item = Cookie<'static>> {
        let now = OffsetDateTime::now_utc();
        self.0
            .read()
            .iter()
            .flat_map(|(domain, path_map)| {
                path_map.iter().flat_map(|(path, name_map)| {
                    name_map.iter().filter_map(|cookie| {
                        if cookie_is_expired(cookie, now) {
                            return None;
                        }

                        let mut cookie = cookie.clone().into_owned();

                        if cookie.domain().is_none() {
                            cookie.set_domain(domain.to_string());
                        }

                        if cookie.path().is_none() {
                            cookie.set_path(path.to_owned());
                        }

                        Some(Cookie(cookie))
                    })
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Add a cookie to this jar.
    ///
    /// # Example
    ///
    /// ```
    /// use wreq::cookie::Jar;
    /// use cookie::CookieBuilder;
    /// let jar = Jar::default();
    /// let cookie = CookieBuilder::new("foo", "bar")
    ///     .domain("example.com")
    ///     .path("/")
    ///     .build();
    /// jar.add(cookie, "http://example.com");
    ///
    /// let cookie = CookieBuilder::new("foo", "bar")
    ///     .domain("example.com")
    ///     .path("/")
    ///     .build();
    /// jar.add(cookie, "http://example.com");
    /// ```
    pub fn add<C, U>(&self, cookie: C, uri: U)
    where
        C: IntoCookie,
        U: IntoUri,
    {
        if let Some(cookie) = cookie.into_cookie() {
            let uri = into_uri!(uri);
            let mut cookie: RawCookie<'static> = cookie.into();

            // If the request-uri contains no host component:
            let Some(host) = uri.host().and_then(canonical_host) else {
                return;
            };

            // If the canonicalized request-host does not domain-match the
            // domain-attribute:
            //    Ignore the cookie entirely and abort these steps.
            //
            // RFC 6265 §5.3 + §5.1.3:
            // https://datatracker.ietf.org/doc/html/rfc6265#section-5.3
            // https://datatracker.ietf.org/doc/html/rfc6265#section-5.1.3
            let domain = if let Some(raw_domain) = cookie.domain() {
                let Some(domain) = canonical_host(raw_domain) else {
                    return;
                };
                if !domain_match(&host, &domain) {
                    return;
                }

                cookie.set_domain(domain.to_string());
                domain
            } else {
                host
            };

            // Max-Age takes precedence over Expires and is relative to when the cookie is
            // received. Store its effective deadline so every read path applies the same
            // expiration decision. RFC 6265 sections 5.2.2 and 5.3:
            // https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.2
            // https://www.rfc-editor.org/rfc/rfc6265.html#section-5.3
            let now = OffsetDateTime::now_utc();
            let expired = match cookie.max_age() {
                Some(max_age) if max_age <= Duration::ZERO => true,
                Some(max_age) => {
                    let deadline = now.saturating_add(max_age);
                    cookie.set_expires(deadline);
                    false
                }
                None => cookie
                    .expires_datetime()
                    .is_some_and(|deadline| deadline <= now),
            };

            // If the request-uri contains no path component or if the first character of the
            // path component of the request-uri is not a %x2F ("/") OR if the cookie's path-
            // attribute is missing or does not start with a %x2F ("/"):
            //    Let cookie-path be the default-path of the request-uri.
            // Otherwise:
            //    Let cookie-path be the substring of the request-uri's path from the first
            // character    up to, not including, the right-most %x2F ("/").
            //
            // RFC 6265 §5.2.4 + §5.1.4:
            // https://datatracker.ietf.org/doc/html/rfc6265#section-5.2.4
            // https://datatracker.ietf.org/doc/html/rfc6265#section-5.1.4
            let path = cookie
                .path()
                .filter(|path| path.starts_with(DEFAULT_PATH))
                .unwrap_or_else(|| normalize_path(uri.path()));

            let mut inner = self.0.write();
            let name_map = inner
                .entry(domain)
                .or_default()
                .entry(path.to_owned())
                .or_default();

            if expired {
                name_map.remove(cookie);
            } else {
                cookie.set_path(path.to_owned());
                name_map.add(cookie);
            }
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
    /// jar.add("foo=bar; Path=/foo; Domain=example.com", "http://example.com/foo");
    /// assert!(jar.get("foo", "http://example.com/foo").is_some());
    /// jar.remove("foo", "http://example.com/foo");
    /// assert!(jar.get("foo", "http://example.com/foo").is_none());
    /// ```
    pub fn remove<C, U>(&self, cookie: C, uri: U)
    where
        C: Into<RawCookie<'static>>,
        U: IntoUri,
    {
        let uri = into_uri!(uri);
        if let Some(host) = uri.host() {
            let Some(host) = canonical_host(host) else {
                return;
            };
            let mut inner = self.0.write();
            if let Some(path_map) = inner.get_mut(&host) {
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
    /// jar.add("foo=bar; Domain=example.com", "http://example.com");
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
            self.add(cookie, uri);
        }
    }

    fn cookies(&self, uri: &Uri, version: Version) -> Cookies {
        let host = match uri.host() {
            Some(host) => match canonical_host(host) {
                Some(host) => host,
                None => return Cookies::Empty,
            },
            None => return Cookies::Empty,
        };

        let now = OffsetDateTime::now_utc();
        let store = self.0.read();
        let request_host = &host;
        let iter = store
            .iter()
            .filter(|(domain, _)| domain_match(request_host, domain))
            .flat_map(|(domain, path_map)| {
                path_map
                    .iter()
                    .filter(|(path, _)| path_match(uri.path(), path))
                    .flat_map(move |(_, name_map)| {
                        name_map.iter().filter(move |cookie| {
                            // RFC 6265 section 5.4 requires host-only cookies to match the
                            // request host exactly. Only cookies with a Domain attribute may
                            // be sent to matching subdomains.
                            // https://www.rfc-editor.org/rfc/rfc6265.html#section-5.4
                            if cookie.domain().is_none() && request_host != domain {
                                return false;
                            }

                            if cookie.secure() == Some(true) && uri.is_http() {
                                return false;
                            }

                            if cookie_is_expired(cookie, now) {
                                return false;
                            }

                            true
                        })
                    })
            });

        if matches!(version, Version::HTTP_2 | Version::HTTP_3) {
            let cookies = iter
                .map(|cookie| {
                    let name = cookie.name();
                    let value = cookie.value();

                    let mut cookie_str = String::with_capacity(name.len() + 1 + value.len());
                    cookie_str.push_str(name);
                    cookie_str.push('=');
                    cookie_str.push_str(value);

                    HeaderValue::from_maybe_shared(Bytes::from(cookie_str))
                })
                .filter_map(Result::ok)
                .collect();

            Cookies::Uncompressed(cookies)
        } else {
            let cookies = iter.fold(String::new(), |mut cookies, cookie| {
                if !cookies.is_empty() {
                    cookies.push_str("; ");
                }
                cookies.push_str(cookie.name());
                cookies.push('=');
                cookies.push_str(cookie.value());
                cookies
            });

            if cookies.is_empty() {
                return Cookies::Empty;
            }

            HeaderValue::from_maybe_shared(Bytes::from(cookies))
                .map(Cookies::Compressed)
                .unwrap_or(Cookies::Empty)
        }
    }
}

const DEFAULT_PATH: &str = "/";

/// Returns whether a stored cookie has reached its effective expiration deadline.
fn cookie_is_expired(cookie: &RawCookie<'_>, now: OffsetDateTime) -> bool {
    cookie
        .max_age()
        .is_some_and(|max_age| max_age <= Duration::ZERO)
        || cookie
            .expires_datetime()
            .is_some_and(|deadline| deadline <= now)
}

/// Determines if the given `host` matches the cookie `domain` according to
/// [RFC 6265 section 5.1.3](https://datatracker.ietf.org/doc/html/rfc6265#section-5.1.3).
///
/// - Returns true if the host and domain are identical.
/// - Returns true if two DNS names have a matching dot-delimited domain suffix.
/// - IP literals never use suffix matching.
/// - Returns false otherwise.
fn domain_match(host: &CanonicalHost, domain: &CanonicalHost) -> bool {
    if host == domain {
        return true;
    }

    let (Host::Domain(host), Host::Domain(domain)) = (host, domain) else {
        return false;
    };

    host.len() > domain.len()
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
        && host.ends_with(domain.as_ref())
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

/// Canonicalizes a DNS name or IP literal for cookie domain matching.
///
/// DNS names are converted to lowercase ASCII, while IPv4 and IPv6 addresses remain typed so
/// they can only match exactly, as required by
/// [RFC 6265 section 5.1.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3).
fn canonical_host(host: &str) -> Option<CanonicalHost> {
    // RFC 6265 section 5.2.3 requires a leading dot in Domain to be ignored.
    // https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.3
    let host = host.strip_prefix('.').unwrap_or(host);

    match Host::parse(host).ok()? {
        Host::Domain(domain) => Some(Host::Domain(domain.into_boxed_str())),
        Host::Ipv4(address) => Some(Host::Ipv4(address)),
        Host::Ipv6(address) => Some(Host::Ipv6(address)),
    }
}

/// Computes the normalized default path for a cookie as specified in
/// [RFC 6265 section 5.1.4](https://datatracker.ietf.org/doc/html/rfc6265#section-5.1.4).
///
/// This function normalizes the path for a cookie, ensuring it matches
/// browser and server expectations for default cookie scope.
fn normalize_path(path: &str) -> &str {
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

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration as StdDuration};

    use http::{Uri, Version};

    use super::{CookieStore, Cookies, Jar};

    #[test]
    fn jar_get_all_backfills_domain_and_path() {
        let jar = Jar::default();
        jar.add("session=abc", "http://example.com/foo/bar");

        let cookies = jar.get_all().collect::<Vec<_>>();
        assert_eq!(cookies.len(), 1);

        let cookie = &cookies[0];
        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.value(), "abc");
        assert_eq!(cookie.domain(), Some("example.com"));
        assert_eq!(cookie.path(), Some("/foo"));
    }

    #[test]
    fn jar_get_all_keeps_existing_domain_and_path() {
        let jar = Jar::default();
        jar.add(
            "session=abc; Domain=example.com; Path=/custom",
            "http://example.com/foo/bar",
        );

        let cookies = jar.get_all().collect::<Vec<_>>();
        assert_eq!(cookies.len(), 1);

        let cookie = &cookies[0];
        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.value(), "abc");
        assert_eq!(cookie.domain(), Some("example.com"));
        assert_eq!(cookie.path(), Some("/custom"));
    }

    #[test]
    fn jar_get_all_backfills_only_missing_field() {
        let jar = Jar::default();
        jar.add("a=1; Domain=example.com", "http://example.com/foo/bar");
        jar.add("b=2; Path=/fixed", "http://example.com/foo/bar");

        let mut cookies = jar.get_all().collect::<Vec<_>>();
        cookies.sort_by(|left, right| left.name().cmp(right.name()));

        let a = &cookies[0];
        assert_eq!(a.name(), "a");
        assert_eq!(a.domain(), Some("example.com"));
        assert_eq!(a.path(), Some("/foo"));

        let b = &cookies[1];
        assert_eq!(b.name(), "b");
        assert_eq!(b.domain(), Some("example.com"));
        assert_eq!(b.path(), Some("/fixed"));
    }

    #[test]
    fn jar_add_rejects_mismatched_domain() {
        let jar = Jar::default();
        jar.add("session=abc; Domain=other.com", "http://example.com/foo");

        assert_eq!(jar.get_all().count(), 0);
    }

    #[test]
    fn jar_add_accepts_matching_parent_domain() {
        let jar = Jar::default();
        jar.add(
            "session=abc; Domain=example.com",
            "http://api.example.com/foo",
        );

        let cookies = jar.get_all().collect::<Vec<_>>();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].domain(), Some("example.com"));
    }

    #[test]
    fn jar_get_all_export_import_keeps_effective_path() {
        let source = Jar::default();
        source.add("session=abc", "http://example.com/foo/bar");

        let exported = source.get_all().collect::<Vec<_>>();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].path(), Some("/foo"));

        let target = Jar::default();
        for cookie in exported {
            target.add(cookie, "http://example.com/another/deeper");
        }

        let imported = target.get_all().collect::<Vec<_>>();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].path(), Some("/foo"));
    }

    #[test]
    fn cookie_store_invalid_explicit_path_falls_back_to_default_path() {
        let jar = Jar::default();
        jar.add("key=val; Path=noslash", "http://example.com/foo/bar");

        assert!(jar.get("key", "http://example.com/foo").is_some());
        assert!(jar.get("key", "http://example.com/noslash").is_none());

        let cookies = jar.get_all().collect::<Vec<_>>();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].path(), Some("/foo"));
    }

    #[test]
    fn jar_sends_parent_domain_cookie_to_subdomain() {
        let jar = Jar::default();
        jar.add(
            "session=abc; Domain=example.com; Path=/",
            "http://example.com/login",
        );

        let should_receive = [
            "http://example.com/dashboard",
            "http://api.example.com/dashboard",
            "http://sub.api.example.com/dashboard",
        ];
        for uri_str in &should_receive {
            let uri = Uri::from_static(uri_str);
            match jar.cookies(&uri, Version::HTTP_11) {
                Cookies::Compressed(v) => assert_eq!(
                    v.to_str().unwrap(),
                    "session=abc",
                    "expected cookie to be sent to {uri_str}"
                ),
                other => panic!("expected Compressed cookie for {uri_str}, got {other:?}"),
            }
        }

        let should_not_receive = [
            "http://notexample.com/dashboard",
            "http://fakeexample.com/dashboard",
        ];
        for uri_str in &should_not_receive {
            let uri = Uri::from_static(uri_str);
            assert!(
                matches!(jar.cookies(&uri, Version::HTTP_11), Cookies::Empty),
                "cookie must NOT be sent to {uri_str}"
            );
        }
    }

    #[test]
    fn jar_does_not_send_host_only_cookie_to_subdomain() {
        let jar = Jar::default();
        jar.add("session=abc; Path=/", "http://example.com/login");

        let origin = Uri::from_static("http://example.com/dashboard");
        match jar.cookies(&origin, Version::HTTP_11) {
            Cookies::Compressed(value) => assert_eq!(value, "session=abc"),
            other => panic!("expected host-only cookie for origin host, got {other:?}"),
        }

        let subdomain = Uri::from_static("http://api.example.com/dashboard");
        assert!(
            matches!(jar.cookies(&subdomain, Version::HTTP_11), Cookies::Empty),
            "host-only cookie must not be sent to a subdomain"
        );
    }

    #[test]
    fn jar_accepts_and_normalizes_mixed_case_domain() {
        let jar = Jar::default();
        jar.add(
            "session=abc; Domain=EXAMPLE.COM; Path=/",
            "https://example.com/login",
        );

        let cookies = jar.get_all().collect::<Vec<_>>();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].domain(), Some("example.com"));

        let subdomain = Uri::from_static("https://api.example.com/dashboard");
        match jar.cookies(&subdomain, Version::HTTP_11) {
            Cookies::Compressed(value) => assert_eq!(value, "session=abc"),
            other => panic!("expected domain cookie for matching subdomain, got {other:?}"),
        }
    }

    #[test]
    fn jar_ignores_leading_dot_in_domain() {
        let jar = Jar::default();
        jar.add(
            "session=abc; Domain=.example.com; Path=/",
            "https://example.com/login",
        );

        let subdomain = Uri::from_static("https://api.example.com/dashboard");
        match jar.cookies(&subdomain, Version::HTTP_11) {
            Cookies::Compressed(value) => assert_eq!(value, "session=abc"),
            other => panic!("expected domain cookie for matching subdomain, got {other:?}"),
        }
    }

    #[test]
    fn jar_enforces_positive_max_age_deadline() {
        let jar = Jar::default();
        let uri = Uri::from_static("http://example.com/");
        jar.add("short=lived; Max-Age=1; Path=/", &uri);

        let cookie = jar.get("short", &uri).expect("cookie should be stored");
        assert_eq!(cookie.max_age(), Some(StdDuration::from_secs(1)));
        assert!(cookie.expires().is_some());
        assert_eq!(jar.get_all().count(), 1);
        assert!(matches!(
            jar.cookies(&uri, Version::HTTP_11),
            Cookies::Compressed(_)
        ));

        thread::sleep(StdDuration::from_millis(1100));

        assert!(jar.get("short", &uri).is_none());
        assert_eq!(jar.get_all().count(), 0);
        assert!(matches!(
            jar.cookies(&uri, Version::HTTP_11),
            Cookies::Empty
        ));
    }

    #[test]
    fn jar_removes_non_positive_max_age() {
        let jar = Jar::default();
        let uri = "http://example.com/";

        jar.add("zero=old; Path=/", uri);
        jar.add("zero=gone; Max-Age=0; Path=/", uri);
        assert!(jar.get("zero", uri).is_none());

        jar.add("negative=old; Path=/", uri);
        jar.add("negative=gone; Max-Age=-10; Path=/", uri);
        assert!(jar.get("negative", uri).is_none());
    }

    #[test]
    fn jar_max_age_overrides_expires_in_either_order() {
        let jar = Jar::default();
        let uri = "http://example.com/";

        jar.add(
            "first=kept; Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
            uri,
        );
        jar.add(
            "last=kept; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=60; Path=/",
            uri,
        );
        assert!(jar.get("first", uri).is_some());
        assert!(jar.get("last", uri).is_some());

        jar.add("remove_first=old; Path=/", uri);
        jar.add(
            "remove_first=gone; Max-Age=0; Expires=Fri, 31 Dec 9999 23:59:59 GMT; Path=/",
            uri,
        );
        jar.add("remove_last=old; Path=/", uri);
        jar.add(
            "remove_last=gone; Expires=Fri, 31 Dec 9999 23:59:59 GMT; Max-Age=0; Path=/",
            uri,
        );
        assert!(jar.get("remove_first", uri).is_none());
        assert!(jar.get("remove_last", uri).is_none());
    }

    #[test]
    fn jar_uses_last_valid_max_age() {
        let jar = Jar::default();
        let uri = "http://example.com/";

        jar.add("kept=value; Max-Age=0; Max-Age=60; Path=/", uri);
        assert!(jar.get("kept", uri).is_some());

        jar.add("removed=old; Path=/", uri);
        jar.add("removed=gone; Max-Age=60; Max-Age=0; Path=/", uri);
        assert!(jar.get("removed", uri).is_none());

        jar.add(
            "malformed=kept; Max-Age=60; Max-Age=invalid; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
            uri,
        );
        assert!(jar.get("malformed", uri).is_some());
    }

    #[test]
    fn jar_ignores_malformed_max_age() {
        let jar = Jar::default();
        let uri = "http://example.com/";

        jar.add(
            "persistent=value; Max-Age=invalid; Expires=Fri, 31 Dec 9999 23:59:59 GMT; Path=/",
            uri,
        );
        assert!(jar.get("persistent", uri).is_some());

        jar.add(
            "expired=value; Max-Age=invalid; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
            uri,
        );
        assert!(jar.get("expired", uri).is_none());

        jar.add(
            "plus=value; Max-Age=+60; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
            uri,
        );
        assert!(jar.get("plus", uri).is_none());

        jar.add("session=value; Max-Age=invalid; Path=/", uri);
        let session = jar
            .get("session", uri)
            .expect("session cookie should be stored");
        assert_eq!(session.max_age(), None);
        assert_eq!(session.expires(), None);
    }

    #[test]
    fn jar_does_not_suffix_match_ipv4_addresses() {
        let jar = Jar::default();
        jar.add("session=abc; Domain=0.1; Path=/", "http://192.168.0.1/");

        assert_eq!(jar.get_all().count(), 0);

        let unrelated = Uri::from_static("http://10.0.0.1/");
        assert!(matches!(
            jar.cookies(&unrelated, Version::HTTP_11),
            Cookies::Empty
        ));
    }

    #[test]
    fn jar_preserves_ipv6_host_identity() {
        let jar = Jar::default();
        jar.add("session=abc; Path=/", "http://[2001:db8::1]/");

        let equivalent = Uri::from_static("http://[2001:0db8:0:0:0:0:0:1]/");
        match jar.cookies(&equivalent, Version::HTTP_11) {
            Cookies::Compressed(value) => assert_eq!(value, "session=abc"),
            other => panic!("expected cookie for equivalent IPv6 host, got {other:?}"),
        }

        let unrelated = Uri::from_static("http://[2001:db8::2]/");
        assert!(matches!(
            jar.cookies(&unrelated, Version::HTTP_11),
            Cookies::Empty
        ));
    }

    #[test]
    fn jar_subdomain_cookie_does_not_leak_to_parent_or_sibling() {
        let jar = Jar::default();
        jar.add(
            "token=xyz; Domain=api.example.com; Path=/",
            "http://api.example.com/",
        );

        let uri = Uri::from_static("http://api.example.com/");
        assert!(
            matches!(jar.cookies(&uri, Version::HTTP_11), Cookies::Compressed(_)),
            "cookie must be sent to api.example.com"
        );

        let must_not_receive = [
            "http://example.com/",
            "http://other.example.com/",
            "http://notapi.example.com/",
        ];
        for uri_str in &must_not_receive {
            let uri = Uri::from_static(uri_str);
            assert!(
                matches!(jar.cookies(&uri, Version::HTTP_11), Cookies::Empty),
                "cookie must NOT leak to {uri_str}"
            );
        }
    }
}
