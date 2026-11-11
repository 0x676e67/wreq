use std::{collections::HashMap, iter};

use cookie::{
    Cookie as RawCookie,
    time::{Duration, OffsetDateTime},
};
use http::Uri;
use url::Host;

use crate::ext::UriExt;

pub const DEFAULT_PATH: &str = "/";

/// Minimum time between two eviction passes, which bounds full-store scans when many cookies
/// expire at staggered times. Expired cookies are filtered on read in the meantime.
const EVICTION_INTERVAL: Duration = Duration::seconds(60);

/// Canonical immutable host used as a cookie domain key.
type CanonicalHost = Host<Box<str>>;
type NameMap = HashMap<Box<str>, CookieEntry>;
type PathMap = HashMap<Box<str>, CookieScopeMap>;
type DomainMap = HashMap<CanonicalHost, PathMap>;

/// A stored cookie and its sequence number for request ordering.
#[derive(Debug)]
pub struct CookieEntry {
    pub cookie: RawCookie<'static>,
    pub creation_index: u64,
}

/// Keeps host-only and `Domain` cookies separate because the host-only flag is part of a cookie's
/// identity under the RFC 6265bis storage model.
///
/// https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html#section-5.7
#[derive(Debug, Default)]
pub struct CookieScopeMap {
    host_only: NameMap,
    domain: NameMap,
}

impl CookieScopeMap {
    /// Returns a mutable cookie from the selected host-only or `Domain` scope.
    pub fn get_mut(&mut self, name: &str, host_only: bool) -> Option<&mut CookieEntry> {
        if host_only {
            self.host_only.get_mut(name)
        } else {
            self.domain.get_mut(name)
        }
    }

    /// Returns cookies with the requested name from both storage scopes.
    pub fn entries(&self, name: &str) -> impl Iterator<Item = &CookieEntry> {
        self.host_only
            .get(name)
            .into_iter()
            .chain(self.domain.get(name))
    }

    /// Inserts a cookie into its host-only or `Domain` scope.
    pub fn insert(&mut self, name: Box<str>, host_only: bool, entry: CookieEntry) {
        if host_only {
            self.host_only.insert(name, entry);
        } else {
            self.domain.insert(name, entry);
        }
    }

    /// Removes and returns a cookie from the selected host-only or `Domain` scope.
    pub fn remove(&mut self, name: &str, host_only: bool) -> Option<CookieEntry> {
        if host_only {
            self.host_only.remove(name)
        } else {
            self.domain.remove(name)
        }
    }

    /// Removes and returns both host-only and `Domain` cookies with the requested name.
    pub fn remove_all(&mut self, name: &str) -> [Option<CookieEntry>; 2] {
        [self.host_only.remove(name), self.domain.remove(name)]
    }

    /// Returns every cookie in this domain and path scope.
    pub fn values(&self) -> impl Iterator<Item = &CookieEntry> {
        self.host_only.values().chain(self.domain.values())
    }

    /// Returns `true` when the host-only and `Domain` scopes are empty.
    pub fn is_empty(&self) -> bool {
        self.host_only.is_empty() && self.domain.is_empty()
    }

    /// Keeps only the cookies in both scopes for which `keep` returns `true`.
    fn retain(&mut self, mut keep: impl FnMut(&CookieEntry) -> bool) {
        self.host_only.retain(|_, entry| keep(entry));
        self.domain.retain(|_, entry| keep(entry));
    }
}

/// Stores cookies by domain, path, host-only scope, and name.
#[derive(Debug, Default)]
pub struct Store {
    /// Mutated only through `Store` methods, which keep `secure` and `next_expiry` in sync.
    cookies: DomainMap,
    next_creation_index: u64,
    /// Earliest expiry among stored cookies. Removals can leave it early, which only costs an
    /// extra eviction pass.
    next_expiry: Option<OffsetDateTime>,
    /// When the last eviction pass ran, used to space passes by [`EVICTION_INTERVAL`].
    last_eviction: Option<OffsetDateTime>,
    secure: SecureIndex,
}

/// Counts `Secure` cookies by name and domain, so the secure overlay check skips unrelated
/// domains.
#[derive(Debug, Default)]
struct SecureIndex(HashMap<Box<str>, HashMap<CanonicalHost, usize>>);

impl Store {
    /// Returns the stored cookies by domain and path.
    #[inline]
    pub fn cookies(&self) -> &DomainMap {
        &self.cookies
    }

    /// Removes expired cookies and empty maps once the earliest stored expiry has passed, at
    /// most once per [`EVICTION_INTERVAL`].
    pub fn evict_expired(&mut self, now: OffsetDateTime) {
        let due = self.next_expiry.is_some_and(|expiry| expiry <= now)
            && self
                .last_eviction
                .is_none_or(|last| now - last >= EVICTION_INTERVAL);
        if !due {
            return;
        }
        self.last_eviction = Some(now);

        let mut next_expiry = None;
        let secure = &mut self.secure;
        self.cookies.retain(|domain, path_map| {
            path_map.retain(|_, cookie_map| {
                cookie_map.retain(|entry| {
                    if cookie_is_expired(&entry.cookie, now) {
                        if is_secure(&entry.cookie) {
                            secure.remove(entry.cookie.name(), domain);
                        }
                        return false;
                    }
                    track_expiry(&mut next_expiry, &entry.cookie);
                    true
                });
                !cookie_map.is_empty()
            });
            !path_map.is_empty()
        });
        self.next_expiry = next_expiry;

        if self.cookies.capacity() > 16 && self.cookies.len() * 4 <= self.cookies.capacity() {
            self.cookies.shrink_to_fit();
        }
    }

    /// Inserts or replaces a cookie in its domain and path scope.
    pub fn insert_stored_cookie(
        &mut self,
        domain: CanonicalHost,
        path: String,
        cookie: RawCookie<'static>,
    ) {
        let host_only = cookie.domain().is_none();
        let secure = is_secure(&cookie);
        track_expiry(&mut self.next_expiry, &cookie);

        // Chromium inherits the creation time only when the replacement keeps the same value. A
        // value change receives a new creation time and therefore moves later among equal-length
        // paths.
        // https://chromium.googlesource.com/chromium/src/+/main/net/cookies/cookie_monster.cc
        if let Some(entry) = self
            .cookies
            .get_mut(&domain)
            .and_then(|path_map| path_map.get_mut(path.as_str()))
            .and_then(|cookie_map| cookie_map.get_mut(cookie.name(), host_only))
        {
            match (is_secure(&entry.cookie), secure) {
                (false, true) => self.secure.add(cookie.name(), &domain),
                (true, false) => self.secure.remove(cookie.name(), &domain),
                _ => {}
            }
            if entry.cookie.value() != cookie.value() {
                entry.creation_index = self.next_creation_index;
                self.next_creation_index = self.next_creation_index.saturating_add(1);
            }
            entry.cookie = cookie;
            return;
        }

        if secure {
            self.secure.add(cookie.name(), &domain);
        }

        let creation_index = self.next_creation_index;
        self.next_creation_index = self.next_creation_index.saturating_add(1);
        let name = Box::from(cookie.name());

        self.cookies
            .entry(domain)
            .or_default()
            .entry(path.into_boxed_str())
            .or_default()
            .insert(
                name,
                host_only,
                CookieEntry {
                    cookie,
                    creation_index,
                },
            );
    }

    /// Removes a cookie matching the domain, path, name, and selected storage scope.
    pub fn remove_stored_cookie(
        &mut self,
        domain: &CanonicalHost,
        path: &str,
        name: &str,
        host_only: bool,
    ) {
        self.remove_stored_cookie_inner(domain, path, name, Some(host_only));
    }

    /// Removes both host-only and `Domain` cookies matching the domain, path, and name.
    pub fn remove_stored_cookies(&mut self, domain: &CanonicalHost, path: &str, name: &str) {
        self.remove_stored_cookie_inner(domain, path, name, None);
    }

    fn remove_stored_cookie_inner(
        &mut self,
        domain: &CanonicalHost,
        path: &str,
        name: &str,
        host_only: Option<bool>,
    ) {
        let remove_domain = if let Some(path_map) = self.cookies.get_mut(domain) {
            let remove_path = if let Some(cookie_map) = path_map.get_mut(path) {
                let removed = match host_only {
                    Some(host_only) => [cookie_map.remove(name, host_only), None],
                    None => cookie_map.remove_all(name),
                };
                for entry in removed.iter().flatten() {
                    if is_secure(&entry.cookie) {
                        self.secure.remove(name, domain);
                    }
                }
                cookie_map.is_empty()
            } else {
                false
            };

            if remove_path {
                path_map.remove(path);
            }

            path_map.is_empty()
        } else {
            false
        };

        if remove_domain {
            self.cookies.remove(domain);
        }
    }

    /// Returns the unexpired cookies that apply to a request URI.
    ///
    /// Performs `O(L)` hash lookups across the parent domain labels of `request_host` instead of
    /// scanning unrelated domains in the store.
    pub fn matching_cookies<'a>(
        &'a self,
        uri: &'a Uri,
        request_host: &'a CanonicalHost,
        now: OffsetDateTime,
    ) -> impl Iterator<Item = (&'a CanonicalHost, &'a str, &'a CookieEntry)> + 'a {
        candidate_domains(request_host)
            .filter_map(move |candidate| self.cookies.get_key_value(&candidate))
            .flat_map(move |(domain, path_map)| {
                path_map.iter().flat_map(move |(path, cookie_map)| {
                    cookie_map.values().filter_map(move |entry| {
                        request_matches_cookie(uri, request_host, domain, path, &entry.cookie, now)
                            .then_some((domain, path.as_ref(), entry))
                    })
                })
            })
    }

    /// Returns whether an insecure cookie would overlay an unexpired `Secure` cookie.
    ///
    /// RFC 6265bis section 5.7:
    /// https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html#section-5.7
    pub fn would_overlay_secure_cookie(
        &self,
        name: &str,
        domain: &CanonicalHost,
        path: &str,
        now: OffsetDateTime,
    ) -> bool {
        self.secure.domains(name).any(|stored_domain| {
            (domain_match(stored_domain, domain) || domain_match(domain, stored_domain))
                && self.cookies.get(stored_domain).is_some_and(|path_map| {
                    path_map.iter().any(|(stored_path, cookie_map)| {
                        path_match(path, stored_path)
                            && cookie_map.entries(name).any(|entry| {
                                entry.cookie.secure() == Some(true)
                                    && !cookie_is_expired(&entry.cookie, now)
                            })
                    })
                })
        })
    }
}

impl SecureIndex {
    /// Records one more `Secure` cookie named `name` under `domain`.
    fn add(&mut self, name: &str, domain: &CanonicalHost) {
        // Look up before inserting so existing keys are not allocated again.
        let Some(domains) = self.0.get_mut(name) else {
            self.0
                .insert(Box::from(name), HashMap::from([(domain.clone(), 1)]));
            return;
        };
        match domains.get_mut(domain) {
            Some(count) => *count += 1,
            None => {
                domains.insert(domain.clone(), 1);
            }
        }
    }

    /// Records one fewer `Secure` cookie, dropping entries whose count reaches zero.
    fn remove(&mut self, name: &str, domain: &CanonicalHost) {
        let Some(domains) = self.0.get_mut(name) else {
            return;
        };
        if let Some(count) = domains.get_mut(domain) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                domains.remove(domain);
            }
        }
        if domains.is_empty() {
            self.0.remove(name);
        }
    }

    /// Returns the domains that hold at least one `Secure` cookie named `name`.
    fn domains(&self, name: &str) -> impl Iterator<Item = &CanonicalHost> {
        self.0.get(name).into_iter().flat_map(HashMap::keys)
    }
}

/// Returns `true` if the cookie has the `Secure` attribute.
#[inline]
fn is_secure(cookie: &RawCookie<'_>) -> bool {
    cookie.secure() == Some(true)
}

/// Lowers `next_expiry` to the cookie's expiry, if it has one.
#[inline]
fn track_expiry(next_expiry: &mut Option<OffsetDateTime>, cookie: &RawCookie<'_>) {
    if let Some(expiry) = cookie.expires_datetime() {
        *next_expiry = Some(next_expiry.map_or(expiry, |current| current.min(expiry)));
    }
}

/// Yields `host` and every parent domain it can domain-match, i.e. the only keys in
/// `Store::cookies` whose cookies may apply to a request to `host`.
fn candidate_domains(host: &CanonicalHost) -> impl Iterator<Item = CanonicalHost> + '_ {
    let name = match host {
        Host::Domain(name) => name.as_ref(),
        Host::Ipv4(_) | Host::Ipv6(_) => "",
    };
    let parents = name
        .match_indices('.')
        .map(move |(dot, _)| &name[dot + 1..])
        .filter(|parent| !parent.is_empty())
        .map(|parent| Host::Domain(Box::from(parent)));
    iter::once(host.clone()).chain(parents)
}

/// Determines whether `domain` is a public suffix under RFC 6265 section 5.3 step 5.
///
/// With the `cookies-psl` feature this uses the Public Suffix List, including its private
/// section. Without it, only single-label domains such as `com` count.
///
/// https://www.rfc-editor.org/rfc/rfc6265.html#section-5.3
pub fn is_public_suffix(domain: &CanonicalHost) -> bool {
    let Host::Domain(domain) = domain else {
        return false;
    };
    // A trailing dot names the same suffix, e.g. `com.` for `com`.
    let domain = domain.strip_suffix('.').unwrap_or(domain);

    #[cfg(feature = "cookies-psl")]
    {
        psl::suffix_str(domain).is_some_and(|suffix| suffix == domain)
    }

    #[cfg(not(feature = "cookies-psl"))]
    {
        !domain.contains('.')
    }
}

/// Applies the RFC 6265 request selection rules supported by this HTTP client.
fn request_matches_cookie(
    uri: &Uri,
    request_host: &CanonicalHost,
    cookie_domain: &CanonicalHost,
    cookie_path: &str,
    cookie: &RawCookie<'_>,
    now: OffsetDateTime,
) -> bool {
    // Host-only cookies require an exact host match. A Domain attribute enables suffix matching.
    // RFC 6265 section 5.4: https://www.rfc-editor.org/rfc/rfc6265.html#section-5.4
    if !(uri.is_http() || uri.is_https())
        || !domain_match(request_host, cookie_domain)
        || cookie.domain().is_none() && request_host != cookie_domain
        || !path_match(uri.path(), cookie_path)
        || cookie.secure() == Some(true) && uri.is_http()
    {
        return false;
    }

    !cookie_is_expired(cookie, now)
}

/// Returns whether a stored cookie has reached its effective expiration deadline.
pub fn cookie_is_expired(cookie: &RawCookie<'_>, now: OffsetDateTime) -> bool {
    cookie
        .max_age()
        .is_some_and(|max_age| max_age <= Duration::ZERO)
        || cookie
            .expires_datetime()
            .is_some_and(|deadline| deadline <= now)
}

/// Determines whether `host` domain-matches `domain` as defined by RFC 6265 section 5.1.3.
///
/// https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3
pub fn domain_match(host: &CanonicalHost, domain: &CanonicalHost) -> bool {
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

/// Determines whether `request_path` path-matches `cookie_path` under RFC 6265 section 5.1.4.
///
/// https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.4
fn path_match(request_path: &str, cookie_path: &str) -> bool {
    request_path == cookie_path
        || request_path.starts_with(cookie_path)
            && (cookie_path.ends_with(DEFAULT_PATH)
                || request_path[cookie_path.len()..].starts_with(DEFAULT_PATH))
}

/// Canonicalizes a DNS name or IP literal for cookie domain matching.
pub fn canonical_host(host: &str) -> Option<CanonicalHost> {
    // RFC 6265 section 5.2.3 requires a leading dot in Domain to be ignored.
    // https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.3
    let host = host.strip_prefix('.').unwrap_or(host);

    match Host::parse(host).ok()? {
        Host::Domain(domain) => Some(Host::Domain(domain.into_boxed_str())),
        Host::Ipv4(address) => Some(Host::Ipv4(address)),
        Host::Ipv6(address) => Some(Host::Ipv6(address)),
    }
}

/// Computes the default cookie path from a request path under RFC 6265 section 5.1.4.
///
/// https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.4
pub fn normalize_path(path: &str) -> &str {
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
    use cookie::time::Duration;

    use super::*;

    fn secure_cookie(expiry: Option<OffsetDateTime>) -> RawCookie<'static> {
        let mut cookie = RawCookie::new("sid", "1");
        cookie.set_secure(true);
        if let Some(expiry) = expiry {
            cookie.set_expires(expiry);
        }
        cookie
    }

    #[test]
    fn store_evicts_expired_cookies_and_tracks_secure_cookies() {
        let now = OffsetDateTime::now_utc();
        let expiry = now + Duration::seconds(1);
        let host = |name: &str| canonical_host(name).unwrap();
        let mut store = Store::default();
        for i in 0..3 {
            let domain = host(&format!("sub{i}.example.com"));
            store.insert_stored_cookie(domain, "/".into(), secure_cookie(Some(expiry)));
        }
        store.insert_stored_cookie(host("example.com"), "/".into(), secure_cookie(None));

        store.evict_expired(now);
        assert_eq!(store.cookies.len(), 4);

        // Expired cookies, their empty maps and their index entries are dropped together.
        store.evict_expired(expiry);
        assert_eq!(store.cookies.len(), 1);
        assert_eq!(store.next_expiry, None);
        assert_eq!(store.secure.domains("sid").count(), 1);

        // Another pass waits for the eviction interval.
        let later = expiry + Duration::seconds(1);
        store.insert_stored_cookie(
            host("late.example.com"),
            "/".into(),
            secure_cookie(Some(later)),
        );
        store.evict_expired(later);
        assert_eq!(store.cookies.len(), 2);
        store.evict_expired(expiry + EVICTION_INTERVAL);
        assert_eq!(store.cookies.len(), 1);

        // Replacing a secure cookie with an insecure one, or removing it, updates the index.
        let domain = host("example.com");
        store.insert_stored_cookie(domain.clone(), "/".into(), RawCookie::new("sid", "2"));
        assert!(!store.would_overlay_secure_cookie("sid", &domain, "/", now));
        store.insert_stored_cookie(domain.clone(), "/".into(), secure_cookie(None));
        assert!(store.would_overlay_secure_cookie("sid", &domain, "/", now));
        store.remove_stored_cookies(&domain, "/", "sid");
        assert!(store.secure.0.is_empty());
    }
}
