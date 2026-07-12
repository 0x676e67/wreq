use std::collections::HashMap;

use cookie::{
    Cookie as RawCookie,
    time::{Duration, OffsetDateTime},
};
use http::Uri;
use url::Host;

use crate::ext::UriExt;

pub const DEFAULT_PATH: &str = "/";

/// Canonical immutable host used as a cookie domain key.
type CanonicalHost = Host<Box<str>>;
type NameMap = HashMap<Box<str>, CookieEntry>;
type PathMap = HashMap<Box<str>, NameMap>;
type DomainMap = HashMap<CanonicalHost, PathMap>;

#[derive(Debug)]
pub struct CookieEntry {
    pub cookie: RawCookie<'static>,
    pub creation_index: u64,
}

#[derive(Debug, Default)]
pub struct CookieStorage {
    pub cookies: DomainMap,
    next_creation_index: u64,
}

pub fn insert_stored_cookie(
    storage: &mut CookieStorage,
    domain: CanonicalHost,
    path: String,
    cookie: RawCookie<'static>,
) {
    // Chromium inherits the creation time only when the replacement keeps the same value. A value
    // change receives a new creation time and therefore moves later among equal-length paths.
    // https://chromium.googlesource.com/chromium/src/+/main/net/cookies/cookie_monster.cc
    if let Some(entry) = storage
        .cookies
        .get_mut(&domain)
        .and_then(|path_map| path_map.get_mut(path.as_str()))
        .and_then(|name_map| name_map.get_mut(cookie.name()))
    {
        if entry.cookie.value() != cookie.value() {
            entry.creation_index = storage.next_creation_index;
            storage.next_creation_index = storage.next_creation_index.saturating_add(1);
        }
        entry.cookie = cookie;
        return;
    }

    let creation_index = storage.next_creation_index;
    storage.next_creation_index = storage.next_creation_index.saturating_add(1);
    let name = Box::from(cookie.name());

    storage
        .cookies
        .entry(domain)
        .or_default()
        .entry(path.into_boxed_str())
        .or_default()
        .insert(
            name,
            CookieEntry {
                cookie,
                creation_index,
            },
        );
}

pub fn remove_stored_cookie(store: &mut DomainMap, domain: &CanonicalHost, path: &str, name: &str) {
    let remove_domain = if let Some(path_map) = store.get_mut(domain) {
        let remove_path = if let Some(name_map) = path_map.get_mut(path) {
            name_map.remove(name);
            name_map.is_empty()
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
        store.remove(domain);
    }
}

pub fn matching_cookies<'a>(
    store: &'a DomainMap,
    uri: &Uri,
    request_host: &CanonicalHost,
    now: OffsetDateTime,
) -> Vec<(&'a CanonicalHost, &'a str, &'a CookieEntry)> {
    store
        .iter()
        .flat_map(|(domain, path_map)| {
            path_map.iter().flat_map(move |(path, name_map)| {
                name_map.values().filter_map(move |entry| {
                    request_matches_cookie(uri, request_host, domain, path, &entry.cookie, now)
                        .then_some((domain, path.as_ref(), entry))
                })
            })
        })
        .collect()
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
