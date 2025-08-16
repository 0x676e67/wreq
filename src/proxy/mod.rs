#[cfg(all(target_os = "macos", feature = "system-proxy"))]
mod mac;
mod matcher;
#[cfg(unix)]
mod uds;
#[cfg(all(windows, feature = "system-proxy"))]
mod win;

use std::error::Error as StdError;
#[cfg(unix)]
use std::{path::Path, sync::Arc};

use http::{HeaderMap, Uri, header::HeaderValue, uri::Scheme};

use crate::{
    Url,
    error::{BadScheme, Error},
    into_url::{IntoUrl, IntoUrlSealed},
};

// # Internals
//
// This module is a couple pieces:
//
// - The public builder API
// - The internal built types that our Connector knows how to use.
//
// The user creates a builder (`wreq::Proxy`), and configures any extras.
// Once that type is passed to the `ClientBuilder`, we convert it into the
// built matcher types, making use of `core`'s matchers.

/// Configuration of a proxy that a `Client` should pass requests to.
///
/// A `Proxy` has a couple pieces to it:
///
/// - a URL of how to talk to the proxy
/// - rules on what `Client` requests should be directed to the proxy
///
/// For instance, let's look at `Proxy::http`:
///
/// ```rust
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let proxy = wreq::Proxy::http("https://secure.example")?;
/// # Ok(())
/// # }
/// ```
///
/// This proxy will intercept all HTTP requests, and make use of the proxy
/// at `https://secure.example`. A request to `http://hyper.rs` will talk
/// to your proxy. A request to `https://hyper.rs` will not.
///
/// Multiple `Proxy` rules can be configured for a `Client`. The `Client` will
/// check each `Proxy` in the order it was added. This could mean that a
/// `Proxy` added first with eager intercept rules, such as `Proxy::all`,
/// would prevent a `Proxy` later in the list from ever working, so take care.
///
/// By enabling the `"socks"` feature it is possible to use a socks proxy:
/// ```rust
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let proxy = wreq::Proxy::http("socks5://192.168.1.1:9000")?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Proxy {
    extra: Extra,
    intercept: Intercept,
    no_proxy: Option<NoProxy>,
}

/// A configuration for filtering out requests that shouldn't be proxied
#[derive(Clone, Debug, Default)]
pub struct NoProxy {
    inner: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Extra {
    auth: Option<HeaderValue>,
    misc: Option<HeaderMap>,
}

impl std::hash::Hash for Extra {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash the optional Proxy-Authorization header value, if present.
        self.auth.hash(state);

        // Hash the misc headers by name and value bytes, in insertion order.
        // HeaderMap preserves insertion order, so no need to sort for determinism.
        if let Some(ref misc) = self.misc {
            for (k, v) in misc.iter() {
                // Hash the header name as bytes.
                k.as_str().hash(state);
                // Hash the header value as bytes.
                v.as_bytes().hash(state);
            }
        } else {
            // Distinguish between None and Some(empty) for misc.
            0u8.hash(state);
        }
    }
}

// ===== Internal =====

#[derive(Clone, Debug)]
enum Intercept {
    All(Url),
    Http(Url),
    Https(Url),
    #[cfg(unix)]
    Unix(Arc<Path>),
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Intercepted {
    Proxy(matcher::Intercept),
    #[cfg(unix)]
    Unix(Arc<Path>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Matcher {
    inner: Box<matcher::Matcher>,
    maybe_has_http_auth: bool,
    maybe_has_http_custom_headers: bool,
}

/// Trait used for converting into a proxy scheme. This trait supports
/// parsing from a URL-like type, whilst also supporting proxy schemes
/// built directly using the factory methods.
pub trait IntoProxy {
    fn into_proxy(self) -> crate::Result<Url>;
}

impl<S: IntoUrl> IntoProxy for S {
    fn into_proxy(self) -> crate::Result<Url> {
        match self.as_str().into_url() {
            Ok(url) => Ok(url),
            Err(e) => {
                let mut presumed_to_have_scheme = true;
                let mut source = e.source();
                while let Some(err) = source {
                    if let Some(parse_error) = err.downcast_ref::<url::ParseError>() {
                        if *parse_error == url::ParseError::RelativeUrlWithoutBase {
                            presumed_to_have_scheme = false;
                            break;
                        }
                    } else if err.downcast_ref::<BadScheme>().is_some() {
                        presumed_to_have_scheme = false;
                        break;
                    }
                    source = err.source();
                }
                if presumed_to_have_scheme {
                    return Err(Error::builder(e));
                }
                // the issue could have been caused by a missing scheme, so we try adding http://
                let try_this = format!("http://{}", self.as_str());
                try_this.into_url().map_err(|_| {
                    // return the original error
                    Error::builder(e)
                })
            }
        }
    }
}

// These bounds are accidentally leaked by the blanket impl of IntoProxy
// for all types that implement IntoUrl. So, this function exists to detect
// if we were to break those bounds for a user.
fn _implied_bounds() {
    fn prox<T: IntoProxy>(_t: T) {}

    fn url<T: IntoUrl>(t: T) {
        prox(t);
    }
}

// ===== impl Proxy =====

impl Proxy {
    /// Proxy all traffic to the passed Unix Domain Socket path.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate wreq;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = wreq::Client::builder()
    ///     .proxy(wreq::Proxy::unix("/var/run/docker.sock")?)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    #[cfg(unix)]
    pub fn unix<P: uds::IntoUnixSocket>(unix: P) -> crate::Result<Proxy> {
        Ok(Proxy::new(Intercept::Unix(unix.unix_socket())))
    }

    /// Proxy all HTTP traffic to the passed URL.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate wreq;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = wreq::Client::builder()
    ///     .proxy(wreq::Proxy::http("https://my.prox")?)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn http<U: IntoProxy>(proxy_scheme: U) -> crate::Result<Proxy> {
        proxy_scheme
            .into_proxy()
            .map(Intercept::Http)
            .map(Proxy::new)
    }

    /// Proxy all HTTPS traffic to the passed URL.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate wreq;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = wreq::Client::builder()
    ///     .proxy(wreq::Proxy::https("https://example.prox:4545")?)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn https<U: IntoProxy>(proxy_scheme: U) -> crate::Result<Proxy> {
        proxy_scheme
            .into_proxy()
            .map(Intercept::Https)
            .map(Proxy::new)
    }

    /// Proxy **all** traffic to the passed URL.
    ///
    /// "All" refers to `https` and `http` URLs. Other schemes are not
    /// recognized by wreq.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate wreq;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = wreq::Client::builder()
    ///     .proxy(wreq::Proxy::all("http://pro.xy")?)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn all<U: IntoProxy>(proxy_scheme: U) -> crate::Result<Proxy> {
        proxy_scheme
            .into_proxy()
            .map(Intercept::All)
            .map(Proxy::new)
    }

    fn new(intercept: Intercept) -> Proxy {
        Proxy {
            extra: Extra {
                auth: None,
                misc: None,
            },
            intercept,
            no_proxy: None,
        }
    }

    /// Set the `Proxy-Authorization` header using Basic auth.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate wreq;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let proxy = wreq::Proxy::https("http://localhost:1234")?.basic_auth("Aladdin", "open sesame");
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn basic_auth(mut self, username: &str, password: &str) -> Proxy {
        match self.intercept {
            Intercept::All(ref mut s)
            | Intercept::Http(ref mut s)
            | Intercept::Https(ref mut s) => {
                s.set_username(username).expect("is a base");
                s.set_password(Some(password)).expect("is a base");
                let header = crate::util::basic_auth(username, Some(password));
                self.extra.auth = Some(header);
            }
            #[cfg(unix)]
            Intercept::Unix(_) => {
                // For Unix sockets, we don't set the auth header.
                // This is a no-op, but keeps the API consistent.
            }
        }

        self
    }

    /// Set the `Proxy-Authorization` header to a specified value.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate wreq;
    /// # use wreq::header::*;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let proxy = wreq::Proxy::https("http://localhost:1234")?
    ///     .custom_http_auth(HeaderValue::from_static("justletmeinalreadyplease"));
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn custom_http_auth(mut self, header_value: HeaderValue) -> Proxy {
        self.extra.auth = Some(header_value);
        self
    }

    /// Adds a Custom Headers to Proxy
    /// Adds custom headers to this Proxy
    ///
    /// # Example
    /// ```
    /// # extern crate wreq;
    /// # use wreq::header::*;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut headers = HeaderMap::new();
    /// headers.insert(USER_AGENT, "wreq".parse().unwrap());
    /// let proxy = wreq::Proxy::https("http://localhost:1234")?.custom_http_headers(headers);
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn custom_http_headers(mut self, headers: HeaderMap) -> Proxy {
        match self.intercept {
            Intercept::All(_) | Intercept::Http(_) | Intercept::Https(_) => {
                self.extra.misc = Some(headers);
            }
            #[cfg(unix)]
            Intercept::Unix(_) => {
                // For Unix sockets, we don't set custom headers.
                // This is a no-op, but keeps the API consistent.
            }
        }

        self
    }

    /// Adds a `No Proxy` exclusion list to this Proxy
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate wreq;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let proxy = wreq::Proxy::https("http://localhost:1234")?
    ///     .no_proxy(wreq::NoProxy::from_string("direct.tld, sub.direct2.tld"));
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn no_proxy(mut self, no_proxy: Option<NoProxy>) -> Proxy {
        self.no_proxy = no_proxy;
        self
    }

    pub(crate) fn into_matcher(self) -> Matcher {
        let Proxy {
            intercept,
            extra,
            no_proxy,
        } = self;

        let cache_maybe_has_http_auth = |url: &Url, extra: &Option<HeaderValue>| {
            url.scheme() == Scheme::HTTP.as_str() && (url.password().is_some() || extra.is_some())
        };

        let cache_maybe_has_http_custom_headers = |url: &Url, extra: &Option<HeaderMap>| {
            url.scheme() == Scheme::HTTP.as_str() && extra.is_some()
        };

        let maybe_has_http_auth;
        let maybe_has_http_custom_headers;

        let inner = match intercept {
            Intercept::All(url) => {
                maybe_has_http_auth = cache_maybe_has_http_auth(&url, &extra.auth);
                maybe_has_http_custom_headers =
                    cache_maybe_has_http_custom_headers(&url, &extra.misc);
                matcher::Matcher::builder()
                    .all(String::from(url))
                    .no(no_proxy.as_ref().map(|n| n.inner.as_ref()).unwrap_or(""))
                    .build(extra)
            }
            Intercept::Http(url) => {
                maybe_has_http_auth = cache_maybe_has_http_auth(&url, &extra.auth);
                maybe_has_http_custom_headers =
                    cache_maybe_has_http_custom_headers(&url, &extra.misc);
                matcher::Matcher::builder()
                    .http(String::from(url))
                    .no(no_proxy.as_ref().map(|n| n.inner.as_ref()).unwrap_or(""))
                    .build(extra)
            }
            Intercept::Https(url) => {
                maybe_has_http_auth = cache_maybe_has_http_auth(&url, &extra.auth);
                maybe_has_http_custom_headers =
                    cache_maybe_has_http_custom_headers(&url, &extra.misc);
                matcher::Matcher::builder()
                    .https(String::from(url))
                    .no(no_proxy.as_ref().map(|n| n.inner.as_ref()).unwrap_or(""))
                    .build(extra)
            }
            #[cfg(unix)]
            Intercept::Unix(unix) => {
                // Unix sockets don't use HTTP auth
                maybe_has_http_auth = false;
                // Unix sockets don't use custom headers
                maybe_has_http_custom_headers = false;
                matcher::Matcher::builder()
                    .unix(unix)
                    .no(no_proxy.as_ref().map(|n| n.inner.as_ref()).unwrap_or(""))
                    .build(extra)
            }
        };

        Matcher {
            inner: Box::new(inner),
            maybe_has_http_auth,
            maybe_has_http_custom_headers,
        }
    }
}

// ===== impl NoProxy =====

impl NoProxy {
    /// Returns a new no-proxy configuration based on environment variables (or `None` if no
    /// variables are set) see [self::NoProxy::from_string()] for the string format
    pub fn from_env() -> Option<NoProxy> {
        let raw = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .ok()?;

        // Per the docs, this returns `None` if no environment variable is set. We can only reach
        // here if an env var is set, so we return `Some(NoProxy::default)` if `from_string`
        // returns None, which occurs with an empty string.
        Some(Self::from_string(&raw).unwrap_or_default())
    }

    /// Returns a new no-proxy configuration based on a `no_proxy` string (or `None` if no variables
    /// are set)
    /// The rules are as follows:
    /// * The environment variable `NO_PROXY` is checked, if it is not set, `no_proxy` is checked
    /// * If neither environment variable is set, `None` is returned
    /// * Entries are expected to be comma-separated (whitespace between entries is ignored)
    /// * IP addresses (both IPv4 and IPv6) are allowed, as are optional subnet masks (by adding
    ///   /size, for example "`192.168.1.0/24`").
    /// * An entry "`*`" matches all hostnames (this is the only wildcard allowed)
    /// * Any other entry is considered a domain name (and may contain a leading dot, for example
    ///   `google.com` and `.google.com` are equivalent) and would match both that domain AND all
    ///   subdomains.
    ///
    /// For example, if `"NO_PROXY=google.com, 192.168.1.0/24"` was set, all the following would
    /// match (and therefore would bypass the proxy):
    /// * `http://google.com/`
    /// * `http://www.google.com/`
    /// * `http://192.168.1.42/`
    ///
    /// The URL `http://notgoogle.com/` would not match.
    pub fn from_string(no_proxy_list: &str) -> Option<Self> {
        Some(NoProxy {
            inner: no_proxy_list.into(),
        })
    }
}

// ===== impl Matcher =====

impl Matcher {
    pub(crate) fn system() -> Self {
        Self {
            inner: Box::new(matcher::Matcher::from_system()),
            // maybe env vars have auth!
            maybe_has_http_auth: true,
            maybe_has_http_custom_headers: true,
        }
    }

    pub(crate) fn intercept(&self, dst: &Uri) -> Option<Intercepted> {
        self.inner.intercept(dst)
    }

    /// Return whether this matcher might provide HTTP (not s) auth.
    ///
    /// This is very specific. If this proxy needs auth to be part of a Forward
    /// request (instead of a tunnel), this should return true.
    ///
    /// If it's not sure, this should return true.
    ///
    /// This is meant as a hint to allow skipping a more expensive check
    /// (calling `intercept()`) if it will never need auth when Forwarding.
    #[inline]
    pub(crate) fn maybe_has_http_auth(&self) -> bool {
        self.maybe_has_http_auth
    }

    #[inline]
    pub(crate) fn maybe_has_http_custom_headers(&self) -> bool {
        self.maybe_has_http_custom_headers
    }

    pub(crate) fn http_non_tunnel_basic_auth(&self, dst: &Uri) -> Option<HeaderValue> {
        if let Some(Intercepted::Proxy(proxy)) = self.intercept(dst) {
            if proxy.uri().scheme() == Some(&Scheme::HTTP) {
                return proxy.basic_auth().cloned();
            }
        }
        None
    }

    pub(crate) fn http_non_tunnel_custom_headers(&self, dst: &Uri) -> Option<HeaderMap> {
        if let Some(Intercepted::Proxy(proxy)) = self.intercept(dst) {
            if proxy.uri().scheme() == Some(&Scheme::HTTP) {
                return proxy.custom_headers().cloned();
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    fn intercepted_uri(p: &Matcher, s: &str) -> Uri {
        match p.intercept(&s.parse().unwrap()).unwrap() {
            Intercepted::Proxy(proxy) => proxy.uri().clone(),
            _ => {
                unreachable!("intercepted_uri should only be called with a Proxy matcher")
            }
        }
    }

    #[test]
    fn test_http() {
        let target = "http://example.domain/";
        let p = Proxy::http(target).unwrap().into_matcher();

        let http = "http://hyper.rs";
        let other = "https://hyper.rs";

        assert_eq!(intercepted_uri(&p, http), target);
        assert!(p.intercept(&uri(other)).is_none());
    }

    #[test]
    fn test_https() {
        let target = "http://example.domain/";
        let p = Proxy::https(target).unwrap().into_matcher();

        let http = "http://hyper.rs";
        let other = "https://hyper.rs";

        assert!(p.intercept(&uri(http)).is_none());
        assert_eq!(intercepted_uri(&p, other), target);
    }

    #[test]
    fn test_all() {
        let target = "http://example.domain/";
        let p = Proxy::all(target).unwrap().into_matcher();

        let http = "http://hyper.rs";
        let https = "https://hyper.rs";
        // no longer supported
        //let other = "x-youve-never-heard-of-me-mr-proxy://hyper.rs";

        assert_eq!(intercepted_uri(&p, http), target);
        assert_eq!(intercepted_uri(&p, https), target);
        //assert_eq!(intercepted_uri(&p, other), target);
    }

    #[test]
    fn test_standard_with_custom_auth_header() {
        let target = "http://example.domain/";
        let p = Proxy::all(target)
            .unwrap()
            .custom_http_auth(http::HeaderValue::from_static("testme"))
            .into_matcher();

        let got = p.intercept(&uri("http://anywhere.local")).unwrap();
        match got {
            Intercepted::Proxy(got) => {
                let auth = got.basic_auth().unwrap();
                assert_eq!(auth, "testme");
            }
            _ => {
                unreachable!("Expected a Proxy Intercepted");
            }
        }
    }

    #[test]
    fn test_maybe_has_http_auth() {
        let m = Proxy::all("https://letme:in@yo.local")
            .unwrap()
            .into_matcher();
        assert!(!m.maybe_has_http_auth(), "https always tunnels");

        let m = Proxy::all("http://letme:in@yo.local")
            .unwrap()
            .into_matcher();
        assert!(m.maybe_has_http_auth(), "http forwards");
    }

    fn test_socks_proxy_default_port(url: &str, url2: &str, port: u16) {
        let m = Proxy::all(url).unwrap().into_matcher();

        let http = "http://hyper.rs";
        let https = "https://hyper.rs";

        assert_eq!(intercepted_uri(&m, http).port_u16(), Some(1080));
        assert_eq!(intercepted_uri(&m, https).port_u16(), Some(1080));

        // custom port
        let m = Proxy::all(url2).unwrap().into_matcher();

        assert_eq!(intercepted_uri(&m, http).port_u16(), Some(port));
        assert_eq!(intercepted_uri(&m, https).port_u16(), Some(port));
    }

    #[test]
    fn test_socks4_proxy_default_port() {
        test_socks_proxy_default_port("socks4://example.com", "socks4://example.com:1234", 1234);
        test_socks_proxy_default_port("socks4a://example.com", "socks4a://example.com:1234", 1234);
    }

    #[test]
    fn test_socks5_proxy_default_port() {
        test_socks_proxy_default_port("socks5://example.com", "socks5://example.com:1234", 1234);
        test_socks_proxy_default_port("socks5h://example.com", "socks5h://example.com:1234", 1234);
    }
}
