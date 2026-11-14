#[cfg(all(target_os = "macos", feature = "system-proxy"))]
mod mac;
#[cfg(unix)]
mod uds;
#[cfg(all(windows, feature = "system-proxy"))]
mod win;

pub(crate) mod matcher;

use std::hash::{Hash, Hasher};
#[cfg(unix)]
use std::{path::Path, sync::Arc};

use http::{HeaderMap, Uri, header::HeaderValue};

use crate::{IntoUri, ext::UriExt};

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
/// - a URI of how to talk to the proxy
/// - rules on what `Client` requests should be directed to the proxy
///
/// For instance, let's look at `Proxy::http`:
///
/// ```rust
/// use wreq::Proxy;
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let proxy = Proxy::http("https://secure.example")?;
/// # Ok(())
/// # }
/// ```
///
/// This proxy will intercept all HTTP requests, and make use of the proxy
/// at `https://secure.example`. A request to `http://hyper.rs` will talk
/// to your proxy. A request to `https://hyper.rs` will not.
///
/// TLS to an `https://` or `quic://` proxy follows the client's TLS settings and is verified
/// against the proxy host rather than the request host.
///
/// Multiple `Proxy` rules can be configured for a `Client`. The `Client` will
/// check each `Proxy` in the order it was added. This could mean that a
/// `Proxy` added first with eager intercept rules, such as `Proxy::all`,
/// would prevent a `Proxy` later in the list from ever working, so take care.
///
/// By enabling the `"socks"` feature it is possible to use a socks proxy:
/// ```rust
/// use wreq::Proxy;
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let proxy = Proxy::http("socks5://192.168.1.1:9000")?;
/// # Ok(())
/// # }
/// ```
///
/// With both `socks` and `http3`, SOCKS5 proxies relay HTTP/3 using
/// [UDP ASSOCIATE](https://www.rfc-editor.org/rfc/rfc1928.html#section-7).
/// `socks5://` resolves targets locally; `socks5h://` leaves target DNS to the proxy.
/// The TCP control connection remains open while its QUIC connection is in use.
/// A relay hostname is resolved locally, including with `socks5h://`.
/// SOCKS4 and HTTP CONNECT proxies do not support HTTP/3.
///
/// With the `http3` feature, `quic://host:port` selects an HTTP/3 MASQUE proxy for
/// HTTP/3 requests. The port defaults to 443. This uses the
/// [RFC 9298 default template](https://www.rfc-editor.org/rfc/rfc9298.html#section-2),
/// `https://host:port/.well-known/masque/udp/{target_host}/{target_port}/`.
/// Proxy credentials and custom headers are sent in the CONNECT-UDP request.
/// HTTP/1 and HTTP/2 requests through this proxy return an error, so `Proxy::http`
/// rejects it. Without `http3`, `quic://` is ignored like other unsupported schemes.
/// The outer connection uses the request's QUIC options with Datagrams enabled. Its MTU never
/// drops below one that fits 1200-byte UDP payloads, and a `max_datagram_frame_size` too small
/// to buffer 16 of them uses the default. A tunnel that cannot carry them fails the connection.
#[derive(Clone, Debug)]
pub struct Proxy {
    extra: Extra,
    scheme: ProxyScheme,
    no_proxy: Option<NoProxy>,
}

/// A configuration for filtering out requests that shouldn't be proxied
#[derive(Clone, Debug, Default)]
pub struct NoProxy {
    inner: String,
}

// ===== Internal =====

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
}

#[derive(Clone, Debug)]
enum ProxyScheme {
    All(Uri),
    Http(Uri),
    Https(Uri),
    #[cfg(unix)]
    Unix(Arc<Path>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Extra {
    auth: Option<HeaderValue>,
    misc: Option<HeaderMap>,
}

/// Validates an explicit QUIC proxy port, or supplies HTTPS's default port.
/// `Authority::port` alone cannot distinguish a missing port from an invalid one.
pub(crate) fn quic_port(uri: &Uri) -> Result<u16, &'static str> {
    let authority = uri.authority().ok_or("QUIC proxy has no authority")?;
    if authority.host().is_empty() {
        return Err("QUIC proxy has no host");
    }
    let authority = authority
        .as_str()
        .rsplit_once('@')
        .map_or(authority.as_str(), |(_, host)| host);
    let suffix = authority
        .strip_prefix(uri.host().ok_or("QUIC proxy has no host")?)
        .ok_or("invalid QUIC proxy authority")?;
    if suffix.is_empty() {
        return Ok(443);
    }
    suffix
        .strip_prefix(':')
        .filter(|port| port.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or("QUIC proxy port must be between 1 and 65535")
}

// ===== impl Proxy =====

impl Proxy {
    /// Proxy all HTTP traffic to the passed URI.
    ///
    /// # Example
    ///
    /// ```
    /// use wreq::{Client, Proxy};
    ///
    /// # extern crate wreq;
    /// # #[cfg(feature = "tokio-rt")]
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::builder_tokio()
    ///     .proxy(Proxy::http("https://my.prox")?)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn http<U: IntoUri>(uri: U) -> crate::Result<Proxy> {
        uri.into_uri().map(ProxyScheme::Http).and_then(Proxy::new)
    }

    /// Proxy all HTTPS traffic to the passed URI.
    ///
    /// # Example
    ///
    /// ```
    /// use wreq::{Client, Proxy};
    ///
    /// # extern crate wreq;
    /// # #[cfg(feature = "tokio-rt")]
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::builder_tokio()
    ///     .proxy(Proxy::https("https://example.prox:4545")?)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn https<U: IntoUri>(uri: U) -> crate::Result<Proxy> {
        uri.into_uri().map(ProxyScheme::Https).and_then(Proxy::new)
    }

    /// Proxy **all** traffic to the passed URI.
    ///
    /// "All" refers to `https` and `http` URIs. Other schemes are not
    /// recognized by wreq.
    ///
    /// # Example
    ///
    /// ```
    /// use wreq::{Client, Proxy};
    ///
    /// # extern crate wreq;
    /// # #[cfg(feature = "tokio-rt")]
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::builder_tokio()
    ///     .proxy(Proxy::all("http://pro.xy")?)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn all<U: IntoUri>(uri: U) -> crate::Result<Proxy> {
        uri.into_uri().map(ProxyScheme::All).and_then(Proxy::new)
    }

    /// Proxy all traffic to the passed Unix Domain Socket path.
    ///
    /// # Example
    ///
    /// ```
    /// use wreq::{Client, Proxy};
    ///
    /// # extern crate wreq;
    /// # #[cfg(feature = "tokio-rt")]
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::builder_tokio()
    ///     .proxy(Proxy::unix("/var/run/docker.sock")?)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    #[cfg(unix)]
    pub fn unix<P: uds::IntoUnixSocket>(unix: P) -> crate::Result<Proxy> {
        Proxy::new(ProxyScheme::Unix(unix.unix_socket()))
    }

    fn new(scheme: ProxyScheme) -> crate::Result<Proxy> {
        // Without `http3`, `quic://` is ignored like any other unsupported scheme.
        #[cfg(feature = "http3")]
        if let ProxyScheme::All(uri) | ProxyScheme::Http(uri) | ProxyScheme::Https(uri) = &scheme
            && uri
                .scheme_str()
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("quic"))
        {
            // `http://` requests never use HTTP/3, so this proxy could only fail them.
            if matches!(scheme, ProxyScheme::Http(_)) {
                return Err(crate::Error::builder(
                    "QUIC proxies require https:// targets; use Proxy::https or Proxy::all",
                ));
            }
            quic_port(uri).map_err(crate::Error::builder)?;
        }
        Ok(Proxy {
            extra: Extra {
                auth: None,
                misc: None,
            },
            scheme,
            no_proxy: None,
        })
    }

    /// Set the `Proxy-Authorization` header using Basic auth.
    ///
    /// # Example
    ///
    /// ```
    /// use wreq::Proxy;
    ///
    /// # extern crate wreq;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let proxy = Proxy::https("http://localhost:1234")?.basic_auth("Aladdin", "open sesame");
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn basic_auth(mut self, username: &str, password: &str) -> Proxy {
        match self.scheme {
            ProxyScheme::All(ref mut uri)
            | ProxyScheme::Http(ref mut uri)
            | ProxyScheme::Https(ref mut uri) => {
                let header = crate::util::basic_auth(username, Some(password));
                uri.set_userinfo(username, Some(password));
                self.extra.auth = Some(header);
            }
            #[cfg(unix)]
            ProxyScheme::Unix(_) => {
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
    /// use wreq::Proxy;
    ///
    /// # extern crate wreq;
    /// # use wreq::header::*;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let proxy = Proxy::https("http://localhost:1234")?
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
    /// use wreq::Proxy;
    ///
    /// # extern crate wreq;
    /// # use wreq::header::*;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut headers = HeaderMap::new();
    /// headers.insert(USER_AGENT, "wreq".parse().unwrap());
    /// let proxy = Proxy::https("http://localhost:1234")?.custom_http_headers(headers);
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn custom_http_headers(mut self, headers: HeaderMap) -> Proxy {
        match self.scheme {
            ProxyScheme::All(_) | ProxyScheme::Http(_) | ProxyScheme::Https(_) => {
                self.extra.misc = Some(headers);
            }
            #[cfg(unix)]
            ProxyScheme::Unix(_) => {
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
    /// use wreq::{NoProxy, Proxy};
    ///
    /// # extern crate wreq;
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let proxy = Proxy::https("http://localhost:1234")?
    ///     .no_proxy(NoProxy::from_string("direct.tld, sub.direct2.tld"));
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
            scheme,
            extra,
            no_proxy,
        } = self;

        let no_proxy = no_proxy.as_ref().map_or("", |n| n.inner.as_ref());

        let inner = match scheme {
            ProxyScheme::All(uri) => matcher::Matcher::builder()
                .all(uri.to_string())
                .no(no_proxy)
                .build(extra),
            ProxyScheme::Http(uri) => matcher::Matcher::builder()
                .http(uri.to_string())
                .no(no_proxy)
                .build(extra),
            ProxyScheme::Https(uri) => matcher::Matcher::builder()
                .https(uri.to_string())
                .no(no_proxy)
                .build(extra),
            #[cfg(unix)]
            ProxyScheme::Unix(unix) => matcher::Matcher::builder()
                .unix(unix)
                .no(no_proxy)
                .build(extra),
        };

        Matcher {
            inner: Box::new(inner),
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
    /// The URI `http://notgoogle.com/` would not match.
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
        }
    }

    /// Intercept the given destination URI, returning the intercepted
    /// proxy configuration if there is a match.
    #[inline]
    pub(crate) fn intercept(&self, dst: &Uri) -> Option<Intercepted> {
        self.inner.intercept(dst)
    }
}

impl crate::config::connect::ConnectConfig for Matcher {
    const SCOPE: crate::config::connect::ConfigScope = crate::config::connect::ConfigScope::ROUTE;
}

// ===== impl Extra =====

impl Hash for Extra {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.auth.hash(state);
        match &self.misc {
            Some(headers) => {
                1u8.hash(state);
                headers.len().hash(state);

                let mut names = headers.keys().collect::<Vec<_>>();
                names.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
                for name in names {
                    name.as_str().hash(state);
                    for value in headers.get_all(name).iter() {
                        value.as_bytes().hash(state);
                    }
                }
            }
            None => 0u8.hash(state),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;

    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    fn intercept(p: &Matcher, s: &Uri) -> matcher::Intercept {
        match p.intercept(s).unwrap() {
            Intercepted::Proxy(proxy) => proxy,
            #[cfg(unix)]
            _ => {
                unreachable!("intercepted_port should only be called with a Proxy matcher")
            }
        }
    }

    fn intercepted_uri(p: &Matcher, s: &str) -> Uri {
        match p.intercept(&s.parse().unwrap()).unwrap() {
            Intercepted::Proxy(proxy) => proxy.uri().clone(),
            #[cfg(unix)]
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

    #[cfg(feature = "http3")]
    #[test]
    fn test_quic_proxy() {
        let destination = uri("https://example.com/");
        for (address, expected) in [
            ("quic://proxy.test", "quic://proxy.test:443/"),
            ("QUIC://proxy.test", "quic://proxy.test:443/"),
            ("QuIc://proxy.test:8443", "quic://proxy.test:8443/"),
            ("quic://proxy.test:8443", "quic://proxy.test:8443/"),
            ("quic://[::1]", "quic://[::1]:443/"),
            ("quic://[::1]:8443", "quic://[::1]:8443/"),
        ] {
            let matcher = Proxy::https(address).unwrap().into_matcher();
            assert_eq!(intercept(&matcher, &destination).uri(), expected);
            assert!(matcher.intercept(&uri("http://example.com/")).is_none());
            // http:// targets never use HTTP/3.
            assert!(Proxy::http(address).unwrap_err().is_builder(), "{address}");
        }
        for address in [
            "quic://proxy.test:",
            "quic://proxy.test:0",
            "quic://proxy.test:70000",
            "quic://proxy.test:abc",
            "quic://proxy.test:+443",
            "quic://[::1]:70000",
            "QUIC://user:pass@proxy.test:abc",
        ] {
            for result in [
                Proxy::all(address),
                Proxy::http(address),
                Proxy::https(address),
            ] {
                assert!(result.unwrap_err().is_builder(), "{address}");
            }
        }

        let proxy = Proxy::all("quic://Aladdin:open%20sesame@proxy.test")
            .unwrap()
            .no_proxy(NoProxy::from_string(".direct.test,127.0.0.1"));
        let matcher = proxy.clone().into_matcher();
        let intercepted = intercept(&matcher, &destination);
        assert_eq!(intercepted.uri(), "quic://proxy.test:443/");
        assert_eq!(
            intercepted.basic_auth(),
            Some(&crate::util::basic_auth("Aladdin", Some("open sesame")))
        );
        assert!(intercepted.basic_auth().unwrap().is_sensitive());
        for direct in ["https://sub.direct.test/", "https://127.0.0.1/"] {
            assert!(matcher.intercept(&uri(direct)).is_none());
        }

        let matcher = proxy.clone().basic_auth("other", "password").into_matcher();
        assert_eq!(
            intercept(&matcher, &destination).basic_auth(),
            Some(&crate::util::basic_auth("other", Some("password")))
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-proxy-header", HeaderValue::from_static("proxy-only"));
        let matcher = proxy
            .custom_http_auth(HeaderValue::from_static("Bearer proxy-token"))
            .custom_http_headers(headers.clone())
            .into_matcher();
        let intercepted = intercept(&matcher, &destination);
        assert_eq!(intercepted.basic_auth().unwrap(), "Bearer proxy-token");
        assert_eq!(intercepted.custom_headers(), Some(&headers));
        assert_eq!(intercepted.uri(), "quic://proxy.test:443/");
    }

    #[test]
    fn test_standard_with_custom_auth_header() {
        let target = "http://example.domain/";
        let p = Proxy::all(target)
            .unwrap()
            .custom_http_auth(http::HeaderValue::from_static("testme"))
            .into_matcher();

        let got = intercept(&p, &uri("http://anywhere.local"));
        let auth = got.basic_auth().unwrap();
        assert_eq!(auth, "testme");
    }

    #[test]
    fn test_maybe_has_http_auth() {
        let uri = uri("http://example.domain/");

        let m = Proxy::all("https://letme:in@yo.local")
            .unwrap()
            .into_matcher();

        let got = intercept(&m, &uri);
        assert!(got.basic_auth().is_some(), "https forwards");

        let m = Proxy::all("http://letme:in@yo.local")
            .unwrap()
            .into_matcher();

        let got = intercept(&m, &uri);
        assert!(got.basic_auth().is_some(), "http forwards");
    }

    #[test]
    fn test_maybe_has_http_custom_headers() {
        let uri = uri("http://example.domain/");

        let mut headers = HeaderMap::new();
        headers.insert("x-custom-header", HeaderValue::from_static("custom-value"));
        headers.insert(
            "x-another-header",
            HeaderValue::from_static("another-value"),
        );

        let mut reversed_headers = HeaderMap::new();
        reversed_headers.insert(
            "x-another-header",
            HeaderValue::from_static("another-value"),
        );
        reversed_headers.insert("x-custom-header", HeaderValue::from_static("custom-value"));

        let m = Proxy::all("https://yo.local")
            .unwrap()
            .custom_http_headers(headers.clone())
            .into_matcher();
        let same = Proxy::all("https://yo.local")
            .unwrap()
            .custom_http_headers(reversed_headers)
            .into_matcher();

        let hash = |matcher: &Matcher| {
            let mut state = DefaultHasher::new();
            matcher.hash(&mut state);
            state.finish()
        };
        assert_eq!(m, same);
        assert_eq!(hash(&m), hash(&same));

        let proxy = intercept(&m, &uri);
        let got_headers = proxy.custom_headers().unwrap();
        assert_eq!(got_headers, &headers, "https forwards");

        let m = Proxy::all("http://yo.local")
            .unwrap()
            .custom_http_headers(headers.clone())
            .into_matcher();

        let proxy = intercept(&m, &uri);
        let got_headers = proxy.custom_headers().unwrap();
        assert_eq!(got_headers, &headers, "http forwards");
    }

    fn test_socks_proxy_default_port(uri: &str, url2: &str, port: u16) {
        let m = Proxy::all(uri).unwrap().into_matcher();

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
        test_socks_proxy_default_port("SOCKS5://example.com", "Socks5H://example.com:1234", 1234);
    }
}
