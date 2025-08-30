//! Extension utilities.

use bytes::Bytes;
use http::{
    Uri,
    uri::{Authority, PathAndQuery, Scheme},
};
use percent_encoding::{AsciiSet, CONTROLS};

use crate::Body;

/// https://url.spec.whatwg.org/#fragment-percent-encode-set
const FRAGMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'`');

/// https://url.spec.whatwg.org/#path-percent-encode-set
const PATH: &AsciiSet = &FRAGMENT.add(b'#').add(b'?').add(b'{').add(b'}');

/// https://url.spec.whatwg.org/#userinfo-percent-encode-set
const USERINFO: &AsciiSet = &PATH
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'=')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'|');

/// Extension trait for `Uri` helpers.
pub(crate) trait UriExt {
    /// Returns true if the URI scheme is HTTPS.
    fn is_https(&self) -> bool;

    /// Returns true if the URI scheme is HTTP.
    fn is_http(&self) -> bool;

    #[cfg(feature = "ws")]
    /// Sets the scheme of the URI.
    fn set_scheme(&mut self, scheme: Scheme);

    /// Sets the query component of the URI, replacing any existing query.
    fn set_query(&mut self, query: String);

    /// Returns the username and password from the URI's userinfo, if present.
    /// Returns (None, None) if no userinfo is present.
    fn userinfo(&self) -> (Option<&str>, Option<&str>);

    /// Sets the username and password in the URI's userinfo component.
    /// If both are empty, removes userinfo.
    fn set_userinfo(&mut self, username: &str, password: Option<&str>);
}

/// Extension trait for http::response::Builder objects
///
/// Allows the user to add a `Uri` to the http::Response
pub trait ResponseBuilderExt {
    /// A builder method for the `http::response::Builder` type that allows the user to add a `Uri`
    /// to the `http::Response`
    fn uri(self, uri: Uri) -> Self;
}

/// Extension trait for http::Response objects
///
/// Provides methods to extract URI information from HTTP responses
pub trait ResponseExt {
    /// Returns a reference to the `Uri` associated with this response, if available.
    fn uri(&self) -> Option<&Uri>;
}

/// Extension type to store the request URI in a response's extensions.
#[derive(Clone)]
pub(crate) struct RequestUri(pub Uri);

impl UriExt for Uri {
    #[inline]
    fn is_https(&self) -> bool {
        self.scheme() == Some(&Scheme::HTTPS)
    }

    #[inline]
    fn is_http(&self) -> bool {
        self.scheme() == Some(&Scheme::HTTP)
    }

    #[cfg(feature = "ws")]
    #[doc(hidden)]
    fn set_scheme(&mut self, scheme: Scheme) {
        let mut parts = self.clone().into_parts();
        parts.scheme = Some(scheme);
        if let Ok(uri) = Uri::from_parts(parts) {
            *self = uri;
        }
    }

    fn set_query(&mut self, query: String) {
        if query.is_empty() {
            return;
        }

        let path = self.path();
        let mut parts = self.clone().into_parts();
        parts.path_and_query = PathAndQuery::try_from(format!("{path}?{query}")).ok();

        if let Ok(uri) = Uri::from_parts(parts) {
            *self = uri;
        }
    }

    fn userinfo(&self) -> (Option<&str>, Option<&str>) {
        self.authority()
            .and_then(|auth| auth.as_str().rsplit_once('@'))
            .map_or((None, None), |(userinfo, _)| {
                match userinfo.split_once(':') {
                    Some((u, p)) => ((!u.is_empty()).then_some(u), (!p.is_empty()).then_some(p)),
                    None => (Some(userinfo), None),
                }
            })
    }

    fn set_userinfo(&mut self, username: &str, password: Option<&str>) {
        let mut parts = self.clone().into_parts();

        let authority = match self.authority() {
            Some(authority) => authority,
            None => return,
        };

        let host_and_port = authority
            .as_str()
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or_else(|| authority.as_str());

        let authority = match (username.is_empty(), password) {
            (true, None) => Authority::from_maybe_shared(Bytes::from(host_and_port.to_owned())),
            (true, Some(pass)) => {
                let pass = percent_encoding::utf8_percent_encode(pass, USERINFO);
                Authority::from_maybe_shared(Bytes::from(format!(":{pass}@{host_and_port}")))
            }
            (false, Some(pass)) => {
                let username = percent_encoding::utf8_percent_encode(username, USERINFO);
                let pass = percent_encoding::utf8_percent_encode(pass, USERINFO);
                Authority::from_maybe_shared(Bytes::from(format!(
                    "{username}:{pass}@{host_and_port}"
                )))
            }
            (false, None) => {
                let username = percent_encoding::utf8_percent_encode(username, USERINFO);
                Authority::from_maybe_shared(Bytes::from(format!("{username}@{host_and_port}")))
            }
        };

        parts.authority = match authority {
            Ok(authority) => Some(authority),
            Err(_err) => {
                debug!("Failed to set userinfo in URI: {_err}");
                return;
            }
        };

        if let Ok(uri) = Uri::from_parts(parts) {
            *self = uri;
        }
    }
}

impl ResponseBuilderExt for http::response::Builder {
    fn uri(self, uri: Uri) -> Self {
        self.extension(RequestUri(uri))
    }
}

impl ResponseExt for http::Response<Body> {
    fn uri(&self) -> Option<&Uri> {
        self.extensions().get::<RequestUri>().map(|r| &r.0)
    }
}

#[cfg(test)]
mod tests {
    use http::{Uri, response::Builder};

    use super::{RequestUri, ResponseBuilderExt, ResponseExt, UriExt};
    use crate::Body;

    #[test]
    fn test_uri_ext_is_https() {
        let https_uri: Uri = "https://example.com".parse().unwrap();
        let http_uri: Uri = "http://example.com".parse().unwrap();

        assert!(https_uri.is_https());
        assert!(!http_uri.is_https());
        assert!(http_uri.is_http());
        assert!(!https_uri.is_http());
    }

    #[test]
    fn test_userinfo_with_username_and_password() {
        let uri: Uri = "http://user:pass@example.com".parse().unwrap();
        let (username, password) = uri.userinfo();

        assert_eq!(username, Some("user"));
        assert_eq!(password, Some("pass"));
    }

    #[test]
    fn test_userinfo_with_empty_username() {
        let uri: Uri = "http://:pass@example.com".parse().unwrap();
        let (username, password) = uri.userinfo();

        assert_eq!(username, None);
        assert_eq!(password, Some("pass"));
    }

    #[test]
    fn test_userinfo_with_empty_password() {
        let uri: Uri = "http://user:@example.com".parse().unwrap();
        let (username, password) = uri.userinfo();

        assert_eq!(username, Some("user"));
        assert_eq!(password, None);

        let uri: Uri = "http://user@example.com".parse().unwrap();
        let (username, password) = uri.userinfo();

        assert_eq!(username, Some("user"));
        assert_eq!(password, None);
    }

    #[test]
    fn test_userinfo_without_colon() {
        let uri: Uri = "http://something@example.com".parse().unwrap();
        let (username, password) = uri.userinfo();

        assert_eq!(username, Some("something"));
        assert_eq!(password, None);
    }

    #[test]
    fn test_userinfo_without_at() {
        let uri: Uri = "http://example.com".parse().unwrap();
        let (username, password) = uri.userinfo();

        assert_eq!(username, None);
        assert_eq!(password, None);
    }

    #[test]
    fn test_set_userinfo_both() {
        let mut uri: Uri = "http://example.com/path".parse().unwrap();
        uri.set_userinfo("user", Some("pass"));

        let (username, password) = uri.userinfo();
        assert_eq!(username, Some("user"));
        assert_eq!(password, Some("pass"));
        assert_eq!(uri.to_string(), "http://user:pass@example.com/path");
    }

    #[test]
    fn test_set_userinfo_empty_username() {
        let mut uri: Uri = "http://user:pass@example.com/path".parse().unwrap();
        uri.set_userinfo("", Some("pass"));

        let (username, password) = uri.userinfo();
        assert_eq!(username, None);
        assert_eq!(password, Some("pass"));
        assert_eq!(uri.to_string(), "http://:pass@example.com/path");
    }

    #[test]
    fn test_set_userinfo_none_password() {
        let mut uri: Uri = "http://user:pass@example.com/path".parse().unwrap();
        uri.set_userinfo("user", None);

        let (username, password) = uri.userinfo();
        assert_eq!(username, Some("user"));
        assert_eq!(password, None);
        assert_eq!(uri.to_string(), "http://user@example.com/path");
    }

    #[test]
    fn test_set_userinfo_empty_username_and_password() {
        let mut uri: Uri = "http://user:pass@example.com/path".parse().unwrap();
        uri.set_userinfo("", None);

        let (username, password) = uri.userinfo();
        assert_eq!(username, None);
        assert_eq!(password, None);
        assert_eq!(uri.to_string(), "http://example.com/path");
    }

    #[test]
    fn test_set_userinfo_with_encoding() {
        use http::Uri;

        use crate::ext::UriExt;

        let mut uri: Uri = "http://example.com/path".parse().unwrap();
        uri.set_userinfo("us er", Some("p@ss:word!"));

        let (username, password) = uri.userinfo();
        assert_eq!(username, Some("us%20er"));
        assert_eq!(password, Some("p%40ss%3Aword!"));

        assert_eq!(
            uri.to_string(),
            "http://us%20er:p%40ss%3Aword!@example.com/path"
        );
    }

    #[test]
    fn test_set_userinfo_only_username_with_encoding() {
        use http::Uri;

        use crate::ext::UriExt;

        let mut uri: Uri = "http://example.com/".parse().unwrap();
        uri.set_userinfo("user name", None);

        let (username, password) = uri.userinfo();
        assert_eq!(username, Some("user%20name"));
        assert_eq!(password, None);

        assert_eq!(uri.to_string(), "http://user%20name@example.com/");
    }

    #[test]
    fn test_set_userinfo_only_password_with_encoding() {
        use http::Uri;

        use crate::ext::UriExt;

        let mut uri: Uri = "http://example.com/".parse().unwrap();
        uri.set_userinfo("", Some("p@ss word"));

        let (username, password) = uri.userinfo();
        assert_eq!(username, None);
        assert_eq!(password, Some("p%40ss%20word"));

        assert_eq!(uri.to_string(), "http://:p%40ss%20word@example.com/");
    }

    #[test]
    fn test_set_query() {
        let mut uri: Uri = "http://example.com/path".parse().unwrap();
        uri.set_query("key=value&foo=bar".to_string());

        assert_eq!(uri.to_string(), "http://example.com/path?key=value&foo=bar");

        let mut uri: Uri = "http://example.com/path?existing=param".parse().unwrap();
        uri.set_query("newkey=newvalue".to_string());

        assert_eq!(uri.to_string(), "http://example.com/path?newkey=newvalue");

        let mut uri: Uri = "http://example.com/path".parse().unwrap();
        uri.set_query("".to_string());

        assert_eq!(uri.to_string(), "http://example.com/path");
    }

    #[test]
    fn test_response_builder_ext() {
        let uri = Uri::try_from("http://example.com").unwrap();
        let response = Builder::new()
            .status(200)
            .uri(uri.clone())
            .body(Body::empty())
            .unwrap();

        assert_eq!(response.uri(), Some(&uri));
    }

    #[test]
    fn test_response_ext() {
        let uri = Uri::try_from("http://example.com").unwrap();
        let response = http::Response::builder()
            .status(200)
            .extension(RequestUri(uri.clone()))
            .body(Body::empty())
            .unwrap();

        assert_eq!(response.uri(), Some(&uri));
    }
}
