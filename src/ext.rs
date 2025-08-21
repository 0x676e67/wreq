//! Extension utilities for `Uri`.

use http::{
    Uri,
    uri::{Authority, Scheme},
};
use url::Url;

use crate::Body;

/// Extension trait for `Uri` helpers.
pub(crate) trait UriExt {
    #[doc(hidden)]
    fn is_https(&self) -> bool;

    #[doc(hidden)]
    fn is_http(&self) -> bool;

    fn userinfo(&self) -> Option<&str>;
    fn username(&self) -> Option<&str>;
    fn password(&self) -> Option<&str>;
}

/// Extension trait for `Authority` helpers.
pub(crate) trait AuthorityExt {
    fn userinfo(&self) -> Option<&str>;
    fn username(&self) -> Option<&str>;
    fn password(&self) -> Option<&str>;
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
/// Provides methods to extract URL information from HTTP responses
pub trait ResponseExt {
    /// Returns a reference to the `Uri` associated with this response, if available.
    fn url(&self) -> Option<&Uri>;
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RequestUrl(pub Url);

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ResponseUri(pub Uri);

impl UriExt for Uri {
    #[inline]
    fn is_https(&self) -> bool {
        self.scheme() == Some(&Scheme::HTTPS)
    }

    #[inline]
    fn is_http(&self) -> bool {
        self.scheme() == Some(&Scheme::HTTP)
    }

    #[inline]
    fn userinfo(&self) -> Option<&str> {
        if let Some(authority) = self.authority() {
            let s = authority.as_str();
            s.rfind('@').map(|i| &s[..i])
        } else {
            None
        }
    }

    #[inline]
    fn username(&self) -> Option<&str> {
        self.userinfo()
            .map(|a| a.rfind(':').map(|i| &a[..i]).unwrap_or(a))
    }

    #[inline]
    fn password(&self) -> Option<&str> {
        self.userinfo()
            .and_then(|a| a.rfind(':').map(|i| &a[i + 1..]))
    }
}

// NB: Treating &str with direct indexes is OK, since Uri parsed the Authority,
// and ensured it's all ASCII (or %-encoded).
impl AuthorityExt for Authority {
    #[inline]
    fn userinfo(&self) -> Option<&str> {
        let s = self.as_str();
        s.rfind('@').map(|i| &s[..i])
    }

    #[inline]
    fn username(&self) -> Option<&str> {
        self.userinfo()
            .map(|a| a.rfind(':').map(|i| &a[..i]).unwrap_or(a))
    }

    #[inline]
    fn password(&self) -> Option<&str> {
        self.userinfo()
            .and_then(|a| a.rfind(':').map(|i| &a[i + 1..]))
    }
}

impl ResponseBuilderExt for http::response::Builder {
    fn uri(self, uri: Uri) -> Self {
        self.extension(ResponseUri(uri))
    }
}

impl ResponseExt for http::Response<Body> {
    fn url(&self) -> Option<&Uri> {
        self.extensions().get::<ResponseUri>().map(|r| &r.0)
    }
}

#[cfg(test)]
mod tests {
    use http::{Uri, response::Builder};

    use super::{ResponseBuilderExt, ResponseExt, ResponseUri};
    use crate::Body;

    #[test]
    fn test_response_builder_ext() {
        let url = Uri::try_from("http://example.com").unwrap();
        let response = Builder::new()
            .status(200)
            .uri(url.clone())
            .body(())
            .unwrap();

        assert_eq!(
            response.extensions().get::<ResponseUri>(),
            Some(&ResponseUri(url))
        );
    }

    #[test]
    fn test_response_ext() {
        let url = Uri::try_from("http://example.com").unwrap();
        let response = http::Response::builder()
            .status(200)
            .extension(ResponseUri(url.clone()))
            .body(Body::empty())
            .unwrap();

        assert_eq!(response.url(), Some(&url));
    }
}
