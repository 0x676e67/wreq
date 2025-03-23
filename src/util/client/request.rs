#![allow(missing_debug_implementations)]

use super::NetworkScheme;
use crate::error::BoxError;
use http::{
    Error, HeaderMap, HeaderName, HeaderValue, Method, Request, Uri, Version,
    header::CONTENT_LENGTH, request::Builder,
};
use http_body::Body;
use std::{any::Any, marker::PhantomData};

/// Represents an HTTP request with additional metadata.
///
/// The `InnerRequest` struct encapsulates an HTTP request along with additional
/// metadata such as the HTTP version and network scheme. It provides methods
/// to build and manipulate the request.
///
/// # Type Parameters
///
/// - `B`: The body type of the request, which must implement the `Body` trait.
pub struct InnerRequest<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    request: Request<B>,
    version: Option<Version>,
    network_scheme: NetworkScheme,
}

impl<B> InnerRequest<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Creates a new `InnerRequestBuilder`.
    ///
    /// This method returns a builder that can be used to construct an `InnerRequest`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rquest::util::client::request::InnerRequest;
    /// use http::Method;
    ///
    /// let request = InnerRequest::builder()
    ///     .method(Method::GET)
    ///     .uri("http://example.com".parse().unwrap())
    ///     .body(())
    ///     .unwrap();
    /// ```
    pub fn builder<'a>() -> InnerRequestBuilder<'a, B> {
        InnerRequestBuilder {
            builder: Request::builder(),
            version: None,
            network_scheme: Default::default(),
            headers_order: None,
            _body: PhantomData,
        }
    }

    /// Decomposes the `InnerRequest` into its components.
    ///
    /// This method returns a tuple containing the request, network scheme, and HTTP version.
    ///
    /// # Returns
    ///
    /// A tuple `(Request<B>, NetworkScheme, Option<Version>)` containing the components of the request.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rquest::util::client::request::InnerRequest;
    /// use http::Method;
    ///
    /// let request = InnerRequest::builder()
    ///     .method(Method::GET)
    ///     .uri("http://example.com".parse().unwrap())
    ///     .body(())
    ///     .unwrap();
    ///
    /// let (req, network_scheme, version) = request.pieces();
    /// ```
    pub fn pieces(self) -> (Request<B>, Option<Version>, NetworkScheme) {
        (self.request, self.version, self.network_scheme)
    }
}

/// A builder for constructing HTTP requests.
///
/// The `InnerRequestBuilder` struct provides a fluent interface for building
/// `InnerRequest` instances. It allows setting various properties of the request,
/// such as the method, URI, headers, and body.
///
/// # Type Parameters
///
/// - `B`: The body type of the request, which must implement the `Body` trait.
pub struct InnerRequestBuilder<'a, B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    builder: Builder,
    version: Option<Version>,
    network_scheme: NetworkScheme,
    headers_order: Option<&'a [HeaderName]>,
    _body: PhantomData<B>,
}

impl<'a, B> InnerRequestBuilder<'a, B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Sets the method for the request.
    ///
    /// # Arguments
    ///
    /// * `method` - The HTTP method to be used for the request.
    ///
    /// # Returns
    ///
    /// The updated `InnerRequestBuilder`.
    #[inline]
    pub fn method(mut self, method: Method) -> Self {
        self.builder = self.builder.method(method);
        self
    }

    /// Sets the URI for the request.
    ///
    /// # Arguments
    ///
    /// * `uri` - The URI to be used for the request.
    ///
    /// # Returns
    ///
    /// The updated `InnerRequestBuilder`.
    #[inline]
    pub fn uri(mut self, uri: Uri) -> Self {
        self.builder = self.builder.uri(uri);
        self
    }

    /// Sets the version for the request.
    ///
    /// # Arguments
    ///
    /// * `version` - The HTTP version to be used for the request.
    ///
    /// # Returns
    ///
    /// The updated `InnerRequestBuilder`.
    #[inline]
    pub fn version(mut self, version: Option<Version>) -> Self {
        if let Some(version) = version {
            self.builder = self.builder.version(version);
            // `Request` defaults to HTTP/1.1 as the version.
            // We don't know if the user has specified a version,
            // so we need to record it here for TLS ALPN negotiation.
            self.version = Some(version);
        }
        self
    }

    /// Sets the headers for the request.
    ///
    /// # Arguments
    ///
    /// * `headers` - The headers to be used for the request.
    ///
    /// # Returns
    ///
    /// The updated `InnerRequestBuilder`.
    #[inline]
    pub fn headers(mut self, mut headers: HeaderMap) -> Self {
        if let Some(h) = self.builder.headers_mut() {
            std::mem::swap(h, &mut headers)
        }
        self
    }

    /// Sets the headers order for the request.
    ///
    /// # Arguments
    ///
    /// * `order` - The order in which headers should be sent.
    ///
    /// # Returns
    ///
    /// The updated `InnerRequestBuilder`.
    #[inline]
    pub fn headers_order(mut self, order: Option<&'a [HeaderName]>) -> Self {
        self.headers_order = order;
        self
    }

    /// Sets an extension for the request.
    ///
    /// # Arguments
    ///
    /// * `extension` - The extension to be added to the request.
    ///
    /// # Returns
    ///
    /// The updated `InnerRequestBuilder`.
    #[inline]
    pub fn extension<T>(mut self, extension: Option<T>) -> Self
    where
        T: Clone + Any + Send + Sync + 'static,
    {
        if let Some(extension) = extension {
            self.builder = self.builder.extension(extension);
        }
        self
    }

    /// Sets the network scheme for the request.
    ///
    /// # Arguments
    ///
    /// * `network_scheme` - The network scheme to be used for the request.
    ///
    /// # Returns
    ///
    /// The updated `InnerRequestBuilder`.
    #[inline]
    pub fn network_scheme(mut self, network_scheme: NetworkScheme) -> Self {
        self.network_scheme = network_scheme;
        self
    }

    /// Sets the body for the request.
    ///
    /// # Arguments
    ///
    /// * `body` - The body to be used for the request.
    ///
    /// # Returns
    ///
    /// A `Result` containing the constructed `InnerRequest` or an `Error`.
    #[inline]
    pub fn body(mut self, body: B) -> Result<InnerRequest<B>, Error> {
        if let Some((method, (headers, headers_order))) = self
            .builder
            .method_ref()
            .cloned()
            .zip(self.builder.headers_mut().zip(self.headers_order))
        {
            add_content_length_header(method, headers, &body);
            sort_headers(headers, headers_order);
        }

        self.builder.body(body).map(|request| InnerRequest {
            request,
            version: self.version,
            network_scheme: self.network_scheme,
        })
    }
}

/// Adds the `Content-Length` header to the request.
///
/// # Arguments
///
/// * `method` - The HTTP method of the request.
/// * `headers` - The headers of the request.
/// * `body` - The body of the request.
#[inline]
fn add_content_length_header<B>(method: Method, headers: &mut HeaderMap, body: &B)
where
    B: Body,
{
    if let Some(len) = Body::size_hint(body).exact() {
        if len != 0 || method_has_defined_payload_semantics(method) {
            headers
                .entry(CONTENT_LENGTH)
                .or_insert_with(|| HeaderValue::from(len));
        }
    }
}

/// Checks if the method has defined payload semantics.
///
/// # Arguments
///
/// * `method` - The HTTP method to check.
///
/// # Returns
///
/// `true` if the method has defined payload semantics, otherwise `false`.
#[inline]
fn method_has_defined_payload_semantics(method: Method) -> bool {
    !matches!(
        method,
        Method::GET | Method::HEAD | Method::DELETE | Method::CONNECT
    )
}

/// Sorts the headers in the specified order.
///
/// Headers in `headers_order` are sorted to the front, preserving their order.
/// Remaining headers are appended in their original order.
///
/// # Arguments
///
/// * `headers` - The headers to be sorted.
/// * `headers_order` - The order in which headers should be sent.
#[inline]
fn sort_headers(headers: &mut HeaderMap, headers_order: &[HeaderName]) {
    if headers.len() <= 1 {
        return;
    }

    // Create a new header map to store the sorted headers
    let mut sorted_headers = HeaderMap::with_capacity(headers.keys_len());

    // First insert headers in the specified order
    for key in headers_order {
        if let Some(value) = headers.remove(key) {
            sorted_headers.insert(key.clone(), value);
        }
    }

    // Then insert any remaining headers that were not ordered
    for (key, value) in headers.drain() {
        if let Some(key) = key {
            sorted_headers.insert(key, value);
        }
    }

    std::mem::swap(headers, &mut sorted_headers);
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderMap, HeaderName, HeaderValue};

    #[test]
    fn test_sort_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("b-header", HeaderValue::from_static("b"));
        headers.insert("a-header", HeaderValue::from_static("a"));
        headers.insert("c-header", HeaderValue::from_static("c"));
        headers.insert("extra-header", HeaderValue::from_static("extra"));

        let headers_order = [
            HeaderName::from_static("a-header"),
            HeaderName::from_static("b-header"),
            HeaderName::from_static("c-header"),
        ];

        sort_headers(&mut headers, &headers_order);

        let mut iter = headers.iter();

        assert_eq!(
            iter.next(),
            Some((
                &HeaderName::from_static("a-header"),
                &HeaderValue::from_static("a")
            ))
        );
        assert_eq!(
            iter.next(),
            Some((
                &HeaderName::from_static("b-header"),
                &HeaderValue::from_static("b")
            ))
        );
        assert_eq!(
            iter.next(),
            Some((
                &HeaderName::from_static("c-header"),
                &HeaderValue::from_static("c")
            ))
        );
        assert_eq!(
            iter.next(),
            Some((
                &HeaderName::from_static("extra-header"),
                &HeaderValue::from_static("extra")
            ))
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_sort_headers_partial_match() {
        let mut headers = HeaderMap::new();
        headers.insert("x-header", HeaderValue::from_static("x"));
        headers.insert("y-header", HeaderValue::from_static("y"));

        let headers_order = [
            HeaderName::from_static("y-header"),
            HeaderName::from_static("z-header"),
        ];

        sort_headers(&mut headers, &headers_order);

        let mut iter = headers.iter();

        assert_eq!(
            iter.next(),
            Some((
                &HeaderName::from_static("y-header"),
                &HeaderValue::from_static("y")
            ))
        );
        assert_eq!(
            iter.next(),
            Some((
                &HeaderName::from_static("x-header"),
                &HeaderValue::from_static("x")
            ))
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_sort_headers_empty() {
        let mut headers = HeaderMap::new();
        let headers_order: [HeaderName; 0] = [];

        sort_headers(&mut headers, &headers_order);

        assert!(headers.is_empty());
    }

    #[test]
    fn test_sort_headers_no_ordering() {
        let mut headers = HeaderMap::new();
        headers.insert("random-header", HeaderValue::from_static("random"));

        let headers_order: [HeaderName; 0] = [];

        sort_headers(&mut headers, &headers_order);

        let mut iter = headers.iter();
        assert_eq!(
            iter.next(),
            Some((
                &HeaderName::from_static("random-header"),
                &HeaderValue::from_static("random")
            ))
        );
        assert_eq!(iter.next(), None);
    }
}
