use std::convert::TryFrom;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use http::{Extensions, Request as HttpRequest, Version, request::Parts};
use serde::Serialize;

use super::body::Body;
use super::client::{Client, Pending};
#[cfg(feature = "multipart")]
use super::multipart;
use super::response::Response;
use crate::config::RequestTimeout;
#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "solaris",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
use crate::core::ext::RequestInterface;
use crate::core::ext::{
    RequestConfig, RequestHttpVersionPref, RequestIpv4Addr, RequestIpv6Addr,
    RequestOriginalHeaders, RequestProxyMatcher,
};
use crate::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use crate::proxy::Matcher as ProxyMatcher;
use crate::{Method, OriginalHeaders, Proxy, Url, redirect};

/// A request which can be executed with `Client::execute()`.
pub struct Request {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Body>,
    extensions: Extensions,
    redirect: Option<redirect::Policy>,
    allow_compression: bool,
}

/// A builder to construct the properties of a `Request`.
///
/// To construct a `RequestBuilder`, refer to the `Client` documentation.
#[must_use = "RequestBuilder does nothing until you 'send' it"]
pub struct RequestBuilder {
    client: Client,
    request: crate::Result<Request>,
}

impl Request {
    /// Constructs a new request.
    #[inline]
    pub fn new(method: Method, url: Url) -> Self {
        Request {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
            extensions: Extensions::new(),
            redirect: None,
            allow_compression: cfg!(any(
                feature = "gzip",
                feature = "brotli",
                feature = "deflate",
                feature = "zstd"
            )),
        }
    }

    /// Get the method.
    #[inline]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Get a mutable reference to the method.
    #[inline]
    pub fn method_mut(&mut self) -> &mut Method {
        &mut self.method
    }

    /// Get the url.
    #[inline]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Get a mutable reference to the url.
    #[inline]
    pub fn url_mut(&mut self) -> &mut Url {
        &mut self.url
    }

    /// Get the headers.
    #[inline]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Get a mutable reference to the headers.
    #[inline]
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Get the original headers.
    #[inline]
    pub fn original_headers(&self) -> Option<&OriginalHeaders> {
        RequestConfig::<RequestOriginalHeaders>::get(&self.extensions)
    }

    /// Get a mutable reference to the original headers.
    #[inline]
    pub fn original_headers_mut(&mut self) -> &mut Option<OriginalHeaders> {
        RequestConfig::<RequestOriginalHeaders>::get_mut(&mut self.extensions)
    }

    /// Get the redirect policy.
    #[inline]
    pub fn redirect(&self) -> Option<&redirect::Policy> {
        self.redirect.as_ref()
    }

    /// Get a mutable reference to the redirect policy.
    #[inline]
    pub fn redirect_mut(&mut self) -> &mut Option<redirect::Policy> {
        &mut self.redirect
    }

    /// Get a mutable reference to the allow_compression policy.
    #[cfg(any(
        feature = "gzip",
        feature = "brotli",
        feature = "deflate",
        feature = "zstd"
    ))]
    #[inline]
    pub fn allow_compression_mut(&mut self) -> &mut bool {
        &mut self.allow_compression
    }

    /// Get the body.
    #[inline]
    pub fn body(&self) -> Option<&Body> {
        self.body.as_ref()
    }

    /// Get a mutable reference to the body.
    #[inline]
    pub fn body_mut(&mut self) -> &mut Option<Body> {
        &mut self.body
    }

    /// Get the http version.
    #[inline]
    pub fn version(&self) -> Option<&Version> {
        RequestConfig::<RequestHttpVersionPref>::get(&self.extensions)
    }

    /// Get a mutable reference to the http version.
    #[inline]
    pub fn version_mut(&mut self) -> &mut Option<Version> {
        RequestConfig::<RequestHttpVersionPref>::get_mut(&mut self.extensions)
    }

    /// Get the timeout.
    #[inline]
    pub fn timeout(&self) -> Option<&Duration> {
        RequestConfig::<RequestTimeout>::get(&self.extensions)
    }

    /// Get a mutable reference to the timeout.
    #[inline]
    pub fn timeout_mut(&mut self) -> &mut Option<Duration> {
        RequestConfig::<RequestTimeout>::get_mut(&mut self.extensions)
    }

    /// Get the read timeout.
    #[inline]
    pub fn read_timeout(&self) -> Option<&Duration> {
        RequestConfig::<RequestTimeout>::get(&self.extensions)
    }

    /// Get a mutable reference to the read timeout.
    #[inline]
    pub fn read_timeout_mut(&mut self) -> &mut Option<Duration> {
        RequestConfig::<RequestTimeout>::get_mut(&mut self.extensions)
    }

    /// Get a mutable reference to the local ipv4 address.
    #[inline]
    pub fn local_ipv4_address_mut(&mut self) -> &mut Option<Ipv4Addr> {
        RequestConfig::<RequestIpv4Addr>::get_mut(&mut self.extensions)
    }

    /// Get a mutable reference to the local ipv6 address.
    #[inline]
    pub fn local_ipv6_address_mut(&mut self) -> &mut Option<Ipv6Addr> {
        RequestConfig::<RequestIpv6Addr>::get_mut(&mut self.extensions)
    }

    /// Get a mutable reference to the interface.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    #[inline]
    pub fn interface_mut(&mut self) -> &mut Option<std::borrow::Cow<'static, str>> {
        RequestConfig::<RequestInterface>::get_mut(&mut self.extensions)
    }

    /// Get a mutable reference to the proxy matcher.
    #[inline]
    pub(crate) fn proxy_matcher_mut(&mut self) -> &mut Option<ProxyMatcher> {
        RequestConfig::<RequestProxyMatcher>::get_mut(&mut self.extensions)
    }

    /// Get the extensions.
    #[inline]
    pub(crate) fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Get a mutable reference to the extensions.
    #[inline]
    pub(crate) fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }

    /// Attempt to clone the request.
    ///
    /// `None` is returned if the request can not be cloned, i.e. if the body is a stream.
    pub fn try_clone(&self) -> Option<Request> {
        let body = match self.body.as_ref() {
            Some(body) => Some(body.try_clone()?),
            None => None,
        };
        let mut req = Request::new(self.method().clone(), self.url().clone());
        *req.timeout_mut() = self.timeout().copied();
        *req.read_timeout_mut() = self.read_timeout().copied();
        *req.headers_mut() = self.headers().clone();
        *req.version_mut() = self.version().cloned();
        *req.redirect_mut() = self.redirect().cloned();
        #[cfg(any(
            feature = "gzip",
            feature = "brotli",
            feature = "deflate",
            feature = "zstd"
        ))]
        {
            *req.allow_compression_mut() = self.allow_compression;
        }
        *req.extensions_mut() = self.extensions().clone();
        req.body = body;
        Some(req)
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn pieces(
        self,
    ) -> (
        Method,
        Url,
        HeaderMap,
        Option<Body>,
        Extensions,
        Option<redirect::Policy>,
        bool,
    ) {
        (
            self.method,
            self.url,
            self.headers,
            self.body,
            self.extensions,
            self.redirect,
            self.allow_compression,
        )
    }
}

impl RequestBuilder {
    pub(super) fn new(client: Client, request: crate::Result<Request>) -> RequestBuilder {
        let mut builder = RequestBuilder { client, request };

        let auth = builder
            .request
            .as_mut()
            .ok()
            .and_then(|req| extract_authority(&mut req.url));

        if let Some((username, password)) = auth {
            builder.basic_auth(username, password)
        } else {
            builder
        }
    }

    /// Assemble a builder starting from an existing `Client` and a `Request`.
    pub fn from_parts(client: Client, request: Request) -> RequestBuilder {
        RequestBuilder {
            client,
            request: crate::Result::Ok(request),
        }
    }

    /// Add a `Header` to this Request.
    ///
    /// If the header is already present, the value will be replaced.
    pub fn header<K, V>(self, key: K, value: V) -> RequestBuilder
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.header_operation(key, value, false, true, false)
    }

    /// Add a `Header` to append to the request.
    ///
    /// The new header is always appended to the request, even if the header already exists.
    pub fn header_append<K, V>(self, key: K, value: V) -> RequestBuilder
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.header_operation(key, value, false, false, false)
    }

    /// Add a `Header` to this Request.
    ///
    /// `sensitive` - if true, the header value is set to sensitive
    /// `overwrite` - if true, the header value is overwritten if it already exists
    /// `or_insert` - if true, the header value is inserted if it does not already exist
    fn header_operation<K, V>(
        mut self,
        key: K,
        value: V,
        sensitive: bool,
        overwrite: bool,
        or_insert: bool,
    ) -> RequestBuilder
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        let mut error = None;
        if let Ok(ref mut req) = self.request {
            match <HeaderName as TryFrom<K>>::try_from(key) {
                Ok(key) => match <HeaderValue as TryFrom<V>>::try_from(value) {
                    Ok(mut value) => {
                        // We want to potentially make an unsensitive header
                        // to be sensitive, not the reverse. So, don't turn off
                        // a previously sensitive header.
                        if sensitive {
                            value.set_sensitive(true);
                        }

                        // If or_insert is true, we want to skip the insertion if the header already exists
                        if or_insert {
                            req.headers_mut().entry(key).or_insert(value);
                        } else if overwrite {
                            req.headers_mut().insert(key, value);
                        } else {
                            req.headers_mut().append(key, value);
                        }
                    }
                    Err(e) => error = Some(crate::error::builder(e.into())),
                },
                Err(e) => error = Some(crate::error::builder(e.into())),
            };
        }
        if let Some(err) = error {
            self.request = Err(err);
        }
        self
    }

    /// Add a set of Headers to the existing ones on this Request.
    ///
    /// The headers will be merged in to any already set.
    pub fn headers(mut self, headers: crate::header::HeaderMap) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            crate::util::replace_headers(req.headers_mut(), headers);
        }
        self
    }

    /// Set the original headers for this request.
    pub fn original_headers(mut self, original_headers: OriginalHeaders) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.original_headers_mut() = Some(original_headers);
        }
        self
    }

    /// Enable HTTP authentication.
    pub fn auth<V>(self, value: V) -> RequestBuilder
    where
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.header_operation(crate::header::AUTHORIZATION, value, true, true, false)
    }

    /// Enable HTTP basic authentication.
    ///
    /// ```rust
    /// # use wreq::Error;
    ///
    /// # async fn run() -> Result<(), Error> {
    /// let client = wreq::Client::new();
    /// let resp = client.delete("http://httpbin.org/delete")
    ///     .basic_auth("admin", Some("good password"))
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn basic_auth<U, P>(self, username: U, password: Option<P>) -> RequestBuilder
    where
        U: fmt::Display,
        P: fmt::Display,
    {
        let header_value = crate::util::basic_auth(username, password);
        self.header_operation(
            crate::header::AUTHORIZATION,
            header_value,
            true,
            true,
            false,
        )
    }

    /// Enable HTTP bearer authentication.
    pub fn bearer_auth<T>(self, token: T) -> RequestBuilder
    where
        T: fmt::Display,
    {
        let header_value = format!("Bearer {}", token);
        self.header_operation(
            crate::header::AUTHORIZATION,
            header_value,
            true,
            true,
            false,
        )
    }

    /// Set the request body.
    pub fn body<T: Into<Body>>(mut self, body: T) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.body_mut() = Some(body.into());
        }
        self
    }

    /// Enables a request timeout.
    ///
    /// The timeout is applied from when the request starts connecting until the
    /// response body has finished. It affects only this request and overrides
    /// the timeout configured using `ClientBuilder::timeout()`.
    pub fn timeout(mut self, timeout: Duration) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.timeout_mut() = Some(timeout);
        }
        self
    }

    /// Enables a read timeout.
    ///
    /// The read timeout is applied from when the response body starts being read
    /// until the response body has finished. It affects only this request and
    /// overrides the read timeout configured using `ClientBuilder::read_timeout()`.
    pub fn read_timeout(mut self, timeout: Duration) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.read_timeout_mut() = Some(timeout);
        }
        self
    }

    /// Sends a multipart/form-data body.
    ///
    /// ```
    /// # use wreq::Error;
    ///
    /// # async fn run() -> Result<(), Error> {
    /// let client = wreq::Client::new();
    /// let form = wreq::multipart::Form::new()
    ///     .text("key3", "value3")
    ///     .text("key4", "value4");
    ///
    ///
    /// let response = client.post("your url")
    ///     .multipart(form)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "multipart")]
    #[cfg_attr(docsrs, doc(cfg(feature = "multipart")))]
    pub fn multipart(self, mut multipart: multipart::Form) -> RequestBuilder {
        let mut builder = self.header_operation(
            CONTENT_TYPE,
            format!("multipart/form-data; boundary={}", multipart.boundary()),
            false,
            false,
            true,
        );

        builder = match multipart.compute_length() {
            Some(length) => builder.header(http::header::CONTENT_LENGTH, length),
            None => builder,
        };

        if let Ok(ref mut req) = builder.request {
            *req.body_mut() = Some(multipart.stream())
        }
        builder
    }

    /// Modify the query string of the URL.
    ///
    /// Modifies the URL of this request, adding the parameters provided.
    /// This method appends and does not overwrite. This means that it can
    /// be called multiple times and that existing query parameters are not
    /// overwritten if the same key is used. The key will simply show up
    /// twice in the query string.
    /// Calling `.query(&[("foo", "a"), ("foo", "b")])` gives `"foo=a&foo=b"`.
    ///
    /// # Note
    /// This method does not support serializing a single key-value
    /// pair. Instead of using `.query(("key", "val"))`, use a sequence, such
    /// as `.query(&[("key", "val")])`. It's also possible to serialize structs
    /// and maps into a key-value pair.
    ///
    /// # Errors
    /// This method will fail if the object you provide cannot be serialized
    /// into a query string.
    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> RequestBuilder {
        let mut error = None;
        if let Ok(ref mut req) = self.request {
            let url = req.url_mut();
            let mut pairs = url.query_pairs_mut();
            let serializer = serde_urlencoded::Serializer::new(&mut pairs);

            if let Err(err) = query.serialize(serializer) {
                error = Some(crate::error::builder(err));
            }
        }
        if let Ok(ref mut req) = self.request {
            if let Some("") = req.url().query() {
                req.url_mut().set_query(None);
            }
        }
        if let Some(err) = error {
            self.request = Err(err);
        }
        self
    }

    /// Set HTTP version
    pub fn version(mut self, version: Version) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.version_mut() = Some(version);
        }
        self
    }

    /// Set the redirect policy for this request.
    pub fn redirect(mut self, policy: redirect::Policy) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            req.redirect = Some(policy)
        }
        self
    }

    /// Sets if this request will announce that it accepts compression.
    ///
    /// This value defaults to true. Note that this only lets the browser know that this request supports
    /// compression, the server might choose not to compress the content.
    #[cfg(any(
        feature = "gzip",
        feature = "brotli",
        feature = "deflate",
        feature = "zstd"
    ))]
    pub fn allow_compression(mut self, allow_compression: bool) -> Self {
        if let Ok(ref mut req) = self.request {
            req.allow_compression = allow_compression
        }
        self
    }

    /// Set the proxy for this request.
    ///
    /// # Examples
    ///
    /// ```
    /// use wreq::Client;
    /// use wreq::Proxy;
    ///
    /// let client = Client::new();
    /// let proxy = Proxy::all("http://hyper.rs/prox")?.basic_auth("Aladdin", "open sesame");
    ///
    /// let resp = client
    ///     .get("https://tls.peet.ws/api/all")
    ///     .proxy(proxy)
    ///     .send()
    ///     .await?;
    /// ```
    pub fn proxy(mut self, proxy: Proxy) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.proxy_matcher_mut() = Some(proxy.into_matcher());
        }
        self
    }

    /// Set the local address for this request.
    pub fn local_address<V>(mut self, local_address: V) -> RequestBuilder
    where
        V: Into<Option<IpAddr>>,
    {
        if let Ok(ref mut req) = self.request {
            if let Some(addr) = local_address.into() {
                match addr {
                    IpAddr::V4(ipv4) => *req.local_ipv4_address_mut() = Some(ipv4),
                    IpAddr::V6(ipv6) => *req.local_ipv6_address_mut() = Some(ipv6),
                }
            }
        }
        self
    }

    /// Set the local addresses for this request.
    pub fn local_addresses<V4, V6>(mut self, ipv4: V4, ipv6: V6) -> RequestBuilder
    where
        V4: Into<Option<Ipv4Addr>>,
        V6: Into<Option<Ipv6Addr>>,
    {
        if let Ok(ref mut req) = self.request {
            *req.local_ipv4_address_mut() = ipv4.into();
            *req.local_ipv6_address_mut() = ipv6.into();
        }
        self
    }

    /// Set the interface for this request.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        )))
    )]
    pub fn interface<I>(mut self, interface: I) -> RequestBuilder
    where
        I: Into<std::borrow::Cow<'static, str>>,
    {
        if let Ok(ref mut req) = self.request {
            *req.interface_mut() = Some(interface.into());
        }
        self
    }

    /// Send a form body.
    ///
    /// Sets the body to the url encoded serialization of the passed value,
    /// and also sets the `Content-Type: application/x-www-form-urlencoded`
    /// header.
    ///
    /// ```rust
    /// # use wreq::Error;
    /// # use std::collections::HashMap;
    /// #
    /// # async fn run() -> Result<(), Error> {
    /// let mut params = HashMap::new();
    /// params.insert("lang", "rust");
    ///
    /// let client = wreq::Client::new();
    /// let res = client.post("http://httpbin.org")
    ///     .form(&params)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// This method fails if the passed value cannot be serialized into
    /// url encoded format
    pub fn form<T: Serialize + ?Sized>(mut self, form: &T) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            match serde_urlencoded::to_string(form) {
                Ok(body) => {
                    req.headers_mut()
                        .entry(CONTENT_TYPE)
                        .or_insert(HeaderValue::from_static(
                            "application/x-www-form-urlencoded",
                        ));
                    *req.body_mut() = Some(body.into());
                }
                Err(err) => self.request = Err(crate::error::builder(err)),
            }
        }
        self
    }

    /// Send a JSON body.
    ///
    /// # Optional
    ///
    /// This requires the optional `json` feature enabled.
    ///
    /// # Errors
    ///
    /// Serialization can fail if `T`'s implementation of `Serialize` decides to
    /// fail, or if `T` contains a map with non-string keys.
    #[cfg(feature = "json")]
    #[cfg_attr(docsrs, doc(cfg(feature = "json")))]
    pub fn json<T: Serialize + ?Sized>(mut self, json: &T) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            match serde_json::to_vec(json) {
                Ok(body) => {
                    req.headers_mut()
                        .entry(CONTENT_TYPE)
                        .or_insert(HeaderValue::from_static("application/json"));
                    *req.body_mut() = Some(body.into());
                }
                Err(err) => self.request = Err(crate::error::builder(err)),
            }
        }

        self
    }

    /// Build a `Request`, which can be inspected, modified and executed with
    /// `Client::execute()`.
    pub fn build(self) -> crate::Result<Request> {
        self.request
    }

    /// Build a `Request`, which can be inspected, modified and executed with
    /// `Client::execute()`.
    ///
    /// This is similar to [`RequestBuilder::build()`], but also returns the
    /// embedded `Client`.
    pub fn build_split(self) -> (Client, crate::Result<Request>) {
        (self.client, self.request)
    }

    /// Constructs the Request and sends it to the target URL, returning a
    /// future Response.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending request,
    /// redirect loop was detected or redirect limit was exhausted.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use wreq::Error;
    /// #
    /// # async fn run() -> Result<(), Error> {
    /// let response = wreq::Client::new()
    ///     .get("https://hyper.rs")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send(self) -> impl Future<Output = Result<Response, crate::Error>> {
        match self.request {
            Ok(req) => self.client.execute_request(req),
            Err(err) => Pending::new_err(err),
        }
    }

    /// Attempt to clone the RequestBuilder.
    ///
    /// `None` is returned if the RequestBuilder can not be cloned,
    /// i.e. if the request body is a stream.
    ///
    /// # Examples
    ///
    /// ```
    /// # use wreq::Error;
    /// #
    /// # fn run() -> Result<(), Error> {
    /// let client = wreq::Client::new();
    /// let builder = client.post("http://httpbin.org/post")
    ///     .body("from a &str!");
    /// let clone = builder.try_clone();
    /// assert!(clone.is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_clone(&self) -> Option<RequestBuilder> {
        self.request
            .as_ref()
            .ok()
            .and_then(|req| req.try_clone())
            .map(|req| RequestBuilder {
                client: self.client.clone(),
                request: Ok(req),
            })
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt_request_fields(&mut f.debug_struct("Request"), self).finish()
    }
}

impl fmt::Debug for RequestBuilder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("RequestBuilder");
        match self.request {
            Ok(ref req) => fmt_request_fields(&mut builder, req).finish(),
            Err(ref err) => builder.field("error", err).finish(),
        }
    }
}

fn fmt_request_fields<'a, 'b>(
    f: &'a mut fmt::DebugStruct<'a, 'b>,
    req: &Request,
) -> &'a mut fmt::DebugStruct<'a, 'b> {
    f.field("method", &req.method)
        .field("url", &req.url)
        .field("headers", &req.headers)
}

/// Check the request URL for a "username:password" type authority, and if
/// found, remove it from the URL and return it.
pub(crate) fn extract_authority(url: &mut Url) -> Option<(String, Option<String>)> {
    use percent_encoding::percent_decode;

    if url.has_authority() {
        let username: String = percent_decode(url.username().as_bytes())
            .decode_utf8()
            .ok()?
            .into();
        let password = url.password().and_then(|pass| {
            percent_decode(pass.as_bytes())
                .decode_utf8()
                .ok()
                .map(String::from)
        });
        if !username.is_empty() || password.is_some() {
            url.set_username("")
                .expect("has_authority means set_username shouldn't fail");
            url.set_password(None)
                .expect("has_authority means set_password shouldn't fail");
            return Some((username, password));
        }
    }

    None
}

impl<T> TryFrom<HttpRequest<T>> for Request
where
    T: Into<Body>,
{
    type Error = crate::Error;

    fn try_from(req: HttpRequest<T>) -> crate::Result<Self> {
        let (parts, body) = req.into_parts();
        let Parts {
            method,
            uri,
            headers,
            ..
        } = parts;
        let url = crate::into_url::IntoUrlSealed::into_url(uri.to_string())?;
        Ok(Request {
            method,
            url,
            headers,
            body: Some(body.into()),
            redirect: None,
            allow_compression: cfg!(any(
                feature = "gzip",
                feature = "brotli",
                feature = "deflate",
                feature = "zstd"
            )),
            extensions: Extensions::new(),
        })
    }
}

impl TryFrom<Request> for HttpRequest<Body> {
    type Error = crate::Error;

    fn try_from(req: Request) -> crate::Result<Self> {
        let version = req.version().cloned();

        let Request {
            method,
            url,
            headers,
            body,
            ..
        } = req;

        let mut builder = HttpRequest::builder();

        if let Some(version) = version {
            builder = builder.version(version);
        }

        let mut req = builder
            .method(method)
            .uri(url.as_str())
            .body(body.unwrap_or_else(Body::empty))
            .map_err(crate::error::builder)?;

        *req.headers_mut() = headers;
        Ok(req)
    }
}
