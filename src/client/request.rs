use std::{
    convert::TryFrom,
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use http::{Extensions, Request as HttpRequest, Uri, Version, request::Parts};
use serde::Serialize;

#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
))]
use super::layer::config::RequestAcceptEncoding;
#[cfg(feature = "multipart")]
use super::multipart;
use super::{
    Body, EmulationFactory, Response,
    http::{Client, Pending},
    layer::config::{RequestDefaultHeaders, RequestRedirectPolicy, RequestTimeoutOptions},
};
use crate::{
    Error, Method, Proxy,
    core::{
        client::options::RequestOptions,
        ext::{RequestConfig, RequestConfigValue, RequestLayerOptions, RequestOrigHeaderMap},
    },
    ext::UriExt,
    header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, OrigHeaderMap},
    redirect,
};

/// A request which can be executed with `Client::execute()`.
#[derive(Debug)]
pub struct Request {
    /// The request's method
    method: Method,

    /// The request's URI
    uri: Uri,

    /// The request's headers
    headers: HeaderMap<HeaderValue>,

    /// The request's extensions
    extensions: Extensions,

    /// The request's body
    body: Option<Body>,
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
    pub fn new(method: Method, uri: Uri) -> Self {
        Request {
            method,
            uri,
            headers: HeaderMap::new(),
            extensions: Extensions::new(),
            body: None,
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

    /// Get the uri.
    #[inline]
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Get a mutable reference to the uri.
    #[inline]
    pub fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
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
    pub fn version(&self) -> Option<Version> {
        self.config::<RequestLayerOptions>()
            .and_then(RequestOptions::enforced_version)
    }

    /// Get a mutable reference to the http version.
    #[inline]
    pub fn version_mut(&mut self) -> &mut Option<Version> {
        self.config_mut::<RequestLayerOptions>()
            .enforced_version_mut()
    }

    /// Attempt to clone the request.
    ///
    /// `None` is returned if the request can not be cloned, i.e. if the body is a stream.
    pub fn try_clone(&self) -> Option<Request> {
        let body = match self.body() {
            Some(body) => Some(body.try_clone()?),
            None => None,
        };
        let mut req = Request::new(self.method().clone(), self.uri().clone());
        *req.headers_mut() = self.headers().clone();
        *req.version_mut() = self.version();
        *req.extensions_mut() = self.extensions().clone();
        *req.body_mut() = body;
        Some(req)
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

    #[inline]
    fn config<T>(&self) -> Option<&T::Value>
    where
        T: RequestConfigValue,
    {
        RequestConfig::<T>::get(&self.extensions)
    }

    #[inline]
    fn config_mut<T>(&mut self) -> &mut T::Value
    where
        T: RequestConfigValue,
        T::Value: Default,
    {
        RequestConfig::<T>::get_mut(&mut self.extensions).get_or_insert_default()
    }
}

impl RequestBuilder {
    pub(super) fn new(client: Client, request: crate::Result<Request>) -> RequestBuilder {
        let mut builder = RequestBuilder { client, request };

        let auth = builder
            .request
            .as_mut()
            .ok()
            .and_then(|req| extract_authority(&mut req.uri));

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

                        // If or_insert is true, we want to skip the insertion if the header already
                        // exists
                        if or_insert {
                            req.headers_mut().entry(key).or_insert(value);
                        } else if overwrite {
                            req.headers_mut().insert(key, value);
                        } else {
                            req.headers_mut().append(key, value);
                        }
                    }
                    Err(e) => error = Some(Error::builder(e.into())),
                },
                Err(e) => error = Some(Error::builder(e.into())),
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
    pub fn headers(mut self, headers: HeaderMap) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            crate::util::replace_headers(req.headers_mut(), headers);
        }
        self
    }

    /// Set the original headers for this request.
    pub fn orig_headers(mut self, orig_headers: OrigHeaderMap) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.config_mut::<RequestOrigHeaderMap>() = orig_headers;
        }
        self
    }

    /// Enable or disable client default headers for this request.
    ///
    /// By default, client default headers are included. Set to `false` to skip them.
    pub fn default_headers(mut self, enable: bool) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.config_mut::<RequestDefaultHeaders>() = enable;
        }
        self
    }

    /// Enable HTTP authentication.
    #[inline]
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
    /// let resp = client
    ///     .delete("http://httpbin.org/delete")
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
        let header_value = format!("Bearer {token}");
        self.header_operation(
            crate::header::AUTHORIZATION,
            header_value,
            true,
            true,
            false,
        )
    }

    /// Enables a request timeout.
    ///
    /// The timeout is applied from when the request starts connecting until the
    /// response body has finished. It affects only this request and overrides
    /// the timeout configured using `ClientBuilder::timeout()`.
    pub fn timeout(mut self, timeout: Duration) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            req.config_mut::<RequestTimeoutOptions>()
                .total_timeout(timeout);
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
            req.config_mut::<RequestTimeoutOptions>()
                .read_timeout(timeout);
        }
        self
    }

    /// Set the request body.
    pub fn body<T: Into<Body>>(mut self, body: T) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.body_mut() = Some(body.into());
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
    /// let response = client.post("your uri").multipart(form).send().await?;
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

    /// Modify the query string of the URI.
    ///
    /// Modifies the URI of this request, adding the parameters provided.
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
            match serde_urlencoded::to_string(query) {
                Ok(serializer) => {
                    let uri = req.uri_mut();
                    uri.set_query(serializer);
                }
                Err(err) => error = Some(Error::builder(err)),
            }
        }
        if let Some(err) = error {
            self.request = Err(err);
        }
        self
    }

    /// Send a form body.
    ///
    /// Sets the body to the uri encoded serialization of the passed value,
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
    /// let res = client
    ///     .post("http://httpbin.org")
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
    /// uri encoded format
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
                Err(err) => self.request = Err(Error::builder(err)),
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
                Err(err) => self.request = Err(Error::builder(err)),
            }
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
            *req.config_mut::<RequestRedirectPolicy>() = policy;
        }
        self
    }

    /// Sets if this request will announce that it accepts gzip encoding.
    #[cfg(feature = "gzip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gzip")))]
    pub fn gzip(mut self, gzip: bool) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            req.config_mut::<RequestAcceptEncoding>().gzip(gzip);
        }
        self
    }

    /// Sets if this request will announce that it accepts brotli encoding.
    #[cfg(feature = "brotli")]
    #[cfg_attr(docsrs, doc(cfg(feature = "brotli")))]
    pub fn brotli(mut self, brotli: bool) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            req.config_mut::<RequestAcceptEncoding>().brotli(brotli);
        }
        self
    }

    /// Sets if this request will announce that it accepts deflate encoding.
    #[cfg(feature = "deflate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
    pub fn deflate(mut self, deflate: bool) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            req.config_mut::<RequestAcceptEncoding>().deflate(deflate);
        }
        self
    }

    /// Sets if this request will announce that it accepts zstd encoding.
    #[cfg(feature = "zstd")]
    #[cfg_attr(docsrs, doc(cfg(feature = "zstd")))]
    pub fn zstd(mut self, zstd: bool) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            req.config_mut::<RequestAcceptEncoding>().zstd(zstd);
        }
        self
    }

    /// Set the proxy for this request.
    pub fn proxy(mut self, proxy: Proxy) -> RequestBuilder {
        if let Ok(ref mut req) = self.request {
            *req.config_mut::<RequestLayerOptions>().proxy_matcher_mut() =
                Some(proxy.into_matcher());
        }
        self
    }

    /// Set the local address for this request.
    pub fn local_address<V>(mut self, local_address: V) -> RequestBuilder
    where
        V: Into<Option<IpAddr>>,
    {
        if let Ok(ref mut req) = self.request {
            req.config_mut::<RequestLayerOptions>()
                .tcp_connect_opts_mut()
                .set_local_address(local_address.into());
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
            req.config_mut::<RequestLayerOptions>()
                .tcp_connect_opts_mut()
                .set_local_addresses(ipv4, ipv6);
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
            req.config_mut::<RequestLayerOptions>()
                .tcp_connect_opts_mut()
                .set_interface(interface);
        }
        self
    }

    /// Set the emulation for this request.
    pub fn emulation<P>(mut self, factory: P) -> RequestBuilder
    where
        P: EmulationFactory,
    {
        if let Ok(ref mut req) = self.request {
            let emulation = factory.emulation();
            let (transport_opts, default_headers, orig_headers) = emulation.into_parts();

            req.config_mut::<RequestLayerOptions>()
                .transport_opts_mut()
                .apply_transport_options(transport_opts);

            self = self.headers(default_headers).orig_headers(orig_headers);
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

    /// Constructs the Request and sends it to the target URI, returning a
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
    /// let response = wreq::Client::new().get("https://hyper.rs").send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send(self) -> impl Future<Output = crate::Result<Response>> {
        match self.request {
            Ok(req) => self.client.execute(req),
            Err(err) => Pending::error(err),
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
    /// let builder = client.post("http://httpbin.org/post").body("from a &str!");
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

/// Check the request URI for a "username:password" type authority, and if
/// found, remove it from the URI and return it.
fn extract_authority(uri: &mut Uri) -> Option<(String, Option<String>)> {
    use percent_encoding::percent_decode;

    let (username, password) = uri.userinfo();

    let username: String = percent_decode(username?.as_bytes())
        .decode_utf8()
        .ok()?
        .into();
    let password = password.and_then(|pass| {
        percent_decode(pass.as_bytes())
            .decode_utf8()
            .ok()
            .map(String::from)
    });

    if !username.is_empty() || password.is_some() {
        uri.set_userinfo("", None);
        return Some((username, password));
    }

    None
}

impl<T> From<HttpRequest<T>> for Request
where
    T: Into<Body>,
{
    fn from(req: HttpRequest<T>) -> Request {
        let (parts, body) = req.into_parts();
        let Parts {
            method,
            uri,
            headers,
            ..
        } = parts;
        Request {
            method,
            uri,
            headers,
            body: Some(body.into()),
            extensions: Extensions::new(),
        }
    }
}

impl From<Request> for HttpRequest<Body> {
    fn from(req: Request) -> HttpRequest<Body> {
        let Request {
            method,
            uri,
            headers,
            extensions,
            body,
            ..
        } = req;

        let mut req = HttpRequest::builder()
            .method(method)
            .uri(uri)
            .body(body.unwrap_or_else(Body::empty))
            .expect("valid request parts");
        *req.headers_mut() = headers;
        *req.extensions_mut() = extensions;
        req
    }
}
