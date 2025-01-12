#![allow(missing_debug_implementations)]

use super::NetworkScheme;
use crate::{error::BoxError, AlpnProtos};
use http::{
    header::CONTENT_LENGTH, request::Builder, Error, HeaderMap, HeaderName, HeaderValue, Method,
    Request, Uri, Version,
};
use http_body::Body;
use std::marker::PhantomData;

pub struct InnerRequest<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    request: Request<B>,
    alpn_protos: Option<AlpnProtos>,
    network_scheme: NetworkScheme,
}

impl<B> InnerRequest<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    pub fn builder<'a>() -> InnerRequestBuilder<'a, B> {
        InnerRequestBuilder {
            builder: Request::builder(),
            alpn_protos: None,
            network_scheme: Default::default(),
            headers_order: None,
            _body: PhantomData,
        }
    }

    pub fn pieces(self) -> (Request<B>, NetworkScheme, Option<AlpnProtos>) {
        (self.request, self.network_scheme, self.alpn_protos)
    }
}

/// A builder for constructing HTTP requests.
pub struct InnerRequestBuilder<'a, B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    builder: Builder,
    alpn_protos: Option<AlpnProtos>,
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
    /// Set the method for the request.
    #[inline]
    pub fn method(mut self, method: Method) -> Self {
        self.builder = self.builder.method(method);
        self
    }

    /// Set the URI for the request.
    #[inline]
    pub fn uri(mut self, uri: Uri) -> Self {
        self.builder = self.builder.uri(uri);
        self
    }

    /// Set the version for the request.
    #[inline]
    pub fn version(mut self, version: Option<Version>) -> Self {
        if let Some(version) = version {
            self.builder = self.builder.version(version);
            self.alpn_protos = map_alpn_protos(version);
        }
        self
    }

    /// Set the headers for the request.
    #[inline]
    pub fn headers(mut self, mut headers: HeaderMap) -> Self {
        if let Some(h) = self.builder.headers_mut() {
            std::mem::swap(h, &mut headers)
        }
        self
    }

    /// Set the headers order for the request.
    #[inline]
    pub fn headers_order(mut self, order: Option<&'a [HeaderName]>) -> Self {
        self.headers_order = order;
        self
    }

    /// Set network scheme for the request.
    #[inline]
    pub fn network_scheme(mut self, network_scheme: NetworkScheme) -> Self {
        self.network_scheme = network_scheme;
        self
    }

    /// Set the body for the request.
    #[inline]
    pub fn body(mut self, body: B) -> Result<InnerRequest<B>, Error> {
        if let Some((order, headers)) = self.headers_order.zip(self.builder.headers_mut()) {
            add_content_length_header(headers, &body);
            sort_headers(headers, order);
        }

        self.builder.body(body).map(|request| InnerRequest {
            request,
            alpn_protos: self.alpn_protos,
            network_scheme: self.network_scheme,
        })
    }
}

fn map_alpn_protos(version: Version) -> Option<AlpnProtos> {
    match version {
        Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => Some(AlpnProtos::Http1),
        Version::HTTP_2 => Some(AlpnProtos::Http2),
        _ => None,
    }
}

/// Add the `Content-Length` header to the request.
#[inline]
fn add_content_length_header<B>(headers: &mut HeaderMap, body: &B)
where
    B: Body,
{
    if let Some(len) = Body::size_hint(body).exact() {
        headers
            .entry(CONTENT_LENGTH)
            .or_insert_with(|| HeaderValue::from(len));
    }
}

/// Sort the headers in the specified order.
///
/// Headers in `headers_order` are sorted to the front, preserving their order.
/// Remaining headers are appended in their original order.
#[inline]
fn sort_headers(headers: &mut HeaderMap, headers_order: &[HeaderName]) {
    if headers.len() <= 1 {
        return;
    }

    let mut sorted_headers = HeaderMap::with_capacity(headers.keys_len());

    // First insert headers in the specified order
    for (key, value) in headers_order
        .iter()
        .filter_map(|key| headers.remove(key).map(|value| (key, value)))
    {
        sorted_headers.insert(key, value);
    }

    // Then insert any remaining headers that were not ordered
    for (key, value) in headers.drain().filter_map(|(k, v)| k.map(|k| (k, v))) {
        sorted_headers.insert(key, value);
    }

    std::mem::swap(headers, &mut sorted_headers);
}
