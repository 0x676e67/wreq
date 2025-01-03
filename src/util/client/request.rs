#![allow(missing_debug_implementations)]

use std::marker::PhantomData;

use super::NetworkScheme;
use crate::{error::BoxError, HttpVersionPref};
use http::{
    header::CONTENT_LENGTH, request::Builder, HeaderMap, HeaderName, HeaderValue, Method, Request,
    Uri, Version,
};
use http_body::Body;

pub struct InnerRequest<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    request: Request<B>,
    version_pref: Option<HttpVersionPref>,
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
            version_pref: None,
            network_scheme: Default::default(),
            headers_order: None,
            _body: PhantomData,
        }
    }

    pub fn pieces(self) -> (Request<B>, NetworkScheme, Option<HttpVersionPref>) {
        (self.request, self.network_scheme, self.version_pref)
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
    version_pref: Option<HttpVersionPref>,
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
    pub fn version(mut self, version: impl Into<Option<Version>>) -> Self {
        if let Some(version) = version.into() {
            self.builder = self.builder.version(version);
            self.version_pref = Some(map_version_to_pref(version));
        }
        self
    }

    /// Set the headers for the request.
    #[inline]
    pub fn headers(mut self, mut headers: HeaderMap) -> Self {
        if let Some(h) = self.builder.headers_mut() {
            std::mem::swap(h, &mut headers);
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
    pub fn network_scheme(mut self, network_scheme: impl Into<NetworkScheme>) -> Self {
        self.network_scheme = network_scheme.into();
        self
    }

    /// Set the body for the request.
    #[inline]
    pub fn body(mut self, body: B) -> InnerRequest<B> {
        if let Some(order) = self.headers_order {
            if let Some(headers) = self.builder.headers_mut() {
                add_content_length_header(&body, headers);
                crate::util::sort_headers(headers, order);
            }
        }

        InnerRequest {
            request: self.builder.body(body).expect("failed to build request"),
            version_pref: self.version_pref,
            network_scheme: self.network_scheme,
        }
    }
}

fn map_version_to_pref(version: Version) -> HttpVersionPref {
    match version {
        Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => HttpVersionPref::Http1,
        Version::HTTP_2 => HttpVersionPref::Http2,
        _ => HttpVersionPref::default(),
    }
}

fn add_content_length_header<B>(body: &B, headers: &mut HeaderMap)
where
    B: Body,
{
    if let Some(len) = http_body::Body::size_hint(body).exact() {
        headers
            .entry(CONTENT_LENGTH)
            .or_insert_with(|| HeaderValue::from(len));
    }
}
