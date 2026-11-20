//! Middleware for decoding

use std::task::{Context, Poll};

use futures_util::{TryFutureExt, future::MapOk};
use http::{
    HeaderValue, Request, Response, StatusCode,
    header::{ACCEPT_ENCODING, CONTENT_ENCODING, Entry, RANGE},
};
use http_body::Body;
use tower::{Layer, Service};
use tower_http::decompression::{self, DecompressionBody, ResponseFuture};

use crate::config::RequestConfig;

/// Configuration for supported content-encoding algorithms.
///
/// `AcceptEncoding` controls which compression formats are enabled for decoding
/// response bodies. Each field corresponds to a specific algorithm and is only
/// available if the corresponding feature is enabled.
#[derive(Clone)]
pub(crate) struct AcceptEncoding {
    #[cfg(feature = "gzip")]
    pub(crate) gzip: bool,
    #[cfg(feature = "brotli")]
    pub(crate) brotli: bool,
    #[cfg(feature = "zstd")]
    pub(crate) zstd: bool,
    #[cfg(feature = "deflate")]
    pub(crate) deflate: bool,
}

/// Builds response decompression middleware for a client service.
///
/// `DecompressionLayer` stores the client's default [`AcceptEncoding`] configuration
/// and applies it when constructing a [`Decompression`] service.
#[derive(Clone)]
pub struct DecompressionLayer {
    accept: AcceptEncoding,
}

/// Negotiates response encodings and transparently decodes response bodies.
///
/// Before forwarding a request, `Decompression` applies request-specific
/// [`AcceptEncoding`] settings and defaults range requests to identity encoding. The wrapped
/// `tower-http` service decodes matching responses except for partial content.
#[derive(Clone)]
pub struct Decompression<S> {
    decoder: Option<decompression::Decompression<PreservePartialContent<S>>>,
    enabled: bool,
}

/// Keeps encoded partial responses out of the wrapped decompressor.
#[derive(Clone)]
struct PreservePartialContent<S>(S);

/// Encoding header values held while tower-http wraps a partial response body.
#[derive(Clone)]
struct PartialContentEncoding(Vec<HeaderValue>);

type MapResponse<F, B> = MapOk<F, fn(Response<B>) -> Response<B>>;

// ===== AcceptEncoding =====

impl Default for AcceptEncoding {
    fn default() -> AcceptEncoding {
        AcceptEncoding {
            #[cfg(feature = "gzip")]
            gzip: true,
            #[cfg(feature = "brotli")]
            brotli: true,
            #[cfg(feature = "zstd")]
            zstd: true,
            #[cfg(feature = "deflate")]
            deflate: true,
        }
    }
}

impl AcceptEncoding {
    fn is_enabled(&self) -> bool {
        #[cfg(feature = "gzip")]
        if self.gzip {
            return true;
        }

        #[cfg(feature = "deflate")]
        if self.deflate {
            return true;
        }

        #[cfg(feature = "brotli")]
        if self.brotli {
            return true;
        }

        #[cfg(feature = "zstd")]
        if self.zstd {
            return true;
        }

        false
    }
}

impl_request_config_value!(AcceptEncoding);

// ===== impl DecompressionLayer =====

impl DecompressionLayer {
    /// Creates a new [`DecompressionLayer`] with the specified [`AcceptEncoding`].
    #[inline(always)]
    pub fn new(accept: AcceptEncoding) -> Self {
        Self { accept }
    }
}

impl<S> Layer<S> for DecompressionLayer {
    type Service = Decompression<S>;

    #[inline(always)]
    fn layer(&self, service: S) -> Self::Service {
        let decoder = decompression::Decompression::new(PreservePartialContent(service))
            .no_br()
            .no_deflate()
            .no_gzip()
            .no_zstd();
        Decompression {
            decoder: Some(Decompression::<S>::accept_in_place(decoder, &self.accept)),
            enabled: self.accept.is_enabled(),
        }
    }
}

// ===== impl Decompression =====

impl<S> Decompression<S> {
    const BUG_MSG: &str = "[BUG] Decompression service not initialized; bug in setup";

    fn accept_in_place(
        mut decoder: decompression::Decompression<PreservePartialContent<S>>,
        accept: &AcceptEncoding,
    ) -> decompression::Decompression<PreservePartialContent<S>> {
        #[cfg(feature = "gzip")]
        {
            decoder = decoder.gzip(accept.gzip);
        }

        #[cfg(feature = "deflate")]
        {
            decoder = decoder.deflate(accept.deflate);
        }

        #[cfg(feature = "brotli")]
        {
            decoder = decoder.br(accept.brotli);
        }

        #[cfg(feature = "zstd")]
        {
            decoder = decoder.zstd(accept.zstd);
        }

        decoder
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for Decompression<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Body,
    ResBody: Body,
{
    type Response = Response<DecompressionBody<ResBody>>;
    type Error = S::Error;
    type Future =
        MapResponse<ResponseFuture<MapResponse<S::Future, ResBody>>, DecompressionBody<ResBody>>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.decoder.as_mut().expect(Self::BUG_MSG).poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let enabled =
            if let Some(accept_encoding) = RequestConfig::<AcceptEncoding>::get(req.extensions()) {
                if let Some(decoder) = self.decoder.take() {
                    self.decoder
                        .replace(Decompression::accept_in_place(decoder, accept_encoding));
                }
                debug_assert!(self.decoder.is_some());
                accept_encoding.is_enabled()
            } else {
                self.enabled
            };

        if enabled && req.headers().contains_key(RANGE) {
            // tower-http does not account for Range when adding Accept-Encoding, so correct it
            // before delegating. RFC 9110 section 14.1.2 applies byte ranges to the encoded
            // representation, and Fetch avoids partial codings by requesting identity:
            // https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.2
            // https://fetch.spec.whatwg.org/#http-network-or-cache-fetch
            req.headers_mut()
                .entry(ACCEPT_ENCODING)
                .or_insert(HeaderValue::from_static("identity"));
        }

        self.decoder
            .as_mut()
            .expect(Self::BUG_MSG)
            .call(req)
            .map_ok(restore_partial_content_encoding::<DecompressionBody<ResBody>> as fn(_) -> _)
    }
}

// ===== impl PreservePartialContent =====

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for PreservePartialContent<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = MapResponse<S::Future, ResBody>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        self.0
            .call(req)
            .map_ok(hide_partial_content_encoding::<ResBody> as fn(_) -> _)
    }
}

fn hide_partial_content_encoding<B>(mut response: Response<B>) -> Response<B> {
    // Byte ranges refer to the encoded representation (RFC 9110 section 14.1.2).
    // tower-http decodes based on Content-Encoding alone, so hide it for 206 responses.
    if response.status() == StatusCode::PARTIAL_CONTENT
        && let Entry::Occupied(entry) = response.headers_mut().entry(CONTENT_ENCODING)
    {
        let (_, values) = entry.remove_entry_mult();
        let encoding = PartialContentEncoding(values.collect());
        response.extensions_mut().insert(encoding);
    }
    response
}

fn restore_partial_content_encoding<B>(mut response: Response<B>) -> Response<B> {
    if response.status() == StatusCode::PARTIAL_CONTENT
        && let Some(encoding) = response.extensions_mut().remove::<PartialContentEncoding>()
    {
        for value in encoding.0 {
            response.headers_mut().append(CONTENT_ENCODING, value);
        }
    }
    response
}
