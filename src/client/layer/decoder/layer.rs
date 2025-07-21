use std::task::{Context, Poll};

use http::{Request, Response};
use http_body::Body;
use tower::{Layer, Service};
use tower_http::decompression::{self, DecompressionBody, ResponseFuture};

use super::AcceptEncoding;
use crate::{client::layer::config::RequestAcceptEncoding, core::ext::RequestConfig};

/// Decompresses response bodies of the underlying service.
///
/// This adds the `Accept-Encoding` header to requests and transparently decompresses response
/// bodies based on the `Content-Encoding` header.
#[derive(Clone)]
pub struct DecompressionLayer {
    accept: AcceptEncoding,
}

impl DecompressionLayer {
    /// Creates a new `DecompressionLayer` with the specified `AcceptEncoding`.
    pub const fn new(accept: AcceptEncoding) -> Self {
        Self { accept }
    }
}

impl<S> Layer<S> for DecompressionLayer {
    type Service = Decompression<S>;

    fn layer(&self, service: S) -> Self::Service {
        let decoder = decompression::Decompression::new(service);
        let decoder = Decompression::<S>::accept_in_place(decoder, &self.accept);
        Decompression {
            decoder: Some(decoder),
        }
    }
}

/// Decompresses response bodies of the underlying service.
///
/// This adds the `Accept-Encoding` header to requests and transparently decompresses response
/// bodies based on the `Content-Encoding` header.
#[derive(Clone)]
pub struct Decompression<S> {
    decoder: Option<decompression::Decompression<S>>,
}

impl<S> Decompression<S> {
    // replaces the current decoder with a new one based on the `AcceptEncoding`.
    fn accept_in_place(
        mut decoder: decompression::Decompression<S>,
        accept: &AcceptEncoding,
    ) -> decompression::Decompression<S> {
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
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone,
    ReqBody: Body,
    ResBody: Body,
{
    type Response = Response<DecompressionBody<ResBody>>;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.decoder.as_mut() {
            Some(decoder) => decoder.poll_ready(cx),
            None => unreachable!("Decompression service is not initialized"),
        }
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // If the accept encoding is set, we need to update the decoder
        // to handle the specified encodings.
        if let Some(accept) = RequestConfig::<RequestAcceptEncoding>::get(req.extensions()) {
            if let Some(mut decoder) = self.decoder.take() {
                decoder = Decompression::accept_in_place(decoder, accept);
                self.decoder = Some(decoder);
            }
        }

        // Call the underlying service with the request
        match self.decoder.as_mut() {
            Some(decoder) => decoder.call(req),
            None => {
                // This branch should never be reached: decoder is always initialized in
                // DecompressionLayer::layer(). If this panic occurs, it indicates a
                // bug in the service setup or unexpected internal state.
                unreachable!(
                    "Decompression service was not initialized; this indicates a bug in service setup"
                );
            }
        }
    }
}
