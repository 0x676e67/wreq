use std::task::{Context, Poll};

use http::{Request, Response};
use http_body::Body;
use tower::Layer;
use tower_http::decompression::{DecompressionBody, ResponseFuture};
use tower_service::Service;

use crate::{client::decoder::Accepts, config::RequestAcceptsEncoding, core::ext::RequestConfig};

/// Decompresses response bodies of the underlying service.
///
/// This adds the `Accept-Encoding` header to requests and transparently decompresses response
/// bodies based on the `Content-Encoding` header.
#[derive(Clone)]
pub struct DecompressionLayer {
    accept: Accepts,
}

impl DecompressionLayer {
    /// Creates a new `DecompressionLayer` with the specified `Accepts`.
    pub const fn new(accept: Accepts) -> Self {
        Self { accept }
    }
}

impl<S> Layer<S> for DecompressionLayer {
    type Service = Decompression<S>;

    fn layer(&self, service: S) -> Self::Service {
        Decompression::new(service, self.accept.clone())
    }
}

/// Decompresses response bodies of the underlying service.
///
/// This adds the `Accept-Encoding` header to requests and transparently decompresses response
/// bodies based on the `Content-Encoding` header.
#[derive(Clone)]
pub struct Decompression<S>(tower_http::decompression::Decompression<S>);

impl<S> Decompression<S> {
    /// Creates a new `Decompression` wrapping the `service`.
    pub fn new(service: S, accepts: Accepts) -> Self {
        let mut service = tower_http::decompression::Decompression::new(service);
        #[cfg(feature = "gzip")]
        {
            service = service.gzip(accepts.gzip);
        }

        #[cfg(feature = "deflate")]
        {
            service = service.deflate(accepts.deflate);
        }

        #[cfg(feature = "brotli")]
        {
            service = service.br(accepts.brotli);
        }

        #[cfg(feature = "zstd")]
        {
            service = service.zstd(accepts.zstd);
        }

        Self(service)
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
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        if let Some(accpets) = RequestConfig::<RequestAcceptsEncoding>::get(req.extensions()) {
            let mut inner = self.0.clone();
            #[cfg(feature = "gzip")]
            {
                inner = inner.gzip(accpets.gzip);
            }

            #[cfg(feature = "deflate")]
            {
                inner = inner.deflate(accpets.deflate);
            }
            #[cfg(feature = "brotli")]
            {
                inner = inner.br(accpets.brotli);
            }

            #[cfg(feature = "zstd")]
            {
                inner = inner.zstd(accpets.zstd);
            }
            self.0 = inner;
        }

        self.0.call(req)
    }
}
