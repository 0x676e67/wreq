//! Middleware for retrying requests.

use futures_util::future;
use http::{Request, Response};
use tower::retry::Policy;
#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
))]
use tower_http::decompression::DecompressionBody;

use super::timeout::TimeoutBody;
use crate::{Body, core::body::Incoming, error::BoxError};

/// A retry policy for HTTP/2 requests that safely determines whether and how many times
/// a request should be retried based on error type and a maximum retry count.
///
/// This policy helps avoid unsafe or infinite retries by tracking the number of attempts
/// and only retrying errors that are considered safe to repeat (such as connection-level errors).
#[derive(Clone)]
pub struct Http2RetryPolicy(usize);

impl Http2RetryPolicy {
    /// Create a new `Http2RetryPolicy` policy with the specified number of attempts.
    #[inline]
    pub const fn new(attempts: usize) -> Self {
        Self(attempts)
    }

    /// Determines whether the given error is considered retryable for HTTP/2 requests.
    ///
    /// Returns `true` if the error type or content indicates that the request can be retried,
    /// otherwise returns `false`.
    fn is_retryable_error(&self, err: &(dyn std::error::Error + 'static)) -> bool {
        let err = if let Some(err) = err.source() {
            err
        } else {
            return false;
        };

        if let Some(cause) = err.source() {
            if let Some(err) = cause.downcast_ref::<http2::Error>() {
                // They sent us a graceful shutdown, try with a new connection!
                if err.is_go_away()
                    && err.is_remote()
                    && err.reason() == Some(http2::Reason::NO_ERROR)
                {
                    return true;
                }

                // REFUSED_STREAM was sent from the server, which is safe to retry.
                // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.7-3.2
                if err.is_reset()
                    && err.is_remote()
                    && err.reason() == Some(http2::Reason::REFUSED_STREAM)
                {
                    return true;
                }
            }
        }
        false
    }
}

type Req = Request<Body>;
#[cfg(not(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
)))]
type Res = Response<TimeoutBody<Incoming>>;
#[cfg(any(
    feature = "gzip",
    feature = "zstd",
    feature = "brotli",
    feature = "deflate",
))]
type Res = Response<TimeoutBody<DecompressionBody<Incoming>>>;

impl Policy<Req, Res, BoxError> for Http2RetryPolicy {
    type Future = future::Ready<()>;

    fn retry(
        &mut self,
        _req: &mut Req,
        result: &mut Result<Res, BoxError>,
    ) -> Option<Self::Future> {
        if let Err(err) = result {
            if !self.is_retryable_error(err.as_ref()) {
                return None;
            }

            // Treat all errors as failures...
            // But we limit the number of attempts...
            return if self.0 > 0 {
                trace!("Retrying HTTP/2 request, attempts left: {}", self.0);
                // Try again!
                self.0 -= 1;
                Some(future::ready(()))
            } else {
                // Used all our attempts, no retry...
                None
            };
        }

        None
    }

    fn clone_request(&mut self, req: &Req) -> Option<Req> {
        let mut new_req = Request::builder()
            .method(req.method().clone())
            .uri(req.uri().clone())
            .version(req.version())
            .body(req.body().try_clone()?)
            .ok()?;

        *new_req.headers_mut() = req.headers().clone();
        *new_req.extensions_mut() = req.extensions().clone();

        Some(new_req)
    }
}
