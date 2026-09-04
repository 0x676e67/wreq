//! Request-local connection and protocol configuration.

use std::task::{Context, Poll};

use futures_util::future::{self, Either, Ready};
use http::{Request, Uri, uri::PathAndQuery};
use tower::{BoxError, Layer, Service, layer::layer_fn};
use wreq_proto::conn;

use super::ConfiguredRequest;
use crate::{
    client::{error, layer::config::RequestOptions},
    config::RequestConfig,
    conn::descriptor::ConnectionDescriptor,
    rt::Executor,
};

/// Creates the request-configuration layer used before internal retries.
///
/// The returned layer owns the base HTTP/1 and HTTP/2 builders. Each service
/// built from it receives a clone of both builders, while request-local protocol
/// options are applied later by [`Configure::call`]. This keeps handshake
/// configuration attached to the request that creates a connection without
/// rebuilding the outer client service stack.
///
/// The layer transforms `Request<B>` into [`ConfiguredRequest<B>`], so it must
/// remain outside the retry and dispatch services in the low-level stack.
pub fn layer<S>(
    h1_builder: conn::http1::Builder,
    h2_builder: conn::http2::Builder<Executor>,
) -> impl Layer<S, Service = Configure<S>> + Clone {
    layer_fn(move |inner| Configure::new(inner, h1_builder.clone(), h2_builder.clone()))
}

/// Applies request-local connection and protocol configuration.
///
/// This is the first service in the low-level client stack. It strips the URI
/// to a connection origin, consumes private request options, and forwards a
/// [`ConfiguredRequest`] while leaving the request body untouched.
#[derive(Clone)]
pub struct Configure<S> {
    inner: S,
    h1_builder: conn::http1::Builder,
    h2_builder: conn::http2::Builder<Executor>,
}

impl<S> Configure<S> {
    /// Wraps a pool request service with request-local configuration handling.
    fn new(
        inner: S,
        h1_builder: conn::http1::Builder,
        h2_builder: conn::http2::Builder<Executor>,
    ) -> Self {
        Self {
            inner,
            h1_builder,
            h2_builder,
        }
    }
}

impl<S, B> Service<Request<B>> for Configure<S>
where
    S: Service<ConfiguredRequest<B>, Error = BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let uri = match connection_origin(request.uri()) {
            Ok(uri) => uri,
            Err(error) => return Either::Right(future::err(error.into())),
        };

        let RequestOptions {
            group,
            proxy,
            version,
            tls_options,
            http1_options,
            http2_options,
            socket_bind_options,
        } = RequestConfig::<RequestOptions>::remove(request.extensions_mut()).unwrap_or_default();

        let h1_builder = http1_options
            .map(|options| self.h1_builder.clone().options(options))
            .unwrap_or_else(|| self.h1_builder.clone());
        let h2_builder = http2_options
            .map(|options| self.h2_builder.clone().options(options))
            .unwrap_or_else(|| self.h2_builder.clone());
        let descriptor =
            ConnectionDescriptor::new(uri, group, proxy, version, tls_options, socket_bind_options);

        Either::Left(self.inner.call(ConfiguredRequest {
            request,
            descriptor,
            h1_builder,
            h2_builder,
        }))
    }
}

/// Builds the origin URI used to select and configure a connection.
///
/// The scheme and authority are preserved while the path and query are replaced
/// with `/`. The request URI itself remains unchanged so protocol encoding still
/// receives the original request target.
///
/// # Errors
///
/// Returns an error when the origin URI cannot be reconstructed from the
/// normalized request URI.
fn connection_origin(uri: &Uri) -> Result<Uri, error::Error> {
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(PathAndQuery::from_static("/"));
    Uri::from_parts(parts)
        .map_err(|source| error::Error::new(error::ErrorKind::UserAbsoluteUriRequired, source))
}
