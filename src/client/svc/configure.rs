//! Request-local connection and protocol configuration.

use std::{
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::{self, Either, Ready};
use http::{Request, Uri, uri::PathAndQuery};
use tower::{BoxError, Layer, Service, layer::layer_fn};
use wreq_proto::conn;

use super::ConfiguredRequest;
use crate::{
    client::{error, layer::config::RequestOptions, pool::ConnectionConfig},
    config::RequestConfig,
    conn::descriptor::ConnectionDescriptor,
    rt::Executor,
};

/// Creates the request-configuration layer used before internal retries.
///
/// Services share the base HTTP/1 and HTTP/2 builders. Request-local options
/// are applied only when a new transport is established, so pool hits do not
/// copy handshake configuration or rebuild the client service stack.
///
/// The layer transforms `Request<B>` into [`ConfiguredRequest<B>`], so it must
/// remain outside the retry and dispatch services in the low-level stack.
pub fn layer<S>(
    h1_builder: conn::http1::Builder,
    h2_builder: conn::http2::Builder<Executor>,
) -> impl Layer<S, Service = Configure<S>> + Clone {
    let h1_builder = Arc::new(h1_builder);
    let h2_builder = Arc::new(h2_builder);
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
    h1_builder: Arc<conn::http1::Builder>,
    h2_builder: Arc<conn::http2::Builder<Executor>>,
}

impl<S> Configure<S> {
    /// Wraps a pool request service with request-local configuration handling.
    fn new(
        inner: S,
        h1_builder: Arc<conn::http1::Builder>,
        h2_builder: Arc<conn::http2::Builder<Executor>>,
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
        // Select connections by origin without changing the request's wire target.
        let mut parts = request.uri().clone().into_parts();
        parts.path_and_query = Some(PathAndQuery::from_static("/"));
        let uri = match Uri::from_parts(parts) {
            Ok(uri) => uri,
            Err(source) => {
                return Either::Right(future::err(
                    error::Error::new(error::ErrorKind::UserAbsoluteUriRequired, source).into(),
                ));
            }
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

        let descriptor =
            ConnectionDescriptor::new(uri, group, proxy, version, tls_options, socket_bind_options);

        Either::Left(self.inner.call(ConfiguredRequest {
            request,
            connection: Arc::new(ConnectionConfig {
                descriptor,
                h1_builder: self.h1_builder.clone(),
                h2_builder: self.h2_builder.clone(),
                http1_options,
                http2_options,
            }),
        }))
    }
}
