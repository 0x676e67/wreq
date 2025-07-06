use std::{
    error::Error,
    fmt::Debug,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::{Uri, uri::Scheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_boring2::{SslStream, SslStreamBuilder};
use tower_service::Service;

use super::{EstablishedConn, HttpsConnector, MaybeHttpsStream};
use crate::{
    core::{
        client::{ConnRequest, connect::Connection},
        rt::TokioIo,
    },
    error::BoxError,
};

type BoxFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

impl<T, S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri, Response = TokioIo<T>> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
{
    type Response = MaybeHttpsStream<T>;
    type Error = BoxError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connect = self.http.call(uri.clone());
        let inner = self.inner.clone();

        let f = async move {
            let conn = connect.await.map_err(Into::into)?.into_inner();

            // Early return if it is not a tls scheme
            if uri.scheme() != Some(&Scheme::HTTPS) {
                return Ok(MaybeHttpsStream::Http(conn));
            }

            let ssl = inner.setup_ssl(uri)?;
            let stream = SslStreamBuilder::new(ssl, conn)
                .connect()
                .await
                .map(MaybeHttpsStream::Https)?;

            Ok(stream)
        };

        Box::pin(f)
    }
}

impl<T, S> Service<ConnRequest> for HttpsConnector<S>
where
    S: Service<Uri, Response = TokioIo<T>> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
{
    type Response = MaybeHttpsStream<T>;
    type Error = BoxError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: ConnRequest) -> Self::Future {
        let uri = req.uri().clone();
        let connect = self.http.call(uri.clone());
        let inner = self.inner.clone();

        let f = async move {
            let conn = connect.await.map_err(Into::into)?.into_inner();

            // Early return if it is not a tls scheme
            if uri.scheme() != Some(&Scheme::HTTPS) {
                return Ok(MaybeHttpsStream::Http(conn));
            }

            let ssl = inner.setup_ssl2(req)?;
            let stream = SslStreamBuilder::new(ssl, conn)
                .connect()
                .await
                .map(MaybeHttpsStream::Https)?;

            Ok(stream)
        };

        Box::pin(f)
    }
}

impl<T, S, IO> Service<EstablishedConn<IO>> for HttpsConnector<S>
where
    S: Service<Uri, Response = TokioIo<T>> + Send + Clone + 'static,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug + 'static,
{
    type Response = SslStream<IO>;
    type Error = Box<dyn Error + Sync + Send>;
    type Future = BoxFuture<Self::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, conn: EstablishedConn<IO>) -> Self::Future {
        let inner = self.inner.clone();
        let fut = async move {
            let ssl = inner.setup_ssl2(conn.req)?;
            let stream = SslStreamBuilder::new(ssl, conn.inner.into_inner())
                .connect()
                .await?;

            Ok(stream)
        };

        Box::pin(fut)
    }
}
