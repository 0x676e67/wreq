use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::{Uri, uri::Scheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_boring2::SslStream;
use tower::Service;

use super::{EstablishedConn, HttpsConnector, MaybeHttpsStream};
use crate::{
    client::{ConnectRequest, Connection},
    error::BoxError,
    ext::UriExt,
};

type BoxFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

async fn perform_handshake<T>(
    ssl: boring2::ssl::Ssl,
    conn: T,
) -> Result<MaybeHttpsStream<T>, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = SslStream::new(ssl, conn)?;
    Pin::new(&mut stream).connect().await?;
    Ok(MaybeHttpsStream::Https(stream))
}

impl<T, S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
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
            let conn = connect.await.map_err(Into::into)?;

            // Early return if it is not a tls scheme
            if uri.scheme() != Some(&Scheme::HTTPS) {
                return Ok(MaybeHttpsStream::Http(conn));
            }

            let ssl = inner.setup_ssl(uri)?;
            perform_handshake(ssl, conn).await
        };

        Box::pin(f)
    }
}

impl<T, S> Service<ConnectRequest> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
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

    fn call(&mut self, req: ConnectRequest) -> Self::Future {
        let uri = req.uri().clone();
        let connect = self.http.call(uri.clone());
        let inner = self.inner.clone();

        let f = async move {
            let conn = connect.await.map_err(Into::into)?;

            // Early return if it is not a tls scheme
            if uri.is_http() {
                return Ok(MaybeHttpsStream::Http(conn));
            }

            let ssl = inner.setup_ssl2(req)?;
            perform_handshake(ssl, conn).await
        };

        Box::pin(f)
    }
}

impl<T, S, IO> Service<EstablishedConn<IO>> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send + Clone + 'static,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug + 'static,
{
    type Response = MaybeHttpsStream<IO>;
    type Error = BoxError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, conn: EstablishedConn<IO>) -> Self::Future {
        let inner = self.inner.clone();
        let fut = async move {
            // Early return if it is not a tls scheme
            if conn.req.uri().is_http() {
                return Ok(MaybeHttpsStream::Http(conn.io));
            }

            let ssl = inner.setup_ssl2(conn.req)?;
            perform_handshake(ssl, conn.io).await
        };

        Box::pin(fut)
    }
}
