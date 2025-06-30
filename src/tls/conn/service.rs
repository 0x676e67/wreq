use std::{
    error::Error,
    fmt::Debug,
    future::Future,
    net::Ipv6Addr,
    pin::Pin,
    task::{Context, Poll},
};

use http::{Uri, uri::Scheme};
use tokio_boring2::SslStream;
use tower_service::Service;

use super::{HttpsConnector, MaybeHttpsStream};
use crate::{
    core::{
        client::connect::Connection,
        rt::{Read, TokioIo, Write},
    },
    error::BoxError,
};

type BoxFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

impl<T, S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: Read + Write + Connection + Unpin + Debug + Sync + Send + 'static,
{
    type Response = MaybeHttpsStream<T>;
    type Error = BoxError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        // Early return if it is not a tls scheme
        if uri.scheme() != Some(&Scheme::HTTPS) {
            let connect = self.http.call(uri);
            return Box::pin(async move {
                connect
                    .await
                    .map(MaybeHttpsStream::Http)
                    .map_err(Into::into)
            });
        }

        let connect = self.http.call(uri.clone());
        let inner = self.inner.clone();

        let f = async move {
            let conn = connect.await.map_err(Into::into)?;

            let mut host = uri.host().ok_or("URI missing host")?;

            // If `host` is an IPv6 address, we must strip away the square brackets that surround
            // it (otherwise, boring will fail to parse the host as an IP address, eventually
            // causing the handshake to fail due a hostname verification error).
            if !host.is_empty() {
                let last = host.len() - 1;
                let mut chars = host.chars();

                if let (Some('['), Some(']')) = (chars.next(), chars.last()) {
                    if host[1..last].parse::<Ipv6Addr>().is_ok() {
                        host = &host[1..last];
                    }
                }
            }

            inner
                .connect(&uri, host, conn)
                .await
                .map(TokioIo::new)
                .map(MaybeHttpsStream::Https)
        };

        Box::pin(f)
    }
}

impl<T, S, IO> Service<(Uri, IO)> for HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send + Clone + 'static,
    S::Error: Into<BoxError>,
    S::Future: Unpin + Send + 'static,
    T: Read + Write + Connection + Unpin + Debug + Sync + Send + 'static,
    IO: Read + Write + Unpin + Send + Sync + Debug + 'static,
{
    type Response = SslStream<TokioIo<IO>>;
    type Error = Box<dyn Error + Sync + Send>;
    type Future = BoxFuture<Self::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, (uri, stream): (Uri, IO)) -> Self::Future {
        let inner = self.inner.clone();
        let fut = async move {
            let host = uri.host().ok_or("URI missing host")?;
            inner.connect(&uri, host, stream).await
        };

        Box::pin(fut)
    }
}
