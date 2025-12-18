use std::{
    io,
    marker::{PhantomData, Unpin},
    pin::Pin,
    task::{self, Poll, ready},
};

use http::{HeaderMap, HeaderValue, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower::Service;

use super::Tunneling;
use crate::{error::BoxError, ext::UriExt};

/// Tunnel Proxy via HTTP CONNECT
///
/// This is a connector that can be used by the `Client`. It wraps
/// another connector, and after getting an underlying connection, it creates
/// an HTTP CONNECT tunnel over it.
#[derive(Debug)]
pub struct TunnelConnector<C> {
    headers: Headers,
    inner: C,
    proxy_dst: Uri,
}

#[derive(Clone, Debug)]
enum Headers {
    Empty,
    Auth(HeaderValue),
    Extra(HeaderMap),
}

#[derive(Debug)]
pub enum TunnelError {
    ConnectFailed(BoxError),
    Io(std::io::Error),
    MissingHost,
    ProxyAuthRequired,
    ProxyHeadersTooLong,
    TunnelUnexpectedEof,
    TunnelUnsuccessful,
}

impl<C> TunnelConnector<C> {
    /// Create a new tunnel connector.
    ///
    /// This wraps an underlying connector, and stores the address of a
    /// tunneling proxy server.
    ///
    /// A `TunnelConnector` can then be called with any destination. The `proxy_dst` passed to
    /// `call` will not be used to create the underlying connection, but will
    /// be used in an HTTP CONNECT request sent to the proxy destination.
    pub fn new(proxy_dst: Uri, connector: C) -> Self {
        Self {
            headers: Headers::Empty,
            inner: connector,
            proxy_dst,
        }
    }

    /// Add `proxy-authorization` header value to the CONNECT request.
    pub fn with_auth(mut self, mut auth: HeaderValue) -> Self {
        // just in case the user forgot
        auth.set_sensitive(true);
        match self.headers {
            Headers::Empty => {
                self.headers = Headers::Auth(auth);
            }
            Headers::Auth(ref mut existing) => {
                *existing = auth;
            }
            Headers::Extra(ref mut extra) => {
                extra.insert(http::header::PROXY_AUTHORIZATION, auth);
            }
        }

        self
    }

    /// Add extra headers to be sent with the CONNECT request.
    ///
    /// If existing headers have been set, these will be merged.
    pub fn with_headers(mut self, mut headers: HeaderMap) -> Self {
        match self.headers {
            Headers::Empty => {
                self.headers = Headers::Extra(headers);
            }
            Headers::Auth(auth) => {
                headers
                    .entry(http::header::PROXY_AUTHORIZATION)
                    .or_insert(auth);
                self.headers = Headers::Extra(headers);
            }
            Headers::Extra(ref mut extra) => {
                extra.extend(headers);
            }
        }

        self
    }
}

impl<C> Service<Uri> for TunnelConnector<C>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
{
    type Response = C::Response;
    type Error = TunnelError;
    type Future = Tunneling<C::Future, C::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(Into::into)
            .map_err(TunnelError::ConnectFailed)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let connecting = self.inner.call(self.proxy_dst.clone());
        let headers = self.headers.clone();

        Tunneling {
            fut: Box::pin(async move {
                let conn = connecting
                    .await
                    .map_err(Into::into)
                    .map_err(TunnelError::ConnectFailed)?;
                tunnel(
                    conn,
                    dst.host().ok_or(TunnelError::MissingHost)?,
                    dst.port_or_default(),
                    &headers,
                )
                .await
            }),
            _marker: PhantomData,
        }
    }
}

async fn tunnel<T>(mut conn: T, host: &str, port: u16, headers: &Headers) -> Result<T, TunnelError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = format!(
        "\
         CONNECT {host}:{port} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         "
    )
    .into_bytes();

    match headers {
        Headers::Auth(auth) => {
            buf.extend_from_slice(b"Proxy-Authorization: ");
            buf.extend_from_slice(auth.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        Headers::Extra(extra) => {
            for (name, value) in extra {
                buf.extend_from_slice(name.as_str().as_bytes());
                buf.extend_from_slice(b": ");
                buf.extend_from_slice(value.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
        }
        Headers::Empty => (),
    }

    // headers end
    buf.extend_from_slice(b"\r\n");

    write_all(&mut conn, &buf).await.map_err(TunnelError::Io)?;

    let mut buf = [0; 8192];
    let mut pos = 0;

    loop {
        let n = read(&mut conn, &mut buf[pos..])
            .await
            .map_err(TunnelError::Io)?;

        if n == 0 {
            return Err(TunnelError::TunnelUnexpectedEof);
        }
        pos += n;

        let recvd = &buf[..pos];
        if recvd.starts_with(b"HTTP/1.1 200") || recvd.starts_with(b"HTTP/1.0 200") {
            if recvd.ends_with(b"\r\n\r\n") {
                return Ok(conn);
            }
            if pos == buf.len() {
                return Err(TunnelError::ProxyHeadersTooLong);
            }
        // else read more
        } else if recvd.starts_with(b"HTTP/1.1 407") {
            return Err(TunnelError::ProxyAuthRequired);
        } else {
            return Err(TunnelError::TunnelUnsuccessful);
        }
    }
}

async fn read<T>(io: &mut T, buf: &mut [u8]) -> io::Result<usize>
where
    T: AsyncRead + Unpin,
{
    std::future::poll_fn(move |cx| {
        let mut buf = ReadBuf::new(buf);
        ready!(Pin::new(&mut *io).poll_read(cx, &mut buf))?;
        Poll::Ready(Ok(buf.filled().len()))
    })
    .await
}

async fn write_all<T>(io: &mut T, buf: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    let mut n = 0;
    std::future::poll_fn(move |cx| {
        while n < buf.len() {
            n += ready!(Pin::new(&mut *io).poll_write(cx, &buf[n..])?);
        }
        Poll::Ready(Ok(()))
    })
    .await
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tunnel error: ")?;

        f.write_str(match self {
            TunnelError::MissingHost => "missing destination host",
            TunnelError::ProxyAuthRequired => "proxy authorization required",
            TunnelError::ProxyHeadersTooLong => "proxy response headers too long",
            TunnelError::TunnelUnexpectedEof => "unexpected end of file",
            TunnelError::TunnelUnsuccessful => "unsuccessful",
            TunnelError::ConnectFailed(_) => "failed to create underlying connection",
            TunnelError::Io(_) => "io error establishing tunnel",
        })
    }
}

impl std::error::Error for TunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TunnelError::Io(e) => Some(e),
            TunnelError::ConnectFailed(e) => Some(&**e),
            _ => None,
        }
    }
}
