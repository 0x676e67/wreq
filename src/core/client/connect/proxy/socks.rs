use std::{
    borrow::Cow,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::Uri;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_socks::{
    TargetAddr,
    tcp::{Socks4Stream, Socks5Stream},
};
use tower::Service;

use crate::dns::{GaiResolver, InternalResolve, Name};

#[derive(Debug)]
pub enum SocksError<C> {
    Inner(C),
    Socks(tokio_socks::Error),
    Io(std::io::Error),
    Utf8(std::str::Utf8Error),
    DnsFailure,
    MissingHost,
}

impl<C> std::fmt::Display for SocksError<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SOCKS error: ")?;

        match self {
            Self::Inner(_) => f.write_str("failed to create underlying connection"),
            Self::Socks(e) => f.write_fmt(format_args!("error during SOCKS handshake: {e}")),
            Self::Io(e) => f.write_fmt(format_args!("io error during SOCKS handshake: {e}")),
            Self::Utf8(e) => f.write_fmt(format_args!(
                "invalid UTF-8 during SOCKS authentication: {e}"
            )),
            Self::DnsFailure => f.write_str("could not resolve to acceptable address type"),
            Self::MissingHost => f.write_str("missing destination host"),
        }
    }
}

impl<C: std::fmt::Debug + std::fmt::Display> std::error::Error for SocksError<C> {}

impl<C> From<std::io::Error> for SocksError<C> {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl<C> From<std::str::Utf8Error> for SocksError<C> {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::Utf8(err)
    }
}

impl<C> From<tokio_socks::Error> for SocksError<C> {
    fn from(err: tokio_socks::Error) -> Self {
        Self::Socks(err)
    }
}

/// Represents the SOCKS protocol version.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Version {
    V4,
    V5,
}

/// Represents the DNS resolution strategy for SOCKS connections.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum DnsResolve {
    Local,
    Remote,
}

pin_project! {
    // Not publicly exported (so missing_docs doesn't trigger).
    //
    // We return this `Future` instead of the `Pin<Box<dyn Future>>` directly
    // so that users don't rely on it fitting in a `Pin<Box<dyn Future>>` slot
    // (and thus we can change the type in the future).
    #[must_use = "futures do nothing unless polled"]
    pub struct Handshaking<F, T, E> {
        #[pin]
        fut: BoxHandshaking<T, E>,
        _marker: std::marker::PhantomData<F>
    }
}

type BoxHandshaking<T, E> = Pin<Box<dyn Future<Output = Result<T, SocksError<E>>> + Send>>;

impl<F, T, E> Future for Handshaking<F, T, E>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<T, SocksError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}

pub struct SocksConnector<C, R = GaiResolver> {
    inner: C,
    resolver: R,
    proxy_dst: Uri,
    auth: Option<(Bytes, Bytes)>,
    version: Version,
    dns_resolve: DnsResolve,
}

impl<C, R> SocksConnector<C, R>
where
    R: InternalResolve + Clone,
{
    /// Create a new SOCKS connector with the given inner service.
    ///
    /// This wraps an underlying connector, and stores the address of a
    /// SOCKS proxy server.
    ///
    /// A `SocksConnector` can then be called with any destination. The `proxy_dst` passed to
    /// `call` will not be used to create the underlying connection, but will
    /// be used in a SOCKS handshake sent to the proxy destination.
    pub fn new_with_resolver(proxy_dst: Uri, inner: C, resolver: R) -> Self {
        SocksConnector {
            inner,
            resolver,
            proxy_dst,
            version: Version::V5,
            dns_resolve: DnsResolve::Local,
            auth: None,
        }
    }

    /// Sets the authentication credentials for the SOCKS proxy connection.
    pub fn set_auth(&mut self, auth: Option<(Bytes, Bytes)>) {
        self.auth = auth;
    }

    /// Sets whether to use the SOCKS5 protocol for the proxy connection.
    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }

    /// Sets whether to resolve DNS locally or let the proxy handle DNS resolution.
    pub fn set_dns_mode(&mut self, dns_resolve: DnsResolve) {
        self.dns_resolve = dns_resolve;
    }
}

impl<C, R> Service<Uri> for SocksConnector<C, R>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C::Error: Send + Sync + 'static,
    R: InternalResolve + Clone + Send + 'static,
    <R as InternalResolve>::Future: Send + 'static,
{
    type Response = C::Response;
    type Error = SocksError<C::Error>;
    type Future = Handshaking<C::Future, C::Response, C::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(SocksError::Inner)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let connecting = self.inner.call(self.proxy_dst.clone());

        let version = self.version;
        let dns_resolve = self.dns_resolve;
        let auth = self.auth.clone();
        let mut resolver = self.resolver.clone();

        let fut = async move {
            let port = dst.port().map(|p| p.as_u16()).unwrap_or(443);
            let host = dst.host().ok_or(SocksError::MissingHost)?;

            // Attempt to tcp connect to the proxy server.
            // This will return a `tokio::net::TcpStream` if successful.
            let socket = connecting.await.map_err(SocksError::Inner)?;

            // Resolve the target address using the provided resolver.
            let target_addr = match dns_resolve {
                DnsResolve::Local => {
                    let mut socket_addr = resolver
                        .resolve(Name::new(host.into()))
                        .await
                        .map_err(|_| SocksError::DnsFailure)?
                        .next()
                        .ok_or(SocksError::DnsFailure)?;
                    socket_addr.set_port(port);
                    TargetAddr::Ip(socket_addr)
                }
                DnsResolve::Remote => TargetAddr::Domain(Cow::Borrowed(host), port),
            };

            match version {
                Version::V4 => {
                    // For SOCKS4, we connect directly to the target address.
                    let stream = Socks4Stream::connect_with_socket(socket, target_addr).await?;
                    Ok(stream.into_inner())
                }
                Version::V5 => {
                    // For SOCKS5, we need to handle authentication if provided.
                    // The `auth` is an optional tuple of (username, password).
                    let stream = match auth {
                        Some((username, password)) => {
                            let username = std::str::from_utf8(&username)?;
                            let password = std::str::from_utf8(&password)?;
                            Socks5Stream::connect_with_password_and_socket(
                                socket,
                                target_addr,
                                username,
                                password,
                            )
                            .await?
                        }
                        None => Socks5Stream::connect_with_socket(socket, target_addr).await?,
                    };
                    Ok(stream.into_inner())
                }
            }
        };

        Handshaking {
            fut: Box::pin(fut),
            _marker: Default::default(),
        }
    }
}
