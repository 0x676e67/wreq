mod errors;
pub use errors::*;

mod messages;
use messages::*;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use std::net::{IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs};

use crate::core::rt::{Read, Write};
use http::Uri;
use tower_service::Service;

use bytes::BytesMut;

use pin_project_lite::pin_project;

/// Tunnel Proxy via SOCKSv4
///
/// This is a connector that can be used by the `legacy::Client`. It wraps
/// another connector, and after getting an underlying connection, it established
/// a TCP tunnel over it using SOCKSv4.
#[derive(Debug, Clone)]
pub struct SocksV4<C> {
    inner: C,
    config: SocksConfig,
}

#[derive(Debug, Clone)]
struct SocksConfig {
    proxy: Uri,
    local_dns: bool,
}

pin_project! {
    // Not publicly exported (so missing_docs doesn't trigger).
    //
    // We return this `Future` instead of the `Pin<Box<dyn Future>>` directly
    // so that users don't rely on it fitting in a `Pin<Box<dyn Future>>` slot
    // (and thus we can change the type in the future).
    #[must_use = "futures do nothing unless polled"]
    #[allow(missing_debug_implementations)]
    pub struct Handshaking<F, T, E> {
        #[pin]
        fut: BoxHandshaking<T, E>,
        _marker: std::marker::PhantomData<F>
    }
}

type BoxHandshaking<T, E> = Pin<Box<dyn Future<Output = Result<T, super::SocksError<E>>> + Send>>;

impl<C> SocksV4<C> {
    /// Create a new SOCKSv4 handshake service
    ///
    /// Wraps an underlying connector and stores the address of a tunneling
    /// proxying server.
    ///
    /// A `SocksV4` can then be called with any destination. The `dst` passed to
    /// `call` will not be used to create the underlying connection, but will
    /// be used in a SOCKS handshake with the proxy destination.
    pub fn new(proxy_dst: Uri, connector: C) -> Self {
        Self {
            inner: connector,
            config: SocksConfig::new(proxy_dst),
        }
    }

    /// Resolve domain names locally on the client, rather than on the proxy server.
    ///
    /// Disabled by default as local resolution of domain names can be detected as a
    /// DNS leak.
    pub fn local_dns(mut self, local_dns: bool) -> Self {
        self.config.local_dns = local_dns;
        self
    }
}

impl SocksConfig {
    pub fn new(proxy: Uri) -> Self {
        Self {
            proxy,
            local_dns: false,
        }
    }

    async fn execute<T, E>(
        self,
        mut conn: T,
        host: String,
        port: u16,
    ) -> Result<T, super::SocksError<E>>
    where
        T: Read + Write + Unpin,
    {
        let address = match host.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => return Err(SocksV4Error::IpV6.into()),
            Ok(IpAddr::V4(ip)) => Address::Socket(SocketAddrV4::new(ip.into(), port)),
            Err(_) => {
                if self.local_dns {
                    (host, port)
                        .to_socket_addrs()?
                        .find_map(|s| {
                            if let SocketAddr::V4(v4) = s {
                                Some(Address::Socket(v4))
                            } else {
                                None
                            }
                        })
                        .ok_or(super::SocksError::DnsFailure)?
                } else {
                    Address::Domain(host, port)
                }
            }
        };

        let mut send_buf = BytesMut::with_capacity(1024);
        let mut recv_buf = BytesMut::with_capacity(1024);

        // Send Request
        let req = Request(&address);
        let n = req.write_to_buf(&mut send_buf)?;
        crate::core::rt::write_all(&mut conn, &send_buf[..n]).await?;

        // Read Response
        let res: Response = super::read_message(&mut conn, &mut recv_buf).await?;
        if res.0 == Status::Success {
            Ok(conn)
        } else {
            Err(SocksV4Error::Command(res.0).into())
        }
    }
}

impl<C> Service<Uri> for SocksV4<C>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: Read + Write + Unpin + Send + 'static,
    C::Error: Send + 'static,
{
    type Response = C::Response;
    type Error = super::SocksError<C::Error>;
    type Future = Handshaking<C::Future, C::Response, C::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(super::SocksError::Inner)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let config = self.config.clone();
        let connecting = self.inner.call(config.proxy.clone());

        let fut = async move {
            let port = dst.port().map(|p| p.as_u16()).unwrap_or(443);
            let host = dst
                .host()
                .ok_or(super::SocksError::MissingHost)?
                .to_string();

            let conn = connecting.await.map_err(super::SocksError::Inner)?;
            config.execute(conn, host, port).await
        };

        Handshaking {
            fut: Box::pin(fut),
            _marker: Default::default(),
        }
    }
}

impl<F, T, E> Future for Handshaking<F, T, E>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<T, super::SocksError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}
