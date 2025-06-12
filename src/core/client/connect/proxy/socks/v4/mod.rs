mod errors;
pub use errors::*;

mod messages;
use messages::*;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use std::net::{IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs};

use crate::core::client::connect::dns::{GaiResolver, Name, Resolve};
use crate::core::rt::{Read, Write};
use http::Uri;
use tower_service::Service;

use bytes::BytesMut;

use pin_project_lite::pin_project;

use super::{BoxHandshaking, Handshaking, SocksError};

/// Tunnel Proxy via SOCKSv4
///
/// This is a connector that can be used by the `Client`. It wraps
/// another connector, and after getting an underlying connection, it established
/// a TCP tunnel over it using SOCKSv4.
#[derive(Debug, Clone)]
pub struct SocksV4<C, R = GaiResolver> {
    inner: C,
    config: SocksConfig<R>,
}

#[derive(Debug, Clone)]
struct SocksConfig<R = GaiResolver> {
    proxy: Uri,
    local_dns: bool,

    resolver: Option<R>,
}

#[cfg(test)]
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
}

impl<C, R> SocksV4<C, R>
where
    R: Resolve + Clone,
{
    /// Create a new SOCKSv4 handshake service
    ///
    /// Wraps an underlying connector and stores the address of a tunneling
    /// proxying server.
    ///
    /// A `SocksV4` can then be called with any destination. The `dst` passed to
    /// `call` will not be used to create the underlying connection, but will
    /// be used in a SOCKS handshake with the proxy destination.
    pub fn new_with_resolver(proxy_dst: Uri, connector: C, resolver: R) -> Self {
        Self {
            inner: connector,
            config: SocksConfig::new_with_resolver(proxy_dst, resolver),
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

#[cfg(test)]
impl SocksConfig {
    pub fn new(proxy: Uri) -> Self {
        Self {
            proxy,
            local_dns: false,
            resolver: None,
        }
    }
}

impl<R> SocksConfig<R>
where
    R: Resolve + Clone,
{
    pub fn new_with_resolver(proxy: Uri, resolver: R) -> SocksConfig<R> {
        SocksConfig {
            proxy,
            local_dns: false,
            resolver: Some(resolver),
        }
    }

    async fn execute<T, E>(
        self,
        mut conn: T,
        host: &str,
        port: u16,
    ) -> Result<T, super::SocksError<E>>
    where
        T: Read + Write + Unpin,
    {
        let address = match host.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => return Err(SocksV4Error::IpV6.into()),
            Ok(IpAddr::V4(ip)) => Address::Socket(SocketAddrV4::new(ip, port)),
            Err(_) => {
                if self.local_dns {
                    if let Some(mut resolver) = self.resolver {
                        resolver
                            .resolve(Name::new(host.into()))
                            .await
                            .map_err(|_| SocksError::DnsFailure)?
                            .find_map(|s| match s {
                                SocketAddr::V4(mut v4) => {
                                    v4.set_port(port);
                                    Some(Address::Socket(v4))
                                }
                                _ => None,
                            })
                            .ok_or(super::SocksError::DnsFailure)?
                    } else {
                        tokio::net::lookup_host((host, port))
                            .await?
                            .find_map(|s| match s {
                                SocketAddr::V4(v4) => Some(Address::Socket(v4)),
                                _ => None,
                            })
                            .ok_or(super::SocksError::DnsFailure)?
                    }
                } else {
                    Address::Domain(host.to_owned(), port)
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

impl<C, R> Service<Uri> for SocksV4<C, R>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: Read + Write + Unpin + Send + 'static,
    C::Error: Send + 'static,
    R: Resolve + Clone + Send + 'static,
    <R as Resolve>::Future: Send + 'static,
{
    type Response = C::Response;
    type Error = SocksError<C::Error>;
    type Future = Handshaking<C::Future, C::Response, C::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(SocksError::Inner)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let config = self.config.clone();
        let connecting = self.inner.call(config.proxy.clone());

        let fut = async move {
            let port = dst.port().map(|p| p.as_u16()).unwrap_or(443);
            let host = dst.host().ok_or(SocksError::MissingHost)?;

            let conn = connecting.await.map_err(SocksError::Inner)?;
            config.execute(conn, host, port).await
        };

        Handshaking {
            fut: Box::pin(fut),
            _marker: Default::default(),
        }
    }
}
