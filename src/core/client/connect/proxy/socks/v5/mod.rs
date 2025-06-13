mod errors;
pub use errors::*;

mod messages;
use std::{
    future::Future,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BytesMut;
use http::Uri;
use messages::*;
use pin_project_lite::pin_project;
use tower_service::Service;

use super::{BoxHandshaking, Handshaking, SocksError};
use crate::core::{
    client::connect::dns::{GaiResolver, Name, Resolve},
    rt::{Read, Write},
};

/// Tunnel Proxy via SOCKSv5
///
/// This is a connector that can be used by the `Client`. It wraps
/// another connector, and after getting an underlying connection, it established
/// a TCP tunnel over it using SOCKSv5.
#[derive(Debug, Clone)]
pub struct SocksV5<C, R = GaiResolver> {
    inner: C,
    config: SocksConfig<R>,
}

#[derive(Debug, Clone)]
pub struct SocksConfig<R = GaiResolver> {
    proxy: Uri,
    proxy_auth: Option<(String, String)>,

    local_dns: bool,
    optimistic: bool,

    resolver: Option<R>,
}

#[derive(Debug)]
enum State {
    SendingNegReq,
    ReadingNegRes,
    SendingAuthReq,
    ReadingAuthRes,
    SendingProxyReq,
    ReadingProxyRes,
}

#[cfg(test)]
impl<C> SocksV5<C> {
    /// Create a new SOCKSv5 handshake service.
    ///
    /// Wraps an underlying connector and stores the address of a tunneling
    /// proxying server.
    ///
    /// A `SocksV5` can then be called with any destination. The `dst` passed to
    /// `call` will not be used to create the underlying connection, but will
    /// be used in a SOCKS handshake with the proxy destination.
    pub fn new(proxy_dst: Uri, connector: C) -> Self {
        Self {
            inner: connector,
            config: SocksConfig::new(proxy_dst),
        }
    }
}

impl<C, R> SocksV5<C, R>
where
    R: Resolve + Clone,
{
    /// Create a new SOCKSv5 handshake service with a custom DNS resolver.
    ///
    /// Wraps an underlying connector and stores the address of a tunneling
    /// proxying server, as well as a custom DNS resolver.
    ///
    /// A `SocksV5` can then be called with any destination. The `dst` passed to
    /// `call` will not be used to create the underlying connection, but will
    /// be used in a SOCKS handshake with the proxy destination.
    pub fn new_with_resolver(proxy_dst: Uri, connector: C, resolver: R) -> Self {
        Self {
            inner: connector,
            config: SocksConfig::new_with_resolver(proxy_dst, resolver),
        }
    }

    /// Use User/Pass authentication method during handshake.
    ///
    /// Username and Password must be maximum of 255 characters each.
    /// 0 length strings are allowed despite RFC prohibiting it. This is done so that
    /// for compatablity with server implementations that require it for IP authentication.
    pub fn with_auth(mut self, user: String, pass: String) -> Self {
        self.config.proxy_auth = Some((user, pass));
        self
    }

    /// Resolve domain names locally on the client, rather than on the proxy server.
    ///
    /// Disabled by default as local resolution of domain names can be detected as a
    /// DNS leak.
    pub fn local_dns(mut self, local_dns: bool) -> Self {
        self.config.local_dns = local_dns;
        self
    }

    /// Send all messages of the handshake optmistically (without waiting for server response).
    ///
    /// Typical SOCKS handshake with auithentication takes 3 round trips. Optimistic sending
    /// can reduce round trip times and dramatically increase speed of handshake at the cost of
    /// reduced portability; many server implementations do not support optimistic sending as it
    /// is not defined in the RFC (RFC 1928).
    ///
    /// Recommended to ensure connector works correctly without optimistic sending before trying
    /// with optimistic sending.
    pub fn send_optimistically(mut self, optimistic: bool) -> Self {
        self.config.optimistic = optimistic;
        self
    }
}

#[cfg(test)]
impl SocksConfig {
    pub fn new(proxy: Uri) -> Self {
        Self {
            proxy,
            proxy_auth: None,

            local_dns: false,
            optimistic: false,

            resolver: None,
        }
    }
}

impl<R> SocksConfig<R>
where
    R: Resolve + Clone,
{
    fn new_with_resolver(proxy: Uri, resolver: R) -> Self {
        Self {
            proxy,
            proxy_auth: None,

            local_dns: false,
            optimistic: false,

            resolver: Some(resolver),
        }
    }

    async fn execute<T, E>(self, mut conn: T, host: &str, port: u16) -> Result<T, SocksError<E>>
    where
        T: Read + Write + Unpin,
    {
        let address = match host.parse::<IpAddr>() {
            Ok(ip) => Address::Socket(SocketAddr::new(ip, port)),
            Err(_) if host.len() <= 255 => {
                if self.local_dns {
                    let socket = if let Some(mut resolver) = self.resolver {
                        let mut socket_addr = resolver
                            .resolve(Name::new(host.into()))
                            .await
                            .map_err(|_| SocksError::DnsFailure)?
                            .next()
                            .ok_or(SocksError::DnsFailure)?;
                        socket_addr.set_port(port);
                        socket_addr
                    } else {
                        tokio::net::lookup_host((host, port))
                            .await?
                            .next()
                            .ok_or(SocksError::DnsFailure)?
                    };

                    Address::Socket(socket)
                } else {
                    Address::Domain(host.to_owned(), port)
                }
            }
            Err(_) => return Err(SocksV5Error::HostTooLong.into()),
        };

        let method = if self.proxy_auth.is_some() {
            AuthMethod::UserPass
        } else {
            AuthMethod::NoAuth
        };

        // Max length of valid recievable message is 513 from Auth Request
        let mut recv_buf = BytesMut::with_capacity(513);
        // Max length of valid sendable message is 262 from Auth Response
        let mut send_buf = BytesMut::with_capacity(262);
        let mut state = State::SendingNegReq;

        loop {
            match state {
                State::SendingNegReq => {
                    let req = NegotiationReq(&method);

                    let start = send_buf.len();
                    req.write_to_buf(&mut send_buf)?;
                    crate::core::rt::write_all(&mut conn, &send_buf[start..]).await?;

                    if self.optimistic {
                        if method == AuthMethod::UserPass {
                            state = State::SendingAuthReq;
                        } else {
                            state = State::SendingProxyReq;
                        }
                    } else {
                        state = State::ReadingNegRes;
                    }
                }

                State::ReadingNegRes => {
                    let res: NegotiationRes = super::read_message(&mut conn, &mut recv_buf).await?;

                    if res.0 == AuthMethod::NoneAcceptable {
                        return Err(SocksV5Error::Auth(AuthError::Unsupported).into());
                    }

                    if res.0 != method {
                        return Err(SocksV5Error::Auth(AuthError::MethodMismatch).into());
                    }

                    if self.optimistic {
                        if res.0 == AuthMethod::UserPass {
                            state = State::ReadingAuthRes;
                        } else {
                            state = State::ReadingProxyRes;
                        }
                    } else if res.0 == AuthMethod::UserPass {
                        state = State::SendingAuthReq;
                    } else {
                        state = State::SendingProxyReq;
                    }
                }

                State::SendingAuthReq => {
                    let (user, pass) = self.proxy_auth.as_ref().unwrap();
                    let req = AuthenticationReq(user, pass);

                    let start = send_buf.len();
                    req.write_to_buf(&mut send_buf)?;
                    crate::core::rt::write_all(&mut conn, &send_buf[start..]).await?;

                    if self.optimistic {
                        state = State::SendingProxyReq;
                    } else {
                        state = State::ReadingAuthRes;
                    }
                }

                State::ReadingAuthRes => {
                    let res: AuthenticationRes =
                        super::read_message(&mut conn, &mut recv_buf).await?;

                    if !res.0 {
                        return Err(SocksV5Error::Auth(AuthError::Failed).into());
                    }

                    if self.optimistic {
                        state = State::ReadingProxyRes;
                    } else {
                        state = State::SendingProxyReq;
                    }
                }

                State::SendingProxyReq => {
                    let req = ProxyReq(&address);

                    let start = send_buf.len();
                    req.write_to_buf(&mut send_buf)?;
                    crate::core::rt::write_all(&mut conn, &send_buf[start..]).await?;

                    if self.optimistic {
                        state = State::ReadingNegRes;
                    } else {
                        state = State::ReadingProxyRes;
                    }
                }

                State::ReadingProxyRes => {
                    let res: ProxyRes = super::read_message(&mut conn, &mut recv_buf).await?;

                    if res.0 == Status::Success {
                        return Ok(conn);
                    } else {
                        return Err(SocksV5Error::Command(res.0).into());
                    }
                }
            }
        }
    }
}

impl<C, R> Service<Uri> for SocksV5<C, R>
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
            let host = host.trim_start_matches('[').trim_end_matches(']');

            let conn = connecting.await.map_err(SocksError::Inner)?;
            config.execute(conn, host, port).await
        };

        Handshaking {
            fut: Box::pin(fut),
            _marker: Default::default(),
        }
    }
}
