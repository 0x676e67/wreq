#[cfg(feature = "compio")]
pub mod compio;
pub mod tokio;

use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::pin,
    time::Duration,
};

use futures_util::future::Either;

use super::{Connection, config::TcpOptions};
use crate::{dns, error::BoxError};

/// A builder for tcp connections.
pub trait TcpConnector: Clone + Send + Sync + 'static {
    /// The underlying stream type.
    type TcpStream: From<socket2::Socket> + Send + Sync + 'static;

    /// The type of connection returned by this builder.
    type Connection: ::tokio::io::AsyncRead
        + ::tokio::io::AsyncWrite
        + Connection
        + Send
        + Unpin
        + 'static;

    /// The type of error returned by this builder.
    type Error: Into<Box<dyn StdError + Send + Sync>>;

    /// The future type returned by this builder.
    type Future: Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static;

    /// The future type returned by this builder's sleep.
    type Sleep: Future<Output = ()> + Send + 'static;

    /// Build a connection from the given socket and connect to the address.
    fn connect(&self, socket: Self::TcpStream, addr: SocketAddr) -> Self::Future;

    /// Return a future that sleeps for the given duration.
    fn sleep(&self, duration: Duration) -> Self::Sleep;
}

pub(super) struct ConnectingTcp<S: TcpConnector> {
    preferred: ConnectingTcpRemote<S>,
    fallback: Option<ConnectingTcpFallback<S>>,
}

struct ConnectingTcpFallback<S: TcpConnector> {
    delay: S::Sleep,
    remote: ConnectingTcpRemote<S>,
}

struct ConnectingTcpRemote<S: TcpConnector> {
    addrs: dns::SocketAddrs,
    connect_timeout: Option<Duration>,
    connector: S,
}

impl<S: TcpConnector> ConnectingTcp<S>
where
    S::TcpStream: From<socket2::Socket>,
{
    pub(super) fn new(remote_addrs: dns::SocketAddrs, config: &TcpOptions, connector: S) -> Self {
        if let Some(fallback_timeout) = config.happy_eyeballs_timeout {
            let (preferred_addrs, fallback_addrs) = remote_addrs.split_by_preference(
                config.socket_bind_options.local_address_ipv4,
                config.socket_bind_options.local_address_ipv6,
            );
            if fallback_addrs.is_empty() {
                return ConnectingTcp {
                    preferred: ConnectingTcpRemote::new(
                        preferred_addrs,
                        config.connect_timeout,
                        connector,
                    ),
                    fallback: None,
                };
            }

            ConnectingTcp {
                preferred: ConnectingTcpRemote::new(
                    preferred_addrs,
                    config.connect_timeout,
                    connector.clone(),
                ),
                fallback: Some(ConnectingTcpFallback {
                    delay: connector.sleep(fallback_timeout),
                    remote: ConnectingTcpRemote::new(
                        fallback_addrs,
                        config.connect_timeout,
                        connector,
                    ),
                }),
            }
        } else {
            ConnectingTcp {
                preferred: ConnectingTcpRemote::new(
                    remote_addrs,
                    config.connect_timeout,
                    connector,
                ),
                fallback: None,
            }
        }
    }
}

impl<S: TcpConnector> ConnectingTcpRemote<S>
where
    S::TcpStream: From<socket2::Socket>,
{
    fn new(addrs: dns::SocketAddrs, connect_timeout: Option<Duration>, connector: S) -> Self {
        let connect_timeout = connect_timeout.and_then(|t| t.checked_div(addrs.len() as u32));

        Self {
            addrs,
            connect_timeout,
            connector,
        }
    }

    async fn connect(&mut self, config: &TcpOptions) -> Result<S::Connection, ConnectError> {
        let mut err = None;
        for addr in &mut self.addrs {
            debug!("connecting to {}", addr);
            match connect(&addr, config, self.connect_timeout, &self.connector) {
                Ok(fut) => match fut.await {
                    Ok(tcp) => {
                        debug!("connected to {}", addr);
                        return Ok(tcp);
                    }
                    Err(mut e) => {
                        trace!("connect error for {}: {:?}", addr, e);
                        e.addr = Some(addr);
                        if err.is_none() {
                            err = Some(e);
                        }
                    }
                },
                Err(mut e) => {
                    trace!("connect error for {}: {:?}", addr, e);
                    e.addr = Some(addr);
                    if err.is_none() {
                        err = Some(e);
                    }
                }
            }
        }

        match err {
            Some(e) => Err(e),
            None => Err(ConnectError::new(
                "tcp connect error",
                std::io::Error::new(std::io::ErrorKind::NotConnected, "Network unreachable"),
            )),
        }
    }
}

fn bind_local_address(
    socket: &socket2::Socket,
    dst_addr: &SocketAddr,
    local_addr_ipv4: &Option<Ipv4Addr>,
    local_addr_ipv6: &Option<Ipv6Addr>,
) -> io::Result<()> {
    match (*dst_addr, local_addr_ipv4, local_addr_ipv6) {
        (SocketAddr::V4(_), Some(addr), _) => {
            socket.bind(&SocketAddr::new((*addr).into(), 0).into())?;
        }
        (SocketAddr::V6(_), _, Some(addr)) => {
            socket.bind(&SocketAddr::new((*addr).into(), 0).into())?;
        }
        _ => {
            if cfg!(windows) {
                // Windows requires a socket be bound before calling connect
                let any: SocketAddr = match *dst_addr {
                    SocketAddr::V4(_) => ([0, 0, 0, 0], 0).into(),
                    SocketAddr::V6(_) => ([0, 0, 0, 0, 0, 0, 0, 0], 0).into(),
                };
                socket.bind(&any.into())?;
            }
        }
    }

    Ok(())
}

fn connect<S: TcpConnector>(
    addr: &SocketAddr,
    config: &TcpOptions,
    connect_timeout: Option<Duration>,
    connector: &S,
) -> Result<impl Future<Output = Result<S::Connection, ConnectError>>, ConnectError>
where
    S::TcpStream: From<socket2::Socket>,
{
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = Domain::for_address(*addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(ConnectError::m("tcp open error"))?;

    // When constructing a Tokio `TcpSocket` from a raw fd/socket, the user is
    // responsible for ensuring O_NONBLOCK is set.
    socket
        .set_nonblocking(true)
        .map_err(ConnectError::m("tcp set_nonblocking error"))?;

    if let Some(tcp_keepalive) = &config.tcp_keepalive_config.into_tcpkeepalive() {
        if let Err(_e) = socket.set_tcp_keepalive(tcp_keepalive) {
            warn!("tcp set_keepalive error: {_e}");
        }
    }

    // That this only works for some socket types, particularly AF_INET sockets.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    if let Some(interface) = &config.socket_bind_options.interface {
        // On Linux-like systems, set the interface to bind using
        // `SO_BINDTODEVICE`.
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket
            .bind_device(Some(interface.as_bytes()))
            .map_err(ConnectError::m("tcp bind interface error"))?;

        // On macOS-like and Solaris-like systems, we instead use `IP_BOUND_IF`.
        // This socket option desires an integer index for the interface, so we
        // must first determine the index of the requested interface name using
        // `if_nametoindex`.
        #[cfg(any(
            target_os = "illumos",
            target_os = "ios",
            target_os = "macos",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
        ))]
        if let Ok(interface) = std::ffi::CString::new(interface.as_bytes()) {
            #[allow(unsafe_code)]
            let idx = unsafe { libc::if_nametoindex(interface.as_ptr()) };
            let idx = std::num::NonZeroU32::new(idx).ok_or_else(|| {
                // If the index is 0, check errno and return an I/O error.
                ConnectError::new(
                    "error converting interface name to index",
                    io::Error::last_os_error(),
                )
            })?;

            // Different setsockopt calls are necessary depending on whether the
            // address is IPv4 or IPv6.
            match addr {
                SocketAddr::V4(_) => socket.bind_device_by_index_v4(Some(idx)),
                SocketAddr::V6(_) => socket.bind_device_by_index_v6(Some(idx)),
            }
            .map_err(ConnectError::m("tcp bind interface error"))?;
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(tcp_user_timeout) = &config.tcp_user_timeout {
        if let Err(_e) = socket.set_tcp_user_timeout(Some(*tcp_user_timeout)) {
            warn!("tcp set_tcp_user_timeout error: {_e}");
        }
    }

    bind_local_address(
        &socket,
        addr,
        &config.socket_bind_options.local_address_ipv4,
        &config.socket_bind_options.local_address_ipv6,
    )
    .map_err(ConnectError::m("tcp bind local error"))?;

    if config.reuse_address {
        if let Err(_e) = socket.set_reuse_address(true) {
            warn!("tcp set_reuse_address error: {_e}");
        }
    }

    if let Some(size) = config.send_buffer_size {
        if let Err(_e) = socket.set_send_buffer_size(size) {
            warn!("tcp set_buffer_size error: {_e}");
        }
    }

    if let Some(size) = config.recv_buffer_size {
        if let Err(_e) = socket.set_recv_buffer_size(size) {
            warn!("tcp set_recv_buffer_size error: {_e}");
        }
    }

    let connect = connector.connect(socket.into(), *addr);
    let sleep = connect_timeout.map(|dur| connector.sleep(dur));

    Ok(async move {
        match sleep {
            Some(sleep) => match futures_util::future::select(pin!(sleep), pin!(connect)).await {
                Either::Left(((), _)) => {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout").into())
                }
                Either::Right((Ok(s), _)) => Ok(s),
                Either::Right((Err(e), _)) => Err(e.into()),
            },
            None => connect.await.map_err(Into::into),
        }
        .map_err(ConnectError::m("tcp connect error"))
    })
}

impl<S: TcpConnector> ConnectingTcp<S>
where
    S::TcpStream: From<socket2::Socket>,
{
    pub(super) async fn connect(
        mut self,
        config: &TcpOptions,
    ) -> Result<S::Connection, ConnectError> {
        match self.fallback {
            None => self.preferred.connect(config).await,
            Some(mut fallback) => {
                let preferred_fut = self.preferred.connect(config);
                futures_util::pin_mut!(preferred_fut);

                let fallback_fut = fallback.remote.connect(config);
                futures_util::pin_mut!(fallback_fut);

                let fallback_delay = fallback.delay;
                futures_util::pin_mut!(fallback_delay);

                let (result, future) =
                    match futures_util::future::select(preferred_fut, fallback_delay).await {
                        Either::Left((result, _fallback_delay)) => {
                            (result, Either::Right(fallback_fut))
                        }
                        Either::Right(((), preferred_fut)) => {
                            // Delay is done, start polling both the preferred and the fallback
                            futures_util::future::select(preferred_fut, fallback_fut)
                                .await
                                .factor_first()
                        }
                    };

                if result.is_err() {
                    // Fallback to the remaining future (could be preferred or fallback)
                    // if we get an error
                    future.await
                } else {
                    result
                }
            }
        }
    }
}

// Not publicly exported (so missing_docs doesn't trigger).
pub struct ConnectError {
    pub(super) msg: &'static str,
    pub(super) addr: Option<SocketAddr>,
    pub(super) cause: Option<BoxError>,
}

impl ConnectError {
    pub(super) fn new<E>(msg: &'static str, cause: E) -> ConnectError
    where
        E: Into<BoxError>,
    {
        ConnectError {
            msg,
            addr: None,
            cause: Some(cause.into()),
        }
    }

    pub(super) fn dns<E>(cause: E) -> ConnectError
    where
        E: Into<BoxError>,
    {
        ConnectError::new("dns error", cause)
    }

    pub(super) fn m<E>(msg: &'static str) -> impl FnOnce(E) -> ConnectError
    where
        E: Into<BoxError>,
    {
        move |cause| ConnectError::new(msg, cause)
    }
}

impl fmt::Debug for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut b = f.debug_tuple("ConnectError");
        b.field(&self.msg);
        if let Some(ref addr) = self.addr {
            b.field(addr);
        }
        if let Some(ref cause) = self.cause {
            b.field(cause);
        }
        b.finish()
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.msg)
    }
}

impl StdError for ConnectError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.cause.as_ref().map(|e| &**e as _)
    }
}
