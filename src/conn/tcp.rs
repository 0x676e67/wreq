pub mod tokio;

#[cfg(any(
    target_os = "illumos",
    target_os = "ios",
    target_os = "macos",
    target_os = "solaris",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
))]
use std::borrow::Cow;
use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::pin,
    time::Duration,
};

use futures_util::future::Either;
use socket2::TcpKeepalive;

use super::Connection;
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
                config.socket_bind.ipv4_address,
                config.socket_bind.ipv6_address,
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

    if let Some(tcp_keepalive) = &config.tcp_keepalive.into_tcpkeepalive() {
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
    if let Some(interface) = &config.socket_bind.interface {
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
        &config.socket_bind.ipv4_address,
        &config.socket_bind.ipv6_address,
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

    if let Err(_e) = socket.set_tcp_nodelay(config.nodelay) {
        warn!("tcp set_tcp_nodelay error: {_e}");
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
                let preferred_fut = pin!(self.preferred.connect(config));
                let fallback_fut = pin!(fallback.remote.connect(config));
                let fallback_delay = pin!(fallback.delay);

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

/// Options for configuring socket bind behavior for outbound connections.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub(crate) struct SocketBindOptions {
    #[cfg(any(
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub interface: Option<Cow<'static, str>>,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
}

impl SocketBindOptions {
    /// Sets the name of the network interface to bind the socket to.
    ///
    /// ## Platform behavior
    /// - On Linux/Fuchsia/Android: sets `SO_BINDTODEVICE`
    /// - On macOS/illumos/Solaris/iOS/etc.: sets `IP_BOUND_IF`
    ///
    /// If `interface` is `None`, the socket will not be explicitly bound to any device.
    ///
    /// # Errors
    ///
    /// On platforms that require a `CString` (e.g. macOS), this will return an error if the
    /// interface name contains an internal null byte (`\0`), which is invalid in C strings.
    ///
    /// # See Also
    /// - [VRF documentation](https://www.kernel.org/doc/Documentation/networking/vrf.txt)
    /// - [`man 7 socket`](https://man7.org/linux/man-pages/man7/socket.7.html)
    /// - [`man 7p ip`](https://docs.oracle.com/cd/E86824_01/html/E54777/ip-7p.html)
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
    #[inline]
    pub fn set_interface<I>(&mut self, interface: I) -> &mut Self
    where
        I: Into<std::borrow::Cow<'static, str>>,
    {
        self.interface = Some(interface.into());
        self
    }

    /// Set that all sockets are bound to the configured address before connection.
    ///
    /// If `None`, the sockets will not be bound.
    ///
    /// Default is `None`.
    #[inline]
    pub fn set_local_address<V>(&mut self, local_address: V)
    where
        V: Into<Option<IpAddr>>,
    {
        match local_address.into() {
            Some(IpAddr::V4(a)) => {
                self.ipv4_address = Some(a);
            }
            Some(IpAddr::V6(a)) => {
                self.ipv6_address = Some(a);
            }
            _ => {}
        };
    }

    /// Set that all sockets are bound to the configured IPv4 or IPv6 address (depending on host's
    /// preferences) before connection.
    ///
    /// If `None`, the sockets will not be bound.
    ///
    /// Default is `None`.
    #[inline]
    pub fn set_local_addresses<V4, V6>(&mut self, ipv4_address: V4, ipv6_address: V6)
    where
        V4: Into<Option<Ipv4Addr>>,
        V6: Into<Option<Ipv6Addr>>,
    {
        if let Some(addr) = ipv4_address.into() {
            self.ipv4_address = Some(addr);
        }
        if let Some(addr) = ipv6_address.into() {
            self.ipv6_address = Some(addr);
        }
    }
}

#[derive(Clone)]
pub(crate) struct TcpOptions {
    pub enforce_http: bool,
    pub connect_timeout: Option<Duration>,
    pub happy_eyeballs_timeout: Option<Duration>,
    pub nodelay: bool,
    pub reuse_address: bool,
    pub send_buffer_size: Option<usize>,
    pub recv_buffer_size: Option<usize>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub tcp_user_timeout: Option<Duration>,
    pub tcp_keepalive: TcpKeepaliveOptions,
    pub socket_bind: SocketBindOptions,
}

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct TcpKeepaliveOptions {
    pub time: Option<Duration>,
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "visionos",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
        target_os = "cygwin",
    ))]
    pub interval: Option<Duration>,
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "visionos",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "cygwin",
        target_os = "windows",
    ))]
    pub retries: Option<u32>,
}

impl TcpKeepaliveOptions {
    /// Converts into a `socket2::TcpKeealive` if there is any keep alive configuration.
    pub(crate) fn into_tcpkeepalive(self) -> Option<TcpKeepalive> {
        let mut dirty = false;
        let mut ka = TcpKeepalive::new();
        if let Some(time) = self.time {
            ka = ka.with_time(time);
            dirty = true
        }

        // Set the value of the `TCP_KEEPINTVL` option. On Windows, this sets the
        // value of the `tcp_keepalive` struct's `keepaliveinterval` field.
        //
        // Sets the time interval between TCP keepalive probes.
        //
        // Some platforms specify this value in seconds, so sub-second
        // specifications may be omitted.
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "visionos",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "windows",
            target_os = "cygwin",
        ))]
        {
            if let Some(interval) = self.interval {
                dirty = true;
                ka = ka.with_interval(interval)
            };
        }

        // Set the value of the `TCP_KEEPCNT` option.
        //
        // Set the maximum number of TCP keepalive probes that will be sent before
        // dropping a connection, if TCP keepalive is enabled on this socket.
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "visionos",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "cygwin",
            target_os = "windows",
        ))]
        if let Some(retries) = self.retries {
            dirty = true;
            ka = ka.with_retries(retries)
        };

        if dirty { Some(ka) } else { None }
    }
}
