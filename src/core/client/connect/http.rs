use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    io,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use futures_util::future::Either;
use http::uri::{Scheme, Uri};
use pin_project_lite::pin_project;
use socket2::TcpKeepalive;
use tokio::{
    net::{TcpSocket, TcpStream},
    time::Sleep,
};

use super::{Connected, Connection};
use crate::{
    core::BoxError,
    dns::{self, GaiResolver, InternalResolve, resolve},
};

/// A connector for the `http` scheme.
///
/// Performs DNS resolution in a thread pool, and then connects over TCP.
///
/// # Note
///
/// Sets the [`HttpInfo`] value on responses, which includes
/// transport information such as the remote socket address used.
#[derive(Clone)]
pub struct HttpConnector<R = GaiResolver> {
    config: Arc<Config>,
    resolver: R,
}

/// Extra information about the transport when an HttpConnector is used.
///
/// # Example
///
/// ```
/// # fn doc(res: http::Response<()>) {
/// use crate::util::client::connect::HttpInfo;
///
/// // res = http::Response
/// res.extensions().get::<HttpInfo>().map(|info| {
///     println!("remote addr = {}", info.remote_addr());
/// });
/// # }
/// ```
///
/// # Note
///
/// If a different connector is used besides [`HttpConnector`],
/// this value will not exist in the extensions. Consult that specific
/// connector to see what "extra" information it might provide to responses.
#[derive(Clone, Debug)]
pub struct HttpInfo {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
}

/// Options for configuring a TCP network connection.
///
/// `TcpConnectOptions` allows fine-grained control over how TCP sockets
/// are created and connected. It can be used to:
///
/// - Bind a socket to a specific **network interface**
/// - Bind to a **local IPv4 or IPv6 address**
///
/// This is especially useful for scenarios involving:
/// - Virtual routing tables (e.g. Linux VRFs)
/// - Multiple NICs (network interface cards)
/// - Explicit source IP routing or firewall rules
///
/// Platform-specific behavior is handled internally, with the interface binding
/// mechanism differing across Unix-like systems.
///
/// # Platform Notes
///
/// ## Interface binding (`set_interface`)
///
/// - **Linux / Android / Fuchsia**: uses the `SO_BINDTODEVICE` socket option   See [`man 7 socket`](https://man7.org/linux/man-pages/man7/socket.7.html)
///
/// - **macOS / iOS / tvOS / watchOS / visionOS / illumos / Solaris**: uses the `IP_BOUND_IF` socket
///   option   See [`man 7p ip`](https://docs.oracle.com/cd/E86824_01/html/E54777/ip-7p.html)
///
/// Binding to an interface ensures that:
/// - **Outgoing packets** are sent through the specified interface
/// - **Incoming packets** are only accepted if received via that interface
///
/// ❗ This only applies to certain socket types (e.g. `AF_INET`), and may require
/// elevated permissions (e.g. `CAP_NET_RAW` on Linux).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct TcpConnectOptions {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    interface: Option<std::borrow::Cow<'static, str>>,
    #[cfg(any(
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    interface: Option<std::ffi::CString>,
    local_ipv4: Option<Ipv4Addr>,
    local_ipv6: Option<Ipv6Addr>,
}

impl TcpConnectOptions {
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
    pub fn set_interface<S>(&mut self, interface: S) -> &mut Self
    where
        S: Into<std::borrow::Cow<'static, str>>,
    {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            self.interface = Some(interface.into());
        }

        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        {
            self.interface = std::ffi::CString::new(interface.into().into_owned()).ok()
        }

        self
    }

    /// Set that all sockets are bound to the configured address before connection.
    ///
    /// If `None`, the sockets will not be bound.
    ///
    /// Default is `None`.
    #[inline]
    pub fn set_local_address(&mut self, local_addr: Option<IpAddr>) {
        match local_addr {
            Some(IpAddr::V4(a)) => {
                self.local_ipv4 = Some(a);
            }
            Some(IpAddr::V6(a)) => {
                self.local_ipv6 = Some(a);
            }
            _ => {}
        };
    }

    /// Set that all sockets are bound to the configured IPv4 or IPv6 address (depending on host's
    /// preferences) before connection.
    #[inline]
    pub fn set_local_addresses<V4, V6>(&mut self, local_ipv4: V4, local_ipv6: V6)
    where
        V4: Into<Option<Ipv4Addr>>,
        V6: Into<Option<Ipv6Addr>>,
    {
        self.local_ipv4 = local_ipv4.into();
        self.local_ipv6 = local_ipv6.into();
    }
}

#[derive(Clone)]
struct Config {
    connect_timeout: Option<Duration>,
    enforce_http: bool,
    happy_eyeballs_timeout: Option<Duration>,
    tcp_keepalive_config: TcpKeepaliveConfig,
    tcp_connect_options: TcpConnectOptions,
    nodelay: bool,
    reuse_address: bool,
    send_buffer_size: Option<usize>,
    recv_buffer_size: Option<usize>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    tcp_user_timeout: Option<Duration>,
}

#[derive(Default, Debug, Clone, Copy)]
struct TcpKeepaliveConfig {
    time: Option<Duration>,
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
    interval: Option<Duration>,
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
    retries: Option<u32>,
}

impl TcpKeepaliveConfig {
    /// Converts into a `socket2::TcpKeealive` if there is any keep alive configuration.
    fn into_tcpkeepalive(self) -> Option<TcpKeepalive> {
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

// ===== impl HttpConnector =====

impl Default for HttpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpConnector {
    /// Construct a new HttpConnector.
    pub fn new() -> HttpConnector {
        HttpConnector::new_with_resolver(GaiResolver::new())
    }
}

impl<R> HttpConnector<R> {
    /// Construct a new HttpConnector.
    ///
    /// Takes a [`Resolver`](crate::core::client::connect::dns#resolvers-are-services) to handle DNS
    /// lookups.
    pub fn new_with_resolver(resolver: R) -> HttpConnector<R> {
        HttpConnector {
            config: Arc::new(Config {
                connect_timeout: None,
                enforce_http: true,
                happy_eyeballs_timeout: Some(Duration::from_millis(300)),
                tcp_keepalive_config: TcpKeepaliveConfig::default(),
                tcp_connect_options: TcpConnectOptions::default(),
                nodelay: false,
                reuse_address: false,
                send_buffer_size: None,
                recv_buffer_size: None,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                tcp_user_timeout: None,
            }),
            resolver,
        }
    }

    /// Option to enforce all `Uri`s have the `http` scheme.
    ///
    /// Enabled by default.
    #[inline]
    pub fn enforce_http(&mut self, is_enforced: bool) {
        self.config_mut().enforce_http = is_enforced;
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied duration
    /// to remain idle before sending TCP keepalive probes.
    ///
    /// If `None`, keepalive is disabled.
    ///
    /// Default is `None`.
    #[inline]
    pub fn set_keepalive(&mut self, time: Option<Duration>) {
        self.config_mut().tcp_keepalive_config.time = time;
    }

    /// Set the duration between two successive TCP keepalive retransmissions,
    /// if acknowledgement to the previous keepalive transmission is not received.
    #[inline]
    pub fn set_keepalive_interval(&mut self, interval: Option<Duration>) {
        self.config_mut().tcp_keepalive_config.interval = interval;
    }

    /// Set the number of retransmissions to be carried out before declaring that remote end is not
    /// available.
    #[inline]
    pub fn set_keepalive_retries(&mut self, retries: Option<u32>) {
        self.config_mut().tcp_keepalive_config.retries = retries;
    }

    /// Set that all sockets have `SO_NODELAY` set to the supplied value `nodelay`.
    ///
    /// Default is `false`.
    #[inline]
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.config_mut().nodelay = nodelay;
    }

    /// Sets the value of the SO_SNDBUF option on the socket.
    #[inline]
    pub fn set_send_buffer_size(&mut self, size: Option<usize>) {
        self.config_mut().send_buffer_size = size;
    }

    /// Sets the value of the SO_RCVBUF option on the socket.
    #[inline]
    pub fn set_recv_buffer_size(&mut self, size: Option<usize>) {
        self.config_mut().recv_buffer_size = size;
    }

    /// Set the connect options to be used when connecting.
    #[inline]
    pub fn set_connect_options(&mut self, opts: TcpConnectOptions) {
        let this = self.config_mut();

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
        if let Some(interface) = opts.interface {
            this.tcp_connect_options.interface = Some(interface);
        }

        if let Some(local_ipv4) = opts.local_ipv4 {
            this.tcp_connect_options
                .set_local_address(Some(local_ipv4.into()));
        }

        if let Some(local_ipv6) = opts.local_ipv6 {
            this.tcp_connect_options
                .set_local_address(Some(local_ipv6.into()));
        }
    }

    /// Set the connect timeout.
    ///
    /// If a domain resolves to multiple IP addresses, the timeout will be
    /// evenly divided across them.
    ///
    /// Default is `None`.
    #[inline]
    pub fn set_connect_timeout(&mut self, dur: Option<Duration>) {
        self.config_mut().connect_timeout = dur;
    }

    /// Set timeout for [RFC 6555 (Happy Eyeballs)][RFC 6555] algorithm.
    ///
    /// If hostname resolves to both IPv4 and IPv6 addresses and connection
    /// cannot be established using preferred address family before timeout
    /// elapses, then connector will in parallel attempt connection using other
    /// address family.
    ///
    /// If `None`, parallel connection attempts are disabled.
    ///
    /// Default is 300 milliseconds.
    ///
    /// [RFC 6555]: https://tools.ietf.org/html/rfc6555
    #[inline]
    pub fn set_happy_eyeballs_timeout(&mut self, dur: Option<Duration>) {
        self.config_mut().happy_eyeballs_timeout = dur;
    }

    /// Set that all socket have `SO_REUSEADDR` set to the supplied value `reuse_address`.
    ///
    /// Default is `false`.
    #[inline]
    pub fn set_reuse_address(&mut self, reuse_address: bool) -> &mut Self {
        self.config_mut().reuse_address = reuse_address;
        self
    }

    /// Sets the value of the TCP_USER_TIMEOUT option on the socket.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[inline]
    pub fn set_tcp_user_timeout(&mut self, time: Option<Duration>) {
        self.config_mut().tcp_user_timeout = time;
    }

    // private

    fn config_mut(&mut self) -> &mut Config {
        // If the are HttpConnector clones, this will clone the inner
        // config. So mutating the config won't ever affect previous
        // clones.
        Arc::make_mut(&mut self.config)
    }
}

static INVALID_NOT_HTTP: &str = "invalid URI, scheme is not http";
static INVALID_MISSING_SCHEME: &str = "invalid URI, scheme is missing";
static INVALID_MISSING_HOST: &str = "invalid URI, host is missing";

// R: Debug required for now to allow adding it to debug output later...
impl<R: fmt::Debug> fmt::Debug for HttpConnector<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpConnector").finish()
    }
}

impl<R> tower::Service<Uri> for HttpConnector<R>
where
    R: InternalResolve + Clone + Send + Sync + 'static,
    R::Future: Send,
{
    type Response = TcpStream;
    type Error = ConnectError;
    type Future = HttpConnecting<R>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.resolver.poll_ready(cx).map_err(ConnectError::dns)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let mut self_ = self.clone();
        HttpConnecting {
            fut: Box::pin(async move { self_.call_async(dst).await }),
            _marker: PhantomData,
        }
    }
}

fn get_host_port<'u>(config: &Config, dst: &'u Uri) -> Result<(&'u str, u16), ConnectError> {
    trace!(
        "Http::connect; scheme={:?}, host={:?}, port={:?}",
        dst.scheme(),
        dst.host(),
        dst.port(),
    );

    if config.enforce_http {
        if dst.scheme() != Some(&Scheme::HTTP) {
            return Err(ConnectError {
                msg: INVALID_NOT_HTTP,
                addr: None,
                cause: None,
            });
        }
    } else if dst.scheme().is_none() {
        return Err(ConnectError {
            msg: INVALID_MISSING_SCHEME,
            addr: None,
            cause: None,
        });
    }

    let host = match dst.host() {
        Some(s) => s,
        None => {
            return Err(ConnectError {
                msg: INVALID_MISSING_HOST,
                addr: None,
                cause: None,
            });
        }
    };
    let port = match dst.port() {
        Some(port) => port.as_u16(),
        None => {
            if dst.scheme() == Some(&Scheme::HTTPS) {
                443
            } else {
                80
            }
        }
    };

    Ok((host, port))
}

impl<R> HttpConnector<R>
where
    R: InternalResolve,
{
    async fn call_async(&mut self, dst: Uri) -> Result<TcpStream, ConnectError> {
        let config = &self.config;

        let (host, port) = get_host_port(config, &dst)?;
        let host = host.trim_start_matches('[').trim_end_matches(']');

        // If the host is already an IP addr (v4 or v6),
        // skip resolving the dns and start connecting right away.
        let addrs = if let Some(addrs) = dns::SocketAddrs::try_parse(host, port) {
            addrs
        } else {
            let addrs = resolve(&mut self.resolver, dns::Name::new(host.into()))
                .await
                .map_err(ConnectError::dns)?;
            let addrs = addrs
                .map(|mut addr| {
                    set_port(&mut addr, port, dst.port().is_some());
                    addr
                })
                .collect();
            dns::SocketAddrs::new(addrs)
        };

        let c = ConnectingTcp::new(addrs, config);

        let sock = c.connect().await?;

        if let Err(_e) = sock.set_nodelay(config.nodelay) {
            warn!("tcp set_nodelay error: {_e}");
        }

        Ok(sock)
    }
}

impl Connection for TcpStream {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        if let (Ok(remote_addr), Ok(local_addr)) = (self.peer_addr(), self.local_addr()) {
            connected.extra(HttpInfo {
                remote_addr,
                local_addr,
            })
        } else {
            connected
        }
    }
}

impl HttpInfo {
    /// Get the remote address of the transport used.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the local address of the transport used.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

pin_project! {
    // Not publicly exported (so missing_docs doesn't trigger).
    //
    // We return this `Future` instead of the `Pin<Box<dyn Future>>` directly
    // so that users don't rely on it fitting in a `Pin<Box<dyn Future>>` slot
    // (and thus we can change the type in the future).
    #[must_use = "futures do nothing unless polled"]
    pub struct HttpConnecting<R> {
        #[pin]
        fut: BoxConnecting,
        _marker: PhantomData<R>,
    }
}

type ConnectResult = Result<TcpStream, ConnectError>;
type BoxConnecting = Pin<Box<dyn Future<Output = ConnectResult> + Send>>;

impl<R: InternalResolve> Future for HttpConnecting<R> {
    type Output = ConnectResult;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}

// Not publicly exported (so missing_docs doesn't trigger).
pub struct ConnectError {
    msg: &'static str,
    addr: Option<SocketAddr>,
    cause: Option<BoxError>,
}

impl ConnectError {
    fn new<E>(msg: &'static str, cause: E) -> ConnectError
    where
        E: Into<BoxError>,
    {
        ConnectError {
            msg,
            addr: None,
            cause: Some(cause.into()),
        }
    }

    fn dns<E>(cause: E) -> ConnectError
    where
        E: Into<BoxError>,
    {
        ConnectError::new("dns error", cause)
    }

    fn m<E>(msg: &'static str) -> impl FnOnce(E) -> ConnectError
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

struct ConnectingTcp<'a> {
    preferred: ConnectingTcpRemote,
    fallback: Option<ConnectingTcpFallback>,
    config: &'a Config,
}

impl<'a> ConnectingTcp<'a> {
    fn new(remote_addrs: dns::SocketAddrs, config: &'a Config) -> Self {
        if let Some(fallback_timeout) = config.happy_eyeballs_timeout {
            let (preferred_addrs, fallback_addrs) = remote_addrs.split_by_preference(
                config.tcp_connect_options.local_ipv4,
                config.tcp_connect_options.local_ipv6,
            );
            if fallback_addrs.is_empty() {
                return ConnectingTcp {
                    preferred: ConnectingTcpRemote::new(preferred_addrs, config.connect_timeout),
                    fallback: None,
                    config,
                };
            }

            ConnectingTcp {
                preferred: ConnectingTcpRemote::new(preferred_addrs, config.connect_timeout),
                fallback: Some(ConnectingTcpFallback {
                    delay: tokio::time::sleep(fallback_timeout),
                    remote: ConnectingTcpRemote::new(fallback_addrs, config.connect_timeout),
                }),
                config,
            }
        } else {
            ConnectingTcp {
                preferred: ConnectingTcpRemote::new(remote_addrs, config.connect_timeout),
                fallback: None,
                config,
            }
        }
    }
}

struct ConnectingTcpFallback {
    delay: Sleep,
    remote: ConnectingTcpRemote,
}

struct ConnectingTcpRemote {
    addrs: dns::SocketAddrs,
    connect_timeout: Option<Duration>,
}

impl ConnectingTcpRemote {
    fn new(addrs: dns::SocketAddrs, connect_timeout: Option<Duration>) -> Self {
        let connect_timeout = connect_timeout.and_then(|t| t.checked_div(addrs.len() as u32));

        Self {
            addrs,
            connect_timeout,
        }
    }
}

impl ConnectingTcpRemote {
    async fn connect(&mut self, config: &Config) -> Result<TcpStream, ConnectError> {
        let mut err = None;
        for addr in &mut self.addrs {
            debug!("connecting to {}", addr);
            match connect(&addr, config, self.connect_timeout)?.await {
                Ok(tcp) => {
                    debug!("connected to {}", addr);
                    return Ok(tcp);
                }
                Err(mut e) => {
                    e.addr = Some(addr);
                    // Only return the first error; assume it’s the most relevant.
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
                io::Error::new(io::ErrorKind::NotConnected, "Network unreachable"),
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

fn connect(
    addr: &SocketAddr,
    config: &Config,
    connect_timeout: Option<Duration>,
) -> Result<impl Future<Output = Result<TcpStream, ConnectError>>, ConnectError> {
    // TODO(eliza): if Tokio's `TcpSocket` gains support for setting the
    // keepalive timeout, it would be nice to use that instead of socket2,
    // and avoid the unsafe `into_raw_fd`/`from_raw_fd` dance...
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
    if let Some(interface) = &config.tcp_connect_options.interface {
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
        {
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
        &config.tcp_connect_options.local_ipv4,
        &config.tcp_connect_options.local_ipv6,
    )
    .map_err(ConnectError::m("tcp bind local error"))?;

    // Safely convert socket2::Socket to tokio TcpSocket.
    let socket = TcpSocket::from_std_stream(socket.into());

    if config.reuse_address {
        if let Err(_e) = socket.set_reuseaddr(true) {
            warn!("tcp set_reuse_address error: {_e}");
        }
    }

    if let Some(size) = config.send_buffer_size {
        if let Err(_e) = socket.set_send_buffer_size(size.try_into().unwrap_or(u32::MAX)) {
            warn!("tcp set_buffer_size error: {_e}");
        }
    }

    if let Some(size) = config.recv_buffer_size {
        if let Err(_e) = socket.set_recv_buffer_size(size.try_into().unwrap_or(u32::MAX)) {
            warn!("tcp set_recv_buffer_size error: {_e}");
        }
    }

    let connect = socket.connect(*addr);
    Ok(async move {
        match connect_timeout {
            Some(dur) => match tokio::time::timeout(dur, connect).await {
                Ok(Ok(s)) => Ok(s),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(io::Error::new(io::ErrorKind::TimedOut, e)),
            },
            None => connect.await,
        }
        .map_err(ConnectError::m("tcp connect error"))
    })
}

impl ConnectingTcp<'_> {
    async fn connect(mut self) -> Result<TcpStream, ConnectError> {
        match self.fallback {
            None => self.preferred.connect(self.config).await,
            Some(mut fallback) => {
                let preferred_fut = self.preferred.connect(self.config);
                futures_util::pin_mut!(preferred_fut);

                let fallback_fut = fallback.remote.connect(self.config);
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

/// Respect explicit ports in the URI, if none, either
/// keep non `0` ports resolved from a custom dns resolver,
/// or use the default port for the scheme.
fn set_port(addr: &mut SocketAddr, host_port: u16, explicit: bool) {
    if explicit || addr.port() == 0 {
        addr.set_port(host_port)
    };
}
