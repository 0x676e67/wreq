//! URI resolution, TCP socket configuration and runtime connection setup.
//! Address ordering and racing use the shared transport policy; the connector sets the deadline.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_util::{TryFutureExt, future::BoxFuture};
use http::uri::{Scheme, Uri};
use socket2::TcpKeepalive;

use super::{BindOptions, ConnectError, ConnectOptions, resolve};
use crate::{
    conn::{Connected, Connection, HttpInfo, TlsInfoFactory},
    dns::{self, DynResolver},
    error::BoxError,
    rt::{BoxConnection, Connecting, DynRuntime, Timer as _},
};

static INVALID_MISSING_SCHEME: &str = "invalid URI, scheme is missing";
static INVALID_MISSING_HOST: &str = "invalid URI, host is missing";

/// Resolves URI targets and races configured TCP sockets using the selected runtime.
/// Clones share the socket settings, resolver and runtime; each dial takes its own
/// `TCP_NODELAY` and bindings.
#[derive(Clone)]
pub(crate) struct TcpConnector {
    inner: Arc<Inner>,
}

/// Client socket settings, the resolver and the runtime shared by every dial.
struct Inner {
    options: TcpOptions,
    resolver: DynResolver,
    runtime: DynRuntime,
}

/// Configures TCP sockets before attaching a resolver with [`Self::build`].
#[must_use]
pub(crate) struct TcpConnectorBuilder {
    options: TcpOptions,
    runtime: DynRuntime,
}

/// Socket settings the client applies to every TCP dial.
struct TcpOptions {
    connect_options: ConnectOptions,
    nodelay: bool,
    reuse_address: bool,
    linger: Option<Duration>,
    send_buffer_size: Option<usize>,
    recv_buffer_size: Option<usize>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    tcp_user_timeout: Option<Duration>,
    keepalive: Option<Duration>,
    keepalive_interval: Option<Duration>,
    keepalive_retries: Option<u32>,
    bind_options: BindOptions,
}

// ===== impl TcpConnector =====

impl TcpConnector {
    /// Starts configuring a TCP connector using the shared runtime.
    pub(crate) fn builder(runtime: DynRuntime) -> TcpConnectorBuilder {
        TcpConnectorBuilder {
            options: TcpOptions {
                connect_options: ConnectOptions::default(),
                nodelay: false,
                reuse_address: false,
                linger: None,
                send_buffer_size: None,
                recv_buffer_size: None,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                tcp_user_timeout: None,
                keepalive: None,
                keepalive_interval: None,
                keepalive_retries: None,
                bind_options: BindOptions::default(),
            },
            runtime,
        }
    }

    /// Returns whether the client disables Nagle.
    #[inline]
    pub(crate) fn nodelay(&self) -> bool {
        self.inner.options.nodelay
    }

    /// Returns the address-race policy that QUIC dials share.
    #[cfg(feature = "http3")]
    #[inline]
    pub(crate) fn connect_options(&self) -> ConnectOptions {
        self.inner.options.connect_options
    }

    /// Resolves `uri` and races its addresses with this dial's `TCP_NODELAY` and bindings.
    /// Request bindings of `None` keep the client's.
    pub(crate) fn dial(
        &self,
        uri: Uri,
        nodelay: bool,
        bind_options: Option<Arc<BindOptions>>,
    ) -> BoxFuture<'static, Result<BoxConnection, BoxError>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let (host, port) = get_host_port(&uri)?;
            let addrs = resolve(host, port, uri.port().is_some(), |name| {
                inner.resolver.resolve(name)
            })
            .await?;
            let bind_options = bind_options
                .as_deref()
                .unwrap_or(&inner.options.bind_options);
            Ok(connect(addrs, &inner.options, bind_options, nodelay, &inner.runtime).await?)
        })
    }
}

// ===== impl TcpConnectorBuilder =====

impl TcpConnectorBuilder {
    /// Sets `TCP_NODELAY` on each socket. Defaults to `false`.
    #[inline]
    pub(crate) fn set_nodelay(mut self, nodelay: bool) -> Self {
        self.options.nodelay = nodelay;
        self
    }

    /// Sets the socket send buffer size (`SO_SNDBUF`).
    #[inline]
    pub(crate) fn set_send_buffer_size(mut self, size: Option<usize>) -> Self {
        self.options.send_buffer_size = size;
        self
    }

    /// Sets the socket receive buffer size (`SO_RCVBUF`).
    #[inline]
    pub(crate) fn set_recv_buffer_size(mut self, size: Option<usize>) -> Self {
        self.options.recv_buffer_size = size;
        self
    }

    /// Sets `SO_REUSEADDR` on each socket. Defaults to `false`.
    #[inline]
    pub(crate) fn set_reuse_address(mut self, reuse_address: bool) -> Self {
        self.options.reuse_address = reuse_address;
        self
    }

    /// Sets `SO_LINGER`. The default, `None`, leaves the socket option unchanged.
    #[inline]
    pub(crate) fn set_linger(mut self, linger: Option<Duration>) -> Self {
        self.options.linger = linger;
        self
    }

    /// Sets `TCP_USER_TIMEOUT` on each socket.
    /// Takes no argument on platforms without this option.
    #[inline]
    pub(crate) fn set_tcp_user_timeout(
        #[cfg_attr(
            not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")),
            expect(unused_mut, reason = "Only supported platforms update this option")
        )]
        mut self,
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))] time: Option<
            Duration,
        >,
    ) -> Self {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            self.options.tcp_user_timeout = time;
        }
        self
    }

    /// Sets the delay between overlapping attempts; defaults to 300 milliseconds.
    /// The first starts immediately. `None` tries addresses sequentially.
    /// See [RFC 8305 section 5](https://www.rfc-editor.org/rfc/rfc8305.html#section-5).
    #[inline]
    pub(crate) fn set_happy_eyeballs_timeout(mut self, dur: Option<Duration>) -> Self {
        self.options.connect_options.happy_eyeballs_timeout = dur;
        self
    }

    /// Sets the idle time before sending TCP keepalive probes.
    /// Defaults to `None`; any keepalive option supported by the platform enables `SO_KEEPALIVE`.
    #[inline]
    pub(crate) fn set_keepalive(mut self, time: Option<Duration>) -> Self {
        self.options.keepalive = time;
        self
    }

    /// Sets the interval between unanswered TCP keepalive probes.
    #[inline]
    pub(crate) fn set_keepalive_interval(mut self, interval: Option<Duration>) -> Self {
        self.options.keepalive_interval = interval;
        self
    }

    /// Sets how many unanswered TCP keepalive probes cause the connection to fail.
    #[inline]
    pub(crate) fn set_keepalive_retries(mut self, retries: Option<u32>) -> Self {
        self.options.keepalive_retries = retries;
        self
    }

    /// Sets the client's local addresses and interface for each socket.
    #[inline]
    pub(crate) fn set_bind_options(mut self, bind_options: &BindOptions) -> Self {
        self.options.bind_options = bind_options.clone();
        self
    }

    /// Attaches the resolver and freezes the socket settings.
    #[inline]
    pub(crate) fn build(self, resolver: DynResolver) -> TcpConnector {
        TcpConnector {
            inner: Arc::new(Inner {
                options: self.options,
                resolver,
                runtime: self.runtime,
            }),
        }
    }
}

fn get_host_port(dst: &Uri) -> Result<(&str, u16), ConnectError> {
    trace!(
        "Http::connect; scheme={:?}, host={:?}, port={:?}",
        dst.scheme(),
        dst.host(),
        dst.port(),
    );

    if dst.scheme().is_none() {
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

/// Connects resolved candidates using the shared network policy.
async fn connect(
    addrs: dns::SocketAddrs,
    options: &TcpOptions,
    bind_options: &BindOptions,
    nodelay: bool,
    runtime: &DynRuntime,
) -> Result<BoxConnection, ConnectError> {
    options
        .connect_options
        .connect(
            addrs,
            bind_options,
            |addr| {
                connect_socket(&addr, options, bind_options, nodelay, runtime)
                    .map(|future| future.map_err(ConnectError::m("tcp connect error")))
            },
            |duration| runtime.sleep(duration),
        )
        .await
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

fn connect_socket(
    addr: &SocketAddr,
    options: &TcpOptions,
    bind_options: &BindOptions,
    nodelay: bool,
    runtime: &DynRuntime,
) -> Result<Connecting, ConnectError> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = Domain::for_address(*addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(ConnectError::m("tcp open error"))?;

    // Supply a nonblocking socket to the selected runtime.
    socket
        .set_nonblocking(true)
        .map_err(ConnectError::m("tcp set_nonblocking error"))?;

    if let Some(tcp_keepalive) = &options.tcp_keepalive()
        && let Err(_e) = socket.set_tcp_keepalive(tcp_keepalive)
    {
        warn!("tcp set_keepalive error: {_e}");
    }

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
    if let Some(interface) = &bind_options.interface {
        super::bind_interface(&socket, *addr, interface)
            .map_err(ConnectError::m("tcp bind interface error"))?;
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(tcp_user_timeout) = &options.tcp_user_timeout
        && let Err(_e) = socket.set_tcp_user_timeout(Some(*tcp_user_timeout))
    {
        warn!("tcp set_tcp_user_timeout error: {_e}");
    }

    bind_local_address(
        &socket,
        addr,
        &bind_options.ipv4_address,
        &bind_options.ipv6_address,
    )
    .map_err(ConnectError::m("tcp bind local error"))?;

    if options.reuse_address
        && let Err(_e) = socket.set_reuse_address(true)
    {
        warn!("tcp set_reuse_address error: {_e}");
    }

    if let Some(linger) = options.linger
        && let Err(_e) = socket.set_linger(Some(linger))
    {
        warn!("tcp set_linger error: {_e}");
    }

    if let Some(size) = options.send_buffer_size
        && let Err(_e) = socket.set_send_buffer_size(size)
    {
        warn!("tcp set_buffer_size error: {_e}");
    }

    if let Some(size) = options.recv_buffer_size
        && let Err(_e) = socket.set_recv_buffer_size(size)
    {
        warn!("tcp set_recv_buffer_size error: {_e}");
    }

    if let Err(_e) = socket.set_tcp_nodelay(nodelay) {
        warn!("tcp set_tcp_nodelay error: {_e}");
    }

    Ok(runtime.connect_tcp(socket.into(), *addr))
}

// ===== impl TcpOptions =====

impl TcpOptions {
    /// Returns socket keepalive settings when at least one option is configured.
    fn tcp_keepalive(&self) -> Option<TcpKeepalive> {
        let mut dirty = false;
        let mut ka = TcpKeepalive::new();
        if let Some(time) = self.keepalive {
            ka = ka.with_time(time);
            dirty = true
        }

        // Some platforms measure TCP_KEEPINTVL in seconds and truncate subsecond values.
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
            if let Some(interval) = self.keepalive_interval {
                dirty = true;
                ka = ka.with_interval(interval)
            };
        }

        // TCP_KEEPCNT limits unanswered keepalive probes before closing the connection.
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
        if let Some(retries) = self.keepalive_retries {
            dirty = true;
            ka = ka.with_retries(retries)
        };

        if dirty { Some(ka) } else { None }
    }
}

// ===== impl BoxConnection =====

impl Connection for BoxConnection {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        match (self.local_addr(), self.peer_addr()) {
            (Some(local_addr), Some(remote_addr)) => connected.extra(HttpInfo {
                local_addr,
                remote_addr,
            }),
            _ => connected,
        }
    }
    #[inline]
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.peer_addr()
    }
}

impl TlsInfoFactory for BoxConnection {}
