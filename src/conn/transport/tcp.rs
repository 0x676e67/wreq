//! URI resolution, TCP socket configuration and runtime connection setup.
//! Address ordering, racing and deadlines use the shared transport policy.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use futures_util::{TryFutureExt, future::BoxFuture};
use http::uri::{Scheme, Uri};
use socket2::TcpKeepalive;
use tower::Service;

use super::{BindOptions, ConnectError, ConnectOptions, resolve};
use crate::{
    conn::{Connected, Connection, HttpInfo, TlsInfoFactory},
    dns::{self, DnsResolver},
    rt::{BoxConnection, Connecting, RuntimeHandle, Timer as _},
};

static INVALID_NOT_HTTP: &str = "invalid URI, scheme is not http";
static INVALID_MISSING_SCHEME: &str = "invalid URI, scheme is missing";
static INVALID_MISSING_HOST: &str = "invalid URI, host is missing";

/// Resolves URI targets and races configured TCP sockets using the selected runtime.
/// Clones share socket settings until a caller changes them.
/// Configure `TcpConnector<()>`, then attach a resolver with [`Self::build`].
#[must_use]
#[derive(Clone)]
pub(crate) struct TcpConnector<R> {
    options: Arc<TcpOptions>,
    resolver: R,
    runtime: RuntimeHandle,
}

#[derive(Clone)]
pub(crate) struct TcpOptions {
    pub enforce_http: bool,
    pub connect: ConnectOptions,
    pub nodelay: bool,
    pub reuse_address: bool,
    pub linger: Option<Duration>,
    pub send_buffer_size: Option<usize>,
    pub recv_buffer_size: Option<usize>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub tcp_user_timeout: Option<Duration>,
    pub keepalive: Option<Duration>,
    pub keepalive_interval: Option<Duration>,
    pub keepalive_retries: Option<u32>,
    pub bind_options: BindOptions,
}

// ===== impl TcpConnector =====

impl TcpConnector<()> {
    /// Starts configuring a TCP connector using the shared runtime.
    pub(crate) fn new(runtime: RuntimeHandle) -> Self {
        Self {
            options: Arc::new(TcpOptions {
                enforce_http: true,
                connect: ConnectOptions::default(),
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
            }),
            resolver: (),
            runtime,
        }
    }

    /// Attaches a resolver without cloning the runtime or socket settings.
    #[inline]
    pub(crate) fn build<R>(self, resolver: R) -> TcpConnector<R> {
        TcpConnector {
            options: self.options,
            resolver,
            runtime: self.runtime,
        }
    }
}

impl<R> TcpConnector<R> {
    fn config_mut(&mut self) -> &mut TcpOptions {
        // Keep existing clones unchanged when updating socket settings.
        Arc::make_mut(&mut self.options)
    }

    /// Returns whether this connector disables Nagle.
    pub(crate) fn nodelay(&self) -> bool {
        self.options.nodelay
    }

    /// Requires the `http` URI scheme when enabled, as it is by default.
    #[inline]
    pub(crate) fn enforce_http(mut self, is_enforced: bool) -> Self {
        self.config_mut().enforce_http = is_enforced;
        self
    }

    /// Sets `TCP_NODELAY` on each socket. Defaults to `false`.
    #[inline]
    pub(crate) fn set_nodelay(mut self, nodelay: bool) -> Self {
        self.config_mut().nodelay = nodelay;
        self
    }

    /// Sets the socket send buffer size (`SO_SNDBUF`).
    #[inline]
    pub(crate) fn set_send_buffer_size(mut self, size: Option<usize>) -> Self {
        self.config_mut().send_buffer_size = size;
        self
    }

    /// Sets the socket receive buffer size (`SO_RCVBUF`).
    #[inline]
    pub(crate) fn set_recv_buffer_size(mut self, size: Option<usize>) -> Self {
        self.config_mut().recv_buffer_size = size;
        self
    }

    /// Sets `SO_REUSEADDR` on each socket. Defaults to `false`.
    #[inline]
    pub(crate) fn set_reuse_address(mut self, reuse_address: bool) -> Self {
        self.config_mut().reuse_address = reuse_address;
        self
    }

    /// Sets `SO_LINGER`. The default, `None`, leaves the socket option unchanged.
    #[inline]
    pub(crate) fn set_linger(mut self, linger: Option<Duration>) -> Self {
        self.config_mut().linger = linger;
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
            self.config_mut().tcp_user_timeout = time;
        }
        self
    }

    /// Sets the timeout for the TCP connection race, after DNS resolution.
    /// Defaults to `None`; the outer connector also applies its overall connection timeout.
    #[inline]
    pub(crate) fn set_connect_timeout(mut self, dur: Option<Duration>) -> Self {
        self.config_mut().connect.timeout = dur;
        self
    }

    /// Sets the delay between overlapping attempts; defaults to 300 milliseconds.
    /// The first starts immediately. `None` tries addresses sequentially.
    /// See [RFC 8305 section 5](https://www.rfc-editor.org/rfc/rfc8305.html#section-5).
    #[inline]
    pub(crate) fn set_happy_eyeballs_timeout(mut self, dur: Option<Duration>) -> Self {
        self.config_mut().connect.happy_eyeballs_timeout = dur;
        self
    }

    /// Sets the idle time before sending TCP keepalive probes.
    /// Defaults to `None`; any keepalive option supported by the platform enables `SO_KEEPALIVE`.
    #[inline]
    pub(crate) fn set_keepalive(mut self, time: Option<Duration>) -> Self {
        self.config_mut().keepalive = time;
        self
    }

    /// Sets the interval between unanswered TCP keepalive probes.
    #[inline]
    pub(crate) fn set_keepalive_interval(mut self, interval: Option<Duration>) -> Self {
        self.config_mut().keepalive_interval = interval;
        self
    }

    /// Sets how many unanswered TCP keepalive probes cause the connection to fail.
    #[inline]
    pub(crate) fn set_keepalive_retries(mut self, retries: Option<u32>) -> Self {
        self.config_mut().keepalive_retries = retries;
        self
    }

    /// Applies local addresses and interface, preserving unspecified bindings.
    #[inline]
    pub(crate) fn set_bind_options(mut self, options: &BindOptions) -> Self {
        self.config_mut().bind_options.merge(options);
        self
    }
}

impl<R> Service<Uri> for TcpConnector<R>
where
    R: DnsResolver + Clone + Send + Sync + 'static,
    R::Future: Send,
{
    type Response = BoxConnection;
    type Error = ConnectError;
    type Future = BoxFuture<'static, Result<BoxConnection, ConnectError>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.resolver.poll_ready(cx).map_err(ConnectError::dns)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let mut this = self.clone();

        Box::pin(async move {
            let (host, port) = get_host_port(&this.options, &dst)?;
            let addrs = resolve(&mut this.resolver, host, port, dst.port().is_some()).await?;
            connect(addrs, &this.options, this.runtime).await
        })
    }
}

fn get_host_port<'u>(options: &TcpOptions, dst: &'u Uri) -> Result<(&'u str, u16), ConnectError> {
    trace!(
        "Http::connect; scheme={:?}, host={:?}, port={:?}",
        dst.scheme(),
        dst.host(),
        dst.port(),
    );

    if options.enforce_http {
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

/// Connects resolved candidates using the shared network policy.
async fn connect(
    addrs: dns::SocketAddrs,
    config: &TcpOptions,
    runtime: RuntimeHandle,
) -> Result<BoxConnection, ConnectError> {
    config
        .connect
        .connect(
            addrs,
            &config.bind_options,
            |addr| {
                connect_socket(&addr, config, &runtime)
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
    config: &TcpOptions,
    runtime: &RuntimeHandle,
) -> Result<Connecting, ConnectError> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = Domain::for_address(*addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(ConnectError::m("tcp open error"))?;

    // Supply a nonblocking socket to the selected runtime.
    socket
        .set_nonblocking(true)
        .map_err(ConnectError::m("tcp set_nonblocking error"))?;

    if let Some(tcp_keepalive) = &config.tcp_keepalive()
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
    if let Some(interface) = &config.bind_options.interface {
        super::bind_interface(&socket, *addr, interface)
            .map_err(ConnectError::m("tcp bind interface error"))?;
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(tcp_user_timeout) = &config.tcp_user_timeout
        && let Err(_e) = socket.set_tcp_user_timeout(Some(*tcp_user_timeout))
    {
        warn!("tcp set_tcp_user_timeout error: {_e}");
    }

    bind_local_address(
        &socket,
        addr,
        &config.bind_options.ipv4_address,
        &config.bind_options.ipv6_address,
    )
    .map_err(ConnectError::m("tcp bind local error"))?;

    if config.reuse_address
        && let Err(_e) = socket.set_reuse_address(true)
    {
        warn!("tcp set_reuse_address error: {_e}");
    }

    if let Some(linger) = config.linger
        && let Err(_e) = socket.set_linger(Some(linger))
    {
        warn!("tcp set_linger error: {_e}");
    }

    if let Some(size) = config.send_buffer_size
        && let Err(_e) = socket.set_send_buffer_size(size)
    {
        warn!("tcp set_buffer_size error: {_e}");
    }

    if let Some(size) = config.recv_buffer_size
        && let Err(_e) = socket.set_recv_buffer_size(size)
    {
        warn!("tcp set_recv_buffer_size error: {_e}");
    }

    if let Err(_e) = socket.set_tcp_nodelay(config.nodelay) {
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
