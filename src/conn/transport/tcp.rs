//! URI resolution, TCP socket configuration and runtime connection setup.
//! Address ordering and racing use the shared transport policy; the connector sets the deadline.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_util::{TryFutureExt, future::BoxFuture};
use http::uri::Uri;
use socket2::TcpKeepalive;

use super::{BindOptions, ConnectError, race, resolve};
use crate::{
    conn::{Connected, Connection, HttpInfo, TlsInfoFactory},
    dns::{self, DynResolver},
    error::BoxError,
    ext::UriExt,
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

/// Client socket options, bindings, the resolver and the runtime shared by every dial.
struct Inner {
    config: TcpConfig,
    bind_options: BindOptions,
    happy_eyeballs_timeout: Option<Duration>,
    resolver: DynResolver,
    runtime: DynRuntime,
}

/// Socket options the client applies to every TCP dial.
pub(crate) struct TcpConfig {
    pub(crate) nodelay: bool,
    pub(crate) reuse_address: bool,
    pub(crate) linger: Option<Duration>,
    pub(crate) send_buffer_size: Option<usize>,
    pub(crate) recv_buffer_size: Option<usize>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub(crate) tcp_user_timeout: Option<Duration>,
    pub(crate) keepalive: Option<Duration>,
    pub(crate) keepalive_interval: Option<Duration>,
    pub(crate) keepalive_retries: Option<u32>,
}

// ===== impl TcpConnector =====

impl TcpConnector {
    /// Creates a connector dialing with the client's socket options and bindings, racing
    /// addresses `happy_eyeballs_timeout` apart.
    pub(crate) fn new(
        runtime: DynRuntime,
        resolver: DynResolver,
        config: TcpConfig,
        bind_options: BindOptions,
        happy_eyeballs_timeout: Option<Duration>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                bind_options,
                happy_eyeballs_timeout,
                resolver,
                runtime,
            }),
        }
    }

    /// Returns whether the client disables Nagle.
    #[inline]
    pub(crate) fn nodelay(&self) -> bool {
        self.inner.config.nodelay
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
            let bind_options = bind_options.as_deref().unwrap_or(&inner.bind_options);
            Ok(connect(addrs, &inner, bind_options, nodelay).await?)
        })
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
            terminal: false,
        });
    }

    let host = match dst.host() {
        Some(s) => s,
        None => {
            return Err(ConnectError {
                msg: INVALID_MISSING_HOST,
                addr: None,
                cause: None,
                terminal: false,
            });
        }
    };
    Ok((host, dst.port_or_default()))
}

/// Connects resolved candidates using the shared network policy.
async fn connect(
    addrs: dns::SocketAddrs,
    inner: &Inner,
    bind_options: &BindOptions,
    nodelay: bool,
) -> Result<BoxConnection, ConnectError> {
    race(
        addrs,
        bind_options,
        inner.happy_eyeballs_timeout,
        |addr| {
            connect_socket(&addr, &inner.config, bind_options, nodelay, &inner.runtime)
                .map(|future| future.map_err(ConnectError::m("tcp connect error")))
        },
        |duration| inner.runtime.sleep(duration),
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
    config: &TcpConfig,
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

    if let Some(tcp_keepalive) = &config.tcp_keepalive()
        && let Err(_e) = socket.set_tcp_keepalive(tcp_keepalive)
    {
        warn!("tcp set_keepalive error: {_e}");
    }

    bind_options
        .bind_interface(&socket, *addr)
        .map_err(ConnectError::m("tcp bind interface error"))?;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(tcp_user_timeout) = &config.tcp_user_timeout
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

    if let Err(_e) = socket.set_tcp_nodelay(nodelay) {
        warn!("tcp set_tcp_nodelay error: {_e}");
    }

    Ok(runtime.connect_tcp(socket.into(), *addr))
}

// ===== impl TcpConfig =====

impl TcpConfig {
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

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            nodelay: true,
            reuse_address: false,
            linger: None,
            send_buffer_size: None,
            recv_buffer_size: None,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            tcp_user_timeout: Some(Duration::from_secs(30)),
            keepalive: Some(Duration::from_secs(15)),
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_retries: Some(3),
        }
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
