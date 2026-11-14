//! TCP socket options and the socket setup for each address the dialer races.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use http::uri::Uri;
use socket2::TcpKeepalive;

use super::{ConnectError, bind_interface};
use crate::{
    ext::UriExt,
    rt::{Connecting, DynRuntime},
};

static INVALID_MISSING_SCHEME: &str = "invalid URI, scheme is missing";
static INVALID_MISSING_HOST: &str = "invalid URI, host is missing";

/// Socket options the client applies to every TCP dial.
pub(crate) struct Config {
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

pub(super) fn get_host_port(dst: &Uri) -> Result<(&str, u16), ConnectError> {
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

/// Opens a nonblocking TCP socket with the client's options and the dial's bindings, and
/// starts connecting it on the runtime.
pub(super) fn connect_socket(
    addr: &SocketAddr,
    config: &Config,
    addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),
    interface: Option<&str>,
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

    bind_interface(&socket, *addr, interface)
        .map_err(ConnectError::m("tcp bind interface error"))?;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(tcp_user_timeout) = &config.tcp_user_timeout
        && let Err(_e) = socket.set_tcp_user_timeout(Some(*tcp_user_timeout))
    {
        warn!("tcp set_tcp_user_timeout error: {_e}");
    }

    bind_local_address(&socket, addr, &addresses.0, &addresses.1)
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

// ===== impl Config =====

impl Config {
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

impl Default for Config {
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
