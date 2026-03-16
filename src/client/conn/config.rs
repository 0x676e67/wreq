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
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use socket2::TcpKeepalive;

/// Options for configuring socket bind behavior for outbound connections.
///
/// `SocketBindOptions` allows fine-grained control over how sockets
/// are bound before use. It can be used to:
///
/// - Bind a socket to a specific **network interface**
/// - Bind to a **local IPv4 or IPv6 address**
///
/// This is especially useful for scenarios involving:
/// - Virtual routing tables (e.g. Linux VRFs)
/// - Multiple NICs (network interface cards)
/// - Explicit source IP routing or firewall rules
///
/// Platform-specific behavior is handled internally, with the interface-binding
/// mechanism differing across operating systems.
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
    pub(crate) interface: Option<Cow<'static, str>>,
    pub(crate) local_address_ipv4: Option<Ipv4Addr>,
    pub(crate) local_address_ipv6: Option<Ipv6Addr>,
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
    pub fn set_local_address(&mut self, local_addr: Option<IpAddr>) {
        match local_addr {
            Some(IpAddr::V4(a)) => {
                self.local_address_ipv4 = Some(a);
            }
            Some(IpAddr::V6(a)) => {
                self.local_address_ipv6 = Some(a);
            }
            _ => {}
        };

        let (v4, v6) = match local_addr {
            Some(IpAddr::V4(a)) => (Some(a), None),
            Some(IpAddr::V6(a)) => (None, Some(a)),
            _ => (None, None),
        };

        self.local_address_ipv4 = v4;
        self.local_address_ipv6 = v6;
    }

    /// Set that all sockets are bound to the configured IPv4 or IPv6 address (depending on host's
    /// preferences) before connection.
    #[inline]
    pub fn set_local_addresses<V4, V6>(&mut self, local_ipv4: V4, local_ipv6: V6)
    where
        V4: Into<Option<Ipv4Addr>>,
        V6: Into<Option<Ipv6Addr>>,
    {
        self.local_address_ipv4 = local_ipv4.into();
        self.local_address_ipv6 = local_ipv6.into();
    }
}

#[derive(Clone)]
pub(crate) struct TcpOptions {
    pub connect_timeout: Option<Duration>,
    pub enforce_http: bool,
    pub happy_eyeballs_timeout: Option<Duration>,
    pub tcp_keepalive_config: TcpKeepaliveOptions,
    pub socket_bind_options: SocketBindOptions,
    pub nodelay: bool,
    pub reuse_address: bool,
    pub send_buffer_size: Option<usize>,
    pub recv_buffer_size: Option<usize>,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub tcp_user_timeout: Option<Duration>,
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
