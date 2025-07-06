use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
pub struct TcpConnectOptions {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub(super) interface: Option<std::borrow::Cow<'static, str>>,
    #[cfg(any(
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    pub(super) interface: Option<std::ffi::CString>,
    pub(super) local_ipv4: Option<Ipv4Addr>,
    pub(super) local_ipv6: Option<Ipv6Addr>,
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
        S: Into<Option<std::borrow::Cow<'static, str>>>,
    {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            self.interface = interface.into();
        }

        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        {
            self.interface = interface
                .into()
                .and_then(|iface| std::ffi::CString::new(iface.into_owned()).ok());
        }

        self
    }

    /// Sets the local address the socket will bind to before connecting.
    ///
    /// If an address is provided, the socket will explicitly bind to it,
    /// ensuring that the outgoing connection uses this address as the source.
    ///
    /// - If an `Ipv4Addr` is given, it will set `local_ipv4` and clear `local_ipv6`.
    /// - If an `Ipv6Addr` is given, it will set `local_ipv6` and clear `local_ipv4`.
    ///
    /// If `None` is passed, both addresses are cleared and the OS will choose automatically.
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

    /// Sets both local IPv4 and IPv6 addresses explicitly.
    ///
    /// Use this method to assign both address families independently.
    ///
    /// If either argument is `None`, the socket will not be bound for that protocol.
    #[inline]
    pub fn set_local_addresses(
        &mut self,
        local_ipv4: Option<Ipv4Addr>,
        local_ipv6: Option<Ipv6Addr>,
    ) {
        self.local_ipv4 = local_ipv4;
        self.local_ipv6 = local_ipv6;
    }
}
