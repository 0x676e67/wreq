use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Options for configuring a TCP network connection.
///
/// `TcpConnectOptions` allows you to specify advanced connection parameters,
/// such as proxy matcher, network interface, and local IP addresses.
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
    pub(super) local_address_ipv4: Option<Ipv4Addr>,
    pub(super) local_address_ipv6: Option<Ipv6Addr>,
}

impl TcpConnectOptions {
    /// Sets the name of the interface to bind sockets produced by this
    /// connector.
    ///
    /// On Linux, this sets the `SO_BINDTODEVICE` option on this socket (see
    /// [`man 7 socket`] for details). On macOS (and macOS-derived systems like
    /// iOS), illumos, and Solaris, this will instead use the `IP_BOUND_IF`
    /// socket option (see [`man 7p ip`]).
    ///
    /// If a socket is bound to an interface, only packets received from that particular
    /// interface are processed by the socket. Note that this only works for some socket
    /// types, particularly `AF_INET`` sockets.
    ///
    /// On Linux it can be used to specify a [VRF], but the binary needs
    /// to either have `CAP_NET_RAW` or to be run as root.
    ///
    /// This function is only available on the following operating systems:
    /// - Linux, including Android
    /// - Fuchsia
    /// - illumos and Solaris
    /// - macOS, iOS, visionOS, watchOS, and tvOS
    ///
    /// [VRF]: https://www.kernel.org/doc/Documentation/networking/vrf.txt
    /// [`man 7 socket`] <https://man7.org/linux/man-pages/man7/socket.7.html>
    /// [`man 7p ip`]: <https://docs.oracle.com/cd/E86824_01/html/E54777/ip-7p.html>
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
        if let Some(interface) = interface.into() {
            let interface = std::ffi::CString::new(interface.into_owned())
                .expect("interface name should not have nulls in it");
            self.interface = Some(interface);
        }
        self
    }

    /// Set that all sockets are bound to the configured address before connection.
    ///
    /// If `None`, the sockets will not be bound.
    ///
    /// Default is `None`.
    #[inline]
    pub fn set_local_address(&mut self, addr: Option<IpAddr>) {
        let (v4, v6) = match addr {
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
    pub fn set_local_addresses(
        &mut self,
        addr_ipv4: Option<Ipv4Addr>,
        addr_ipv6: Option<Ipv6Addr>,
    ) {
        self.local_address_ipv4 = addr_ipv4;
        self.local_address_ipv6 = addr_ipv6;
    }
}
