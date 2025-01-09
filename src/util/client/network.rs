//! Request network scheme.
use crate::{cfg_bindable_device, cfg_non_bindable_device, proxy::ProxyScheme};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

cfg_bindable_device! {
    /// Represents the network configuration scheme.
    ///
    /// This enum defines different strategies for configuring network settings,
    /// such as binding to specific interfaces, addresses, or proxy schemes.
    #[derive(Clone, Hash, PartialEq, Eq, Default)]
    pub enum NetworkScheme {
        /// Custom network scheme with specific configurations.
        Scheme {
            /// Specifies the network interface to bind to using `SO_BINDTODEVICE`.
            ///
            /// - **Supported Platforms:** Android, Fuchsia, Linux.
            /// - **Purpose:** Allows binding network traffic to a specific network interface.
            interface: Option<std::borrow::Cow<'static, str>>,

            /// Specifies IP addresses to bind sockets before establishing a connection.
            ///
            /// - **Tuple Structure:** `(Option<Ipv4Addr>, Option<Ipv6Addr>)`
            /// - **Purpose:** Ensures that all sockets use the specified IP addresses
            ///   for both IPv4 and IPv6 connections.
            addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),

            /// Defines the proxy scheme for network requests.
            ///
            /// - **Examples:** HTTP, HTTPS, SOCKS5, SOCKS5h.
            /// - **Purpose:** Routes network traffic through a specified proxy.
            proxy_scheme: Option<ProxyScheme>,
        },

        /// The default network scheme.
        ///
        /// - **Purpose:** Represents a standard or unconfigured network state.
        #[default]
        Default,
    }
}

cfg_non_bindable_device! {
    /// Represents the network configuration scheme.
    ///
    /// This enum defines different strategies for configuring network settings,
    /// such as binding to specific interfaces, addresses, or proxy schemes.
    #[derive(Clone, Hash, PartialEq, Eq, Default)]
    pub enum NetworkScheme {
        /// Custom network scheme with specific configurations.
        Scheme {
            /// Specifies IP addresses to bind sockets before establishing a connection.
            ///
            /// - **Tuple Structure:** `(Option<Ipv4Addr>, Option<Ipv6Addr>)`
            /// - **Purpose:** Ensures that all sockets use the specified IP addresses
            ///   for both IPv4 and IPv6 connections.
            addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),

            /// Defines the proxy scheme for network requests.
            ///
            /// - **Examples:** HTTP, HTTPS, SOCKS5, SOCKS5h.
            /// - **Purpose:** Routes network traffic through a specified proxy.
            proxy_scheme: Option<ProxyScheme>,
        },

        /// The default network scheme.
        ///
        /// - **Purpose:** Represents a standard or unconfigured network state.
        #[default]
        Default,
    }
}

/// ==== impl NetworkScheme ====
impl NetworkScheme {
    pub fn builder() -> NetworkSchemeBuilder {
        NetworkSchemeBuilder::default()
    }

    #[inline]
    pub fn take_proxy_scheme(&mut self) -> Option<ProxyScheme> {
        match self {
            NetworkScheme::Scheme {
                proxy_scheme: proxy,
                ..
            } => proxy.take(),
            _ => None,
        }
    }

    #[inline]
    pub fn take_addresses(&mut self) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        match self {
            NetworkScheme::Scheme { addresses, .. } => (addresses.0.take(), addresses.1.take()),
            _ => (None, None),
        }
    }

    cfg_bindable_device! {
        #[inline]
        pub fn take_interface(&mut self) -> Option<std::borrow::Cow<'static, str>> {
            {
                return match self {
                    NetworkScheme::Scheme { interface, .. } => interface.take(),
                    _ => None,
                };
            }
        }
    }
}

impl fmt::Debug for NetworkScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        cfg_bindable_device! {
            match self {
                NetworkScheme::Scheme {
                    interface,
                    addresses,
                    proxy_scheme,
                } => {
                    // Only print the interface value if it is Some and not None
                    if let Some(interface) = interface {
                        write!(f, "interface={:?},", interface)?;
                    }

                    // Only print the IPv4 address value if it is Some and not None
                    if let Some(v4) = &addresses.0 {
                        write!(f, "ipv4={:?},", v4)?;
                    }

                    // Only print the IPv6 address value if it is Some and not None
                    if let Some(v6) = &addresses.1 {
                        write!(f, "ipv6={:?}),", v6)?;
                    }

                    // Only print the proxy_scheme value if it is Some and not None
                    if let Some(proxy) = proxy_scheme {
                        write!(f, "proxy={:?}", proxy)?;
                    }

                    write!(f, "}}")
                }
                NetworkScheme::Default => {
                    write!(f, "default")
                }
            }
        }

        cfg_non_bindable_device! {
            match self {
                NetworkScheme::Scheme {
                    addresses,
                    proxy_scheme,
                } => {
                    // Only print the IPv4 address value if it is Some and not None
                    if let Some(v4) = &addresses.0 {
                        write!(f, "ipv4={:?},", v4)?;
                    }

                    // Only print the IPv6 address value if it is Some and not None
                    if let Some(v6) = &addresses.1 {
                        write!(f, "ipv6={:?}),", v6)?;
                    }

                    // Only print the proxy_scheme value if it is Some and not None
                    if let Some(proxy) = proxy_scheme {
                        write!(f, "proxy={:?}", proxy)?;
                    }

                    write!(f, "}}")
                }
                NetworkScheme::Default => {
                    write!(f, "default")
                }
            }
        }
    }
}

cfg_bindable_device! {
    /// Builder for `NetworkScheme`.
    #[derive(Clone, Debug, Default)]
    pub struct NetworkSchemeBuilder {
        interface: Option<std::borrow::Cow<'static, str>>,
        addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),
        proxy_scheme: Option<ProxyScheme>,
    }
}

cfg_non_bindable_device! {
    /// Builder for `NetworkScheme`.
    #[derive(Clone, Debug, Default)]
    pub struct NetworkSchemeBuilder {
        addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),
        proxy_scheme: Option<ProxyScheme>,
    }
}

/// ==== impl NetworkSchemeBuilder ====
impl NetworkSchemeBuilder {
    #[inline]
    pub fn address(&mut self, addr: impl Into<Option<IpAddr>>) -> &mut Self {
        self.addresses = match addr.into() {
            Some(IpAddr::V4(addr)) => (Some(addr), None),
            Some(IpAddr::V6(addr)) => (None, Some(addr)),
            _ => (None, None),
        };
        self
    }

    #[inline]
    pub fn addresses<V4, V6>(&mut self, ipv4: V4, ipv6: V6) -> &mut Self
    where
        V4: Into<Option<Ipv4Addr>>,
        V6: Into<Option<Ipv6Addr>>,
    {
        self.addresses = (ipv4.into(), ipv6.into());
        self
    }

    cfg_bindable_device! {
        #[inline]
        pub fn interface<I>(&mut self, interface: I) -> &mut Self
        where
            I: Into<std::borrow::Cow<'static, str>>,
        {
            self.interface = Some(interface.into());
            self
        }
    }

    #[inline]
    pub fn proxy_scheme(&mut self, proxy: impl Into<Option<ProxyScheme>>) -> &mut Self {
        self.proxy_scheme = proxy.into();
        self
    }

    #[inline]
    pub fn build(self) -> NetworkScheme {
        cfg_non_bindable_device! {
            if matches!((&self.proxy_scheme, &self.addresses), (None, (None, None))) {
                return NetworkScheme::Default;
            }
        }

        cfg_non_bindable_device! {
            NetworkScheme::Scheme {
                addresses: self.addresses,
                proxy_scheme: self.proxy_scheme,
            }
        }

        cfg_bindable_device! {
            if matches!(
                (&self.proxy_scheme, &self.addresses, &self.interface),
                (None, (None, None), None)
            ) {
                return NetworkScheme::Default;
            }

            NetworkScheme::Scheme {
                interface: self.interface,
                addresses: self.addresses,
                proxy_scheme: self.proxy_scheme,
            }
        }
    }
}
