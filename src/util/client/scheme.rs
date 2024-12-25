use crate::proxy::ProxyScheme;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Hash, PartialEq, Eq, Default)]
pub enum NetworkScheme {
    /// Network scheme with an interface.
    Iface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        interface: Option<std::borrow::Cow<'static, str>>,
        addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),
    },

    /// Network scheme with a proxy.
    Proxy(Option<ProxyScheme>),

    /// No network scheme.
    #[default]
    None,
}

impl NetworkScheme {
    pub fn builder() -> NetworkSchemeBuilder {
        NetworkSchemeBuilder::new()
    }

    pub fn take_proxy(&mut self) -> Option<ProxyScheme> {
        match self {
            NetworkScheme::Proxy(proxy) => proxy.take(),
            _ => None,
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    pub fn take_iface(&mut self) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        match self {
            NetworkScheme::Iface { addresses, .. } => (addresses.0.take(), addresses.1.take()),
            _ => (None, None),
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn take_iface(
        &mut self,
    ) -> (
        Option<std::borrow::Cow<'static, str>>,
        (Option<Ipv4Addr>, Option<Ipv6Addr>),
    ) {
        match self {
            NetworkScheme::Iface {
                interface,
                addresses,
            } => (interface.take(), (addresses.0.take(), addresses.1.take())),
            _ => (None, (None, None)),
        }
    }
}

impl std::fmt::Debug for NetworkScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkScheme::Proxy(proxy) => write!(f, "proxy: {:?}", proxy),
            #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
            NetworkScheme::Iface { addresses, .. } => {
                write!(f, "iface: {:?}, {:?}", addresses.0, addresses.1)
            }
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            NetworkScheme::Iface {
                interface,
                addresses,
            } => {
                write!(
                    f,
                    "iface: {:?}, {:?}, {:?}",
                    interface, addresses.0, addresses.1
                )
            }
            NetworkScheme::None => write!(f, "None"),
        }
    }
}

#[allow(missing_debug_implementations)]
pub struct NetworkSchemeBuilder {
    addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    interface: Option<std::borrow::Cow<'static, str>>,
    proxy: Option<ProxyScheme>,
}

impl NetworkSchemeBuilder {
    fn new() -> Self {
        Self {
            addresses: (None, None),
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            interface: None,
            proxy: None,
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    pub fn iface(mut self, iface: (Option<Ipv4Addr>, Option<Ipv6Addr>)) -> Self {
        self.addresses = iface;
        self
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn iface(
        mut self,
        (interface, addresses): (
            Option<std::borrow::Cow<'static, str>>,
            (Option<Ipv4Addr>, Option<Ipv6Addr>),
        ),
    ) -> Self {
        self.addresses = addresses;
        self.interface = interface;
        self
    }

    pub fn proxy(mut self, proxy: impl Into<Option<ProxyScheme>>) -> Self {
        self.proxy = proxy.into();
        self
    }

    pub fn build(self) -> NetworkScheme {
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        if let (None, (None, None)) = (&self.proxy, &self.addresses) {
            return NetworkScheme::None;
        }

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let (None, (None, None), None) = (&self.proxy, &self.addresses, &self.interface) {
            return NetworkScheme::None;
        }

        if self.proxy.is_some() {
            return NetworkScheme::Proxy(self.proxy);
        }

        NetworkScheme::Iface {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            interface: self.interface,
            addresses: self.addresses,
        }
    }
}

impl From<Option<IpAddr>> for NetworkScheme {
    fn from(value: Option<IpAddr>) -> Self {
        NetworkScheme::Iface {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            interface: None,
            addresses: match value {
                Some(IpAddr::V4(a)) => (Some(a), None),
                Some(IpAddr::V6(b)) => (None, Some(b)),
                _ => (None, None),
            },
        }
    }
}

impl From<(Option<Ipv4Addr>, Option<Ipv6Addr>)> for NetworkScheme {
    fn from(value: (Option<Ipv4Addr>, Option<Ipv6Addr>)) -> Self {
        NetworkScheme::Iface {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            interface: None,
            addresses: value,
        }
    }
}

impl From<ProxyScheme> for NetworkScheme {
    fn from(value: ProxyScheme) -> Self {
        NetworkScheme::Proxy(Some(value))
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
impl From<String> for NetworkScheme {
    fn from(value: String) -> Self {
        NetworkScheme::Iface {
            interface: Some(std::borrow::Cow::Owned(value)),
            addresses: (None, None),
        }
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
impl From<&'static str> for NetworkScheme {
    fn from(value: &'static str) -> Self {
        NetworkScheme::Iface {
            interface: Some(std::borrow::Cow::Borrowed(value)),
            addresses: (None, None),
        }
    }
}
