use crate::proxy::ProxyScheme;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub enum NetworkScheme {
    /// Network scheme.
    Scheme {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        interface: Option<std::borrow::Cow<'static, str>>,
        addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),
        proxy_scheme: Option<ProxyScheme>,
    },

    /// No network scheme.
    #[default]
    Default,
}

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

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[inline]
    pub fn take_interface(&mut self) -> Option<std::borrow::Cow<'static, str>> {
        match self {
            NetworkScheme::Scheme { interface, .. } => interface.take(),
            _ => None,
        }
    }
}

/// Builder for `NetworkScheme`.
#[derive(Clone, Debug, Default)]
pub struct NetworkSchemeBuilder {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    interface: Option<std::borrow::Cow<'static, str>>,
    addresses: (Option<Ipv4Addr>, Option<Ipv6Addr>),
    proxy_scheme: Option<ProxyScheme>,
}

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

    #[inline]
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn interface<I>(&mut self, interface: I) -> &mut Self
    where
        I: Into<std::borrow::Cow<'static, str>>,
    {
        self.interface = Some(interface.into());
        self
    }

    #[inline]
    pub fn proxy_scheme(&mut self, proxy: impl Into<Option<ProxyScheme>>) -> &mut Self {
        self.proxy_scheme = proxy.into();
        self
    }

    #[inline]
    pub fn build(self) -> NetworkScheme {
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        if matches!((&self.proxy_scheme, &self.addresses), (None, (None, None))) {
            return NetworkScheme::Default;
        }

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if matches!(
            (&self.proxy_scheme, &self.addresses, &self.interface),
            (None, (None, None), None)
        ) {
            return NetworkScheme::Default;
        }

        NetworkScheme::Scheme {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            interface: self.interface,
            addresses: self.addresses,
            proxy_scheme: self.proxy_scheme,
        }
    }
}

impl From<Option<IpAddr>> for NetworkScheme {
    fn from(value: Option<IpAddr>) -> Self {
        NetworkScheme::Scheme {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            interface: None,
            addresses: match value {
                Some(IpAddr::V4(a)) => (Some(a), None),
                Some(IpAddr::V6(b)) => (None, Some(b)),
                _ => (None, None),
            },
            proxy_scheme: None,
        }
    }
}

impl From<(Option<Ipv4Addr>, Option<Ipv6Addr>)> for NetworkScheme {
    fn from((v4, v6): (Option<Ipv4Addr>, Option<Ipv6Addr>)) -> Self {
        let mut builder = NetworkScheme::builder();
        builder.addresses(v4, v6);
        builder.build()
    }
}

impl From<ProxyScheme> for NetworkScheme {
    fn from(value: ProxyScheme) -> Self {
        let mut builder = NetworkScheme::builder();
        builder.proxy_scheme(value);
        builder.build()
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
impl From<String> for NetworkScheme {
    fn from(value: String) -> Self {
        let mut builder = NetworkScheme::builder();
        builder.interface(value);
        builder.build()
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
impl From<&'static str> for NetworkScheme {
    fn from(value: &'static str) -> Self {
        let mut builder = NetworkScheme::builder();
        builder.interface(value);
        builder.build()
    }
}
