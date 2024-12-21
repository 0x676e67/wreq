use crate::proxy::ProxyScheme;
use std::net::IpAddr;

#[derive(Clone)]
pub(crate) struct ConnectExtension<T: Clone> {
    value: T,
}

impl<T: Clone> ConnectExtension<T> {
    pub(crate) fn new(value: T) -> Self {
        Self { value }
    }

    pub(crate) fn into_inner(self) -> T {
        self.value
    }
}

/// Extension for pool key
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum PoolKeyExtension {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    Interface(std::borrow::Cow<'static, str>),
    Address(Option<IpAddr>, Option<IpAddr>),
    Proxy(ProxyScheme),
}
