use std::task::{self, Poll};

use tower::Service;
use wreq_rt::DnsResolver;

use super::{Addrs, Name, Resolve, Resolving};
use crate::{error::BoxError, rt::RuntimeHandle};

/// A resolver using blocking `getaddrinfo` calls in a threadpool.
#[derive(Clone)]
pub struct GaiResolver(RuntimeHandle);

impl GaiResolver {
    /// Creates a new [`GaiResolver`].
    #[inline(always)]
    pub(crate) fn new(runtime: RuntimeHandle) -> Self {
        GaiResolver(runtime)
    }
}

impl Service<Name> for GaiResolver {
    type Response = Addrs;
    type Error = BoxError;
    type Future = Resolving;

    #[inline(always)]
    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline(always)]
    fn call(&mut self, name: Name) -> Self::Future {
        self.0.resolve(name.into_inner())
    }
}

impl Resolve for GaiResolver {
    #[inline(always)]
    fn resolve(&self, name: Name) -> Resolving {
        self.clone().call(name)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::dns::{Name, SocketAddrs};

    #[test]
    fn test_ip_addrs_split_by_preference() {
        let ip_v4 = Ipv4Addr::new(127, 0, 0, 1);
        let ip_v6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let v4_addr = (ip_v4, 80).into();
        let v6_addr = (ip_v6, 80).into();

        let (mut preferred, mut fallback) = SocketAddrs {
            iter: vec![v4_addr, v6_addr].into_iter(),
        }
        .split_by_preference(None, None);
        assert!(preferred.next().unwrap().is_ipv4());
        assert!(fallback.next().unwrap().is_ipv6());

        let (mut preferred, mut fallback) = SocketAddrs {
            iter: vec![v6_addr, v4_addr].into_iter(),
        }
        .split_by_preference(None, None);
        assert!(preferred.next().unwrap().is_ipv6());
        assert!(fallback.next().unwrap().is_ipv4());

        let (mut preferred, mut fallback) = SocketAddrs {
            iter: vec![v4_addr, v6_addr].into_iter(),
        }
        .split_by_preference(Some(ip_v4), Some(ip_v6));
        assert!(preferred.next().unwrap().is_ipv4());
        assert!(fallback.next().unwrap().is_ipv6());

        let (mut preferred, mut fallback) = SocketAddrs {
            iter: vec![v6_addr, v4_addr].into_iter(),
        }
        .split_by_preference(Some(ip_v4), Some(ip_v6));
        assert!(preferred.next().unwrap().is_ipv6());
        assert!(fallback.next().unwrap().is_ipv4());

        let (mut preferred, fallback) = SocketAddrs {
            iter: vec![v4_addr, v6_addr].into_iter(),
        }
        .split_by_preference(Some(ip_v4), None);
        assert!(preferred.next().unwrap().is_ipv4());
        assert!(fallback.is_empty());

        let (mut preferred, fallback) = SocketAddrs {
            iter: vec![v4_addr, v6_addr].into_iter(),
        }
        .split_by_preference(None, Some(ip_v6));
        assert!(preferred.next().unwrap().is_ipv6());
        assert!(fallback.is_empty());
    }

    #[test]
    fn test_name_from_str() {
        const DOMAIN: &str = "test.example.com";
        let name = Name::from(DOMAIN);
        assert_eq!(name.to_string(), DOMAIN);
        assert_eq!(name.into_inner().as_ref(), DOMAIN);
    }
}
