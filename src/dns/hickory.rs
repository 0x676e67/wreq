//! DNS resolution via the [hickory-resolver](https://github.com/hickory-dns/hickory-dns) crate

use super::{Addrs, Name, Resolve, Resolving};
use hickory_resolver::config::{LookupIpStrategy as HickoryLookupIpStrategy, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{TokioResolver, lookup_ip::LookupIpIntoIter};
use std::net::SocketAddr;
use std::sync::Arc;

/// The lookup ip strategy
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LookupIpStrategy {
    /// Only query for A (Ipv4) records
    Ipv4Only,
    /// Only query for AAAA (Ipv6) records
    Ipv6Only,
    /// Query for A and AAAA in parallel
    #[default]
    Ipv4AndIpv6,
    /// Query for Ipv6 if that fails, query for Ipv4
    Ipv6thenIpv4,
    /// Query for Ipv4 if that fails, query for Ipv6
    Ipv4thenIpv6,
}

impl LookupIpStrategy {
    const fn to_hickory(self) -> HickoryLookupIpStrategy {
        match self {
            LookupIpStrategy::Ipv4Only => HickoryLookupIpStrategy::Ipv4Only,
            LookupIpStrategy::Ipv6Only => HickoryLookupIpStrategy::Ipv6Only,
            LookupIpStrategy::Ipv4AndIpv6 => HickoryLookupIpStrategy::Ipv4AndIpv6,
            LookupIpStrategy::Ipv6thenIpv4 => HickoryLookupIpStrategy::Ipv6thenIpv4,
            LookupIpStrategy::Ipv4thenIpv6 => HickoryLookupIpStrategy::Ipv4thenIpv6,
        }
    }
}

/// Wrapper around an `AsyncResolver`, which implements the `Resolve` trait.
#[derive(Debug, Clone)]
pub struct HickoryDnsResolver {
    /// Since we might not have been called in the context of a
    /// Tokio Runtime in initialization, so we must delay the actual
    /// construction of the resolver.
    state: Arc<TokioResolver>,
}

impl HickoryDnsResolver {
    /// Create a new resolver with the default configuration,
    /// which reads from `/etc/resolve.conf`. The options are
    /// overriden to look up for both IPv4 and IPv6 addresses
    /// to work with "happy eyeballs" algorithm.
    pub fn new<S>(strategy: S) -> crate::Result<Self>
    where
        S: Into<Option<LookupIpStrategy>>,
    {
        let mut resolver = match TokioResolver::builder_tokio() {
            Ok(resolver) => resolver,
            Err(_err) => {
                debug!("error reading DNS system conf: {}", _err);
                TokioResolver::builder_with_config(
                    ResolverConfig::default(),
                    TokioConnectionProvider::default(),
                )
            }
        };

        resolver.options_mut().ip_strategy = strategy
            .into()
            .map(LookupIpStrategy::to_hickory)
            .unwrap_or_default();

        Ok(Self {
            state: Arc::new(resolver.build()),
        })
    }
}

struct SocketAddrs {
    iter: LookupIpIntoIter,
}

impl Resolve for HickoryDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let lookup = resolver.state.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(SocketAddrs {
                iter: lookup.into_iter(),
            });
            Ok(addrs)
        })
    }
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip_addr| SocketAddr::new(ip_addr, 0))
    }
}
