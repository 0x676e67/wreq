//! DNS resolution via the [hickory-resolver](https://github.com/hickory-dns/hickory-dns) crate

use std::{net::SocketAddr, sync::Arc};

pub use hickory_resolver::config::LookupIpStrategy;
use hickory_resolver::{
    TokioResolver, config::ResolverConfig, lookup_ip::LookupIpIntoIter,
    name_server::TokioConnectionProvider,
};

use super::{Addrs, Name, Resolve, Resolving};

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
            Err(err) => {
                log::debug!("error reading DNS system conf: {}", err);
                TokioResolver::builder_with_config(
                    ResolverConfig::default(),
                    TokioConnectionProvider::default(),
                )
            }
        };

        resolver.options_mut().ip_strategy =
            strategy.into().unwrap_or(LookupIpStrategy::Ipv4AndIpv6);

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
