//! DNS resolution via the [hickory-resolver](https://github.com/hickory-dns/hickory-dns) crate.

use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
};

use hickory_resolver::{
    TokioResolver,
    config::{self, LookupIpStrategy, ResolverConfig},
    net::{NetError, runtime::TokioRuntimeProvider},
};

use super::{Addrs, Name, Resolve, Resolving};

/// Resolver shared by all clients, built once from the system configuration.
/// Falls back to Google DNS when the system configuration cannot be read.
static RESOLVER: LazyLock<Result<TokioResolver, Arc<NetError>>> = LazyLock::new(|| {
    let mut builder = match TokioResolver::builder_tokio() {
        Ok(builder) => {
            debug!("using system DNS configuration");
            builder
        }
        Err(_err) => {
            debug!("error reading DNS system conf: {}, using defaults", _err);
            TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&config::GOOGLE),
                TokioRuntimeProvider::default(),
            )
        }
    };
    // Look up both families so connection attempts can use Happy Eyeballs.
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    builder.build().map_err(Arc::new)
});

/// Hickory DNS resolver used by the Tokio runtime.
/// The shared resolver is built on the first lookup; a build failure is returned by every lookup.
pub(crate) struct HickoryResolver;

impl Resolve for HickoryResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let resolver = RESOLVER.as_ref().map_err(|error| error.clone())?;
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(
                lookup
                    .iter()
                    .map(|ip_addr| SocketAddr::new(ip_addr, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            Ok(addrs)
        })
    }
}
