//! DNS resolution

#[cfg(feature = "hickory-dns")]
pub use hickory::HickoryDnsResolver;
#[cfg(feature = "hickory-dns")]
pub use hickory_resolver::config::LookupIpStrategy;
pub use resolve::{Addrs, Name, Resolve, Resolving};
pub(crate) use resolve::{DnsResolverWithOverrides, DynResolver};

pub(crate) mod gai;
#[cfg(feature = "hickory-dns")]
pub(crate) mod hickory;
pub(crate) mod resolve;
